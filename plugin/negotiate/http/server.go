package http

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/gaukas/logging"
	"github.com/gaukas/rtcsocks"
	"github.com/gaukas/rtcsocks/internal/utils"
)

// Server helps the RTCSocks Server to talk to the negotiator server.
type Server struct {
	Secret  string
	GroupID uint64 // set by SetNewOfferHandler

	ServerAddr         string // server address, e.g. "www.google.com"
	SNI                string // SNI to use, e.g. "example.com"
	InsecureSkipVerify bool   // skip TLS certificate verification for HTTPS
	InsecurePlainHTTP  bool   // use plain HTTP instead of HTTPS, when enabled, InsecureSkipVerify is ignored
	insecureWarnOnce   sync.Once

	Logger           logging.Logger
	nextOfferHandler rtcsocks.NextOfferHandlerFunction
	startLoopOnce    sync.Once
	WaitAfterSuccess time.Duration // sleep duration when success returned by readNextOffer, 0 -> no sleep
	WaitAfterPending time.Duration // sleep duration when readNextOffer waits for new offer, 0 -> defaultWaitAfterPending
	WaitAfterError   time.Duration // sleep duration when error occurs in readNextOffer, 0 -> return immediately if errored
}

func (s *Server) SetNextOfferHandler(handler rtcsocks.NextOfferHandlerFunction) {
	s.nextOfferHandler = handler

	s.startLoopOnce.Do(func() {
		go s.loopReadNextOffer()
	}) // start loopReadNextOffer if not started
}

func (s *Server) RegisterAnswer(offerID uint64, answer []byte) error {
	if s.ServerAddr == "" {
		return ErrInvalidServerAddr
	}

	s.insecureWarnOnce.Do(func() {
		if s.InsecureSkipVerify || s.InsecurePlainHTTP {
			if s.Logger != nil {
				s.Logger.Warnf("Server: InsecureSkipVerify/InsecurePlainHTTP enabled, connection is not secure unless negotiator server is local")
			}
		}
	})

	serverUrl := s.ServerAddr + "/rtcsocks/answer/new"
	if !s.InsecurePlainHTTP {
		serverUrl = "https://" + serverUrl
	} else {
		serverUrl = "http://" + serverUrl
	}

	postForm := map[string]interface{}{
		"gid":      fmt.Sprintf("%x", s.GroupID), // uint64 as hex string
		"secret":   s.Secret,
		"offer_id": fmt.Sprintf("%x", offerID), // uint64 as hex string
		"answer":   base64.StdEncoding.EncodeToString(answer),
	}
	if s.Logger != nil {
		s.Logger.Debugf("Server: POST %s, form: %v", serverUrl, postForm)
	}

	// POST answer to negotiator server
	_, resp, err := utils.POST(
		serverUrl,
		postForm,
		s.InsecureSkipVerify,
		s.SNI,
	)
	if err != nil {
		return fmt.Errorf("POST %s: %w", serverUrl, err)
	}

	// parse response
	var responseData struct {
		Status    string `json:"status"`
		Reference string `json:"reference"` // reference for debugging or error reporting
	}
	if json.Unmarshal(resp, &responseData) != nil {
		return ErrInvalidResponseFormat
	}

	if responseData.Status == "success" {
		return nil
	} else {
		return fmt.Errorf("POST %s returned status: %s, reference: %s", serverUrl, responseData.Status, responseData.Reference)
	}
}

func (s *Server) loopReadNextOffer() {
	for {
		offerID, offer, err := s.readNextOffer()
		if err != nil {
			if err == rtcsocks.ErrNoOfferAvailable {
				if s.Logger != nil {
					s.Logger.Debugf("Server: readNextOffer: empty offer queue, retry later...")
				}
				if s.WaitAfterPending > 0 {
					time.Sleep(s.WaitAfterPending)
				} else {
					time.Sleep(defaultWaitAfterPending)
				}
			} else {
				if s.Logger != nil {
					s.Logger.Errorf("Server: readNextOffer failed: %v", err)
				}
				if s.WaitAfterError > 0 {
					time.Sleep(s.WaitAfterError)
				} else {
					return
				}
			}
		}
		if s.Logger != nil {
			s.Logger.Debugf("Server: readNextOffer: offerID: %d, offer: %x", offerID, offer)
		}

		if s.nextOfferHandler != nil {
			err := s.nextOfferHandler(offerID, offer)
			if err != nil {
				if s.Logger != nil {
					s.Logger.Errorf("Server: newOfferHandler failed: %v", err)
				}
			}
		} else {
			if s.Logger != nil {
				s.Logger.Warnf("Server: newOfferHandler not set, offer discarded")
			}
		}

		if s.WaitAfterSuccess > 0 {
			time.Sleep(s.WaitAfterSuccess)
		}
	}
}

func (s *Server) readNextOffer() (offerID uint64, offer []byte, err error) {
	if s.ServerAddr == "" {
		return 0, nil, ErrInvalidServerAddr
	}

	s.insecureWarnOnce.Do(func() {
		if s.InsecureSkipVerify || s.InsecurePlainHTTP {
			if s.Logger != nil {
				s.Logger.Warnf("Server: InsecureSkipVerify/InsecurePlainHTTP enabled, connection is not secure unless negotiator server is local")
			}
		}
	})
	serverUrl := s.ServerAddr + "/rtcsocks/offer/next"
	if !s.InsecurePlainHTTP {
		serverUrl = "https://" + serverUrl
	} else {
		serverUrl = "http://" + serverUrl
	}

	postForm := map[string]interface{}{
		"gid":    fmt.Sprintf("%x", s.GroupID), // uint64 as hex string
		"secret": s.Secret,
	}
	if s.Logger != nil {
		s.Logger.Debugf("Client: POST %s, form: %v", serverUrl, postForm)
	}

	// POST offer to negotiator server
	_, resp, err := utils.POST(
		serverUrl,
		postForm,
		s.InsecureSkipVerify,
		s.SNI,
	)
	if err != nil {
		return 0, nil, fmt.Errorf("POST %s: %w", serverUrl, err)
	}

	// parse response
	var responseData struct {
		Status     string `json:"status"`
		OfferIDHex string `json:"offer_id"`
		OfferB64   string `json:"offer"`
		Reference  string `json:"reference"` // reference for debugging or error reporting
	}
	if json.Unmarshal(resp, &responseData) != nil {
		return 0, nil, ErrInvalidResponseFormat
	}

	if responseData.Status == "success" {
		// hex string to uint64
		offerID, err = strconv.ParseUint(responseData.OfferIDHex, 16, 64)
		if err != nil {
			return 0, nil, fmt.Errorf("non-Hex offer_id returned by negotiator: %s", responseData.OfferIDHex)
		}

		// decode base64 string to byte array
		offer, err = base64.StdEncoding.DecodeString(responseData.OfferB64)
		if err != nil {
			return 0, nil, fmt.Errorf("base64 decode error: %w", err)
		}

		return offerID, offer, nil
	} else if responseData.Status == "pending" {
		return 0, nil, rtcsocks.ErrNoOfferAvailable
	} else {
		return 0, nil, fmt.Errorf("POST %s returned status: %s, reference: %s", serverUrl, responseData.Status, responseData.Reference)
	}
}
