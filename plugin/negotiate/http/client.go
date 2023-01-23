package http

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"sync"

	"github.com/gaukas/logging"
	"github.com/gaukas/rtcsocks"
	"github.com/gaukas/rtcsocks/internal/utils"
)

// Client helps the RTCSocks Client to talk to the negotiator server.
// It uses two endpoints: /offer/new and /offer/accept to create offers and lookup answers.
type Client struct {
	UserID   uint64
	Password string

	ServerAddr         string // server address, e.g. "www.google.com"
	SNI                string // SNI to use, e.g. "example.com"
	InsecureSkipVerify bool   // skip TLS certificate verification for HTTPS
	InsecurePlainHTTP  bool   // use plain HTTP instead of HTTPS, when enabled, InsecureSkipVerify is ignored
	insecureWarnOnce   sync.Once

	Logger logging.Logger
}

func (c *Client) RegisterOffer(offer []byte, groupID ...uint64) (offerID uint64, err error) {
	if c.ServerAddr == "" {
		return 0, ErrInvalidServerAddr
	}

	c.insecureWarnOnce.Do(func() {
		if c.InsecureSkipVerify || c.InsecurePlainHTTP {
			if c.Logger != nil {
				c.Logger.Warnf("Client: InsecureSkipVerify or InsecurePlainHTTP enabled, connection is not secure unless negotiator server is local")
			}
		}
	})

	serverUrl := c.ServerAddr + "/rtcsocks/offer/new"
	if !c.InsecurePlainHTTP {
		serverUrl = "https://" + serverUrl
	} else {
		serverUrl = "http://" + serverUrl
	}

	mac := hmac.New(sha256.New, []byte(c.Password))
	mac.Write(offer)
	sum := mac.Sum(nil)

	postForm := map[string]interface{}{
		"offer": offer,                       // byte array as base64 string (auto-encoded)
		"hmac":  sum,                         // byte array as base64 string (auto-encoded)
		"uid":   fmt.Sprintf("%x", c.UserID), // uint64 as hex string
		"gid":   groupID,                     // array of uint64
	}
	if c.Logger != nil {
		c.Logger.Debugf("Client: POST %s, form: %v", serverUrl, postForm)
	}

	// POST offer to negotiator server
	_, resp, err := utils.POST(
		serverUrl,
		postForm,
		c.InsecureSkipVerify,
		c.SNI,
	)
	if err != nil {
		return 0, fmt.Errorf("POST %s: %w", serverUrl, err)
	}

	// parse response
	var responseData struct {
		Status     string `json:"status"`
		OfferIDHex string `json:"offer_id"`
		Reference  string `json:"reference"` // reference for debugging or error reporting
	}
	if json.Unmarshal(resp, &responseData) != nil {
		return 0, ErrInvalidResponseFormat
	}

	if responseData.Status != "success" {
		return 0, fmt.Errorf("POST %s returned status: %s, reference: %s", serverUrl, responseData.Status, responseData.Reference)
	}

	// hex string to uint64
	offerID, err = strconv.ParseUint(responseData.OfferIDHex, 16, 64)
	if err != nil {
		return 0, fmt.Errorf("non-Hex offer_id returned by negotiator: %s", responseData.OfferIDHex)
	}

	return offerID, nil
}

func (c *Client) LookupAnswer(offerID uint64) (answer []byte, err error) {
	if c.ServerAddr == "" {
		return nil, ErrInvalidServerAddr
	}

	c.insecureWarnOnce.Do(func() {
		if c.InsecureSkipVerify || c.InsecurePlainHTTP {
			if c.Logger != nil {
				c.Logger.Warnf("Client: InsecureSkipVerify or InsecurePlainHTTP enabled, connection is not secure unless negotiator server is local")
			}
		}
	})

	serverUrl := c.ServerAddr + "/rtcsocks/answer/lookup"
	if !c.InsecurePlainHTTP {
		serverUrl = "https://" + serverUrl
	} else {
		serverUrl = "http://" + serverUrl
	}

	postForm := map[string]interface{}{
		"offer_id": fmt.Sprintf("%x", offerID), // uint64 as hex string
		"uid":      fmt.Sprintf("%x", c.UserID),
	}

	mac := hmac.New(sha256.New, []byte(c.Password))
	mac.Write([]byte(postForm["offer_id"].(string)))
	sum := mac.Sum(nil)

	postForm["hmac"] = sum

	// POST offer to server
	_, resp, err := utils.POST(
		serverUrl,
		postForm,
		c.InsecureSkipVerify,
		c.SNI,
	)
	if err != nil {
		return nil, fmt.Errorf("POST %s: %w", serverUrl, err)
	}

	// parse response
	var responseData struct {
		Status    string `json:"status"`
		AnswerB64 string `json:"answer"`
		Reference string `json:"reference"` // reference for debugging or error reporting
	}
	if json.Unmarshal(resp, &responseData) != nil {
		return nil, ErrInvalidResponseFormat
	}

	if responseData.Status == "success" {
		// decode base64 string to byte array
		answer, err = base64.StdEncoding.DecodeString(responseData.AnswerB64)
		if err != nil {
			return nil, fmt.Errorf("base64 decode error: %w", err)
		}
		return answer, nil
	} else if responseData.Status == "pending" {
		return nil, rtcsocks.ErrAnswerPending
	}

	return nil, fmt.Errorf("POST %s returned status: %s, reference: %s", serverUrl, responseData.Status, responseData.Reference)
}
