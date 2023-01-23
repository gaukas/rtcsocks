package rtcsocks

import (
	"crypto/rand"
	"fmt"
	"math"
	"math/big"
	"sync"
	"time"
)

var (
	ErrNotAuthenticated = fmt.Errorf("not authenticated")
	ErrBadGroupID       = fmt.Errorf("bad group ID")
	ErrRNGError         = fmt.Errorf("random number generation error")
	ErrInvalidOfferID   = fmt.Errorf("invalid offer ID")
	ErrNoOfferAvailable = fmt.Errorf("no offer available yet")
	ErrAnswerPending    = fmt.Errorf("answer is pending for the specified offer")
	ErrAnswerRepeated   = fmt.Errorf("answer is already registered for the specified offer")
	ErrNoAccess         = fmt.Errorf("no access to the specified offer")
)

// Negotiator isolates the Client and the Edge Server and provides a way for them to
// communicate without knowing each other's IP address beforehand.
type Negotiator struct {
	maxGroupID uint64                 // maximum group ID, >= 1
	offerBins  map[uint64]chan *offer // bin_id -> chan offer
	answers    map[uint64]*answer     // offer_id -> answer_sdp
	ttl        time.Duration          // time to live for an offer/answer pair

	mutexAnswers sync.Mutex
}

type offer struct {
	id   uint64
	user uint64 // user ID
	sdp  []byte // offer SDP
}

type answer struct {
	body   []byte
	expiry time.Time  // garbage collection
	user   uint64     // offer owner
	mutex  sync.Mutex // for concurrent read(ReadAnswer) and write(Answer)
}

func NewNegotiator(maxGroupID int, ttl time.Duration) *Negotiator {
	offerBins := make(map[uint64]chan *offer)
	// 1~2^(numGroup)-1
	maxBinIdx := uint64(math.Pow(2, float64(maxGroupID))) - 1
	var i uint64
	for i = 1; i <= maxBinIdx; i++ {
		offerBins[i] = make(chan *offer)
	}

	n := &Negotiator{
		maxGroupID:   uint64(maxGroupID),
		offerBins:    offerBins,
		answers:      make(map[uint64]*answer),
		ttl:          ttl,
		mutexAnswers: sync.Mutex{},
	}

	go n.autoPurge()

	return n
}

func (n *Negotiator) HookToAPI(api NegotiatorAPI) {
	api.SetRegisterOfferCallback(n.registerOffer)
	api.SetNextOfferCallback(n.nextOffer)
	api.SetRegisterAnswerCallback(n.registerAnswer)
	api.SetLookupAnswerCallback(n.lookupAnswer)
}

func (n *Negotiator) registerOffer(user uint64, sdp []byte, groups ...uint64) (offerID uint64, err error) {
	// calculate binID
	binID := uint64(0)
	for _, groupID := range groups {
		if groupID <= uint64(n.maxGroupID) {
			binID |= uint64(math.Pow(2, float64(groupID-1)))
		}
	}
	if binID == 0 {
		return 0, ErrBadGroupID
	}

	// Generate Random Offer ID
	bigN := new(big.Int)
	randID, err := rand.Int(rand.Reader, bigN.SetUint64(math.MaxUint64))
	if err != nil {
		return 0, ErrRNGError
	}
	offerID = randID.Uint64()

	// Save offer to Offer Bin
	n.offerBins[binID] <- &offer{
		id:   offerID,
		user: user,
		sdp:  sdp,
	}

	// Store Answer
	n.mutexAnswers.Lock()
	n.answers[offerID] = &answer{
		body:   nil,
		expiry: time.Now().Add(n.ttl),
		user:   user,
		mutex:  sync.Mutex{},
	}
	n.mutexAnswers.Unlock()

	return offerID, nil
}

func (n *Negotiator) nextOffer(group uint64) (offerID uint64, sdp []byte, err error) {
	// calculate binIDs to receive from
	// binaryGroupID = 2^(groupID-1). e.g. groupID=3 => binaryGroupID=4/
	binaryGroupID := uint64(math.Pow(2, float64(group-1)))
	binIDs := make([]uint64, 0)
	for binID := range n.offerBins {
		if binaryGroupID&binID > 0 {
			binIDs = append(binIDs, binID)
		}
	}

LOOP_ALL_BINS:
	for _, binID := range binIDs {
	LOOP_CURRENT_BIN:
		for {
			select {
			case offerObj := <-n.offerBins[binID]:
				// check if offer is expired
				n.mutexAnswers.Lock()
				answer, ok := n.answers[offerObj.id]
				if !ok {
					n.mutexAnswers.Unlock()
					continue LOOP_CURRENT_BIN
				}
				answer.mutex.Lock()
				if answer.expiry.Before(time.Now()) {
					answer.mutex.Unlock()
					n.mutexAnswers.Unlock()
					continue LOOP_CURRENT_BIN
				}
				answer.mutex.Unlock()
				n.mutexAnswers.Unlock()
				return offerObj.id, offerObj.sdp, nil
			default: // if not readily available, try next bin
				continue LOOP_ALL_BINS
			}
		}
	}

	return 0, nil, ErrNoOfferAvailable
}

func (n *Negotiator) registerAnswer(offerID uint64, sdp []byte) error {
	n.mutexAnswers.Lock()
	defer n.mutexAnswers.Unlock()
	answer, ok := n.answers[offerID]
	if !ok {
		return ErrInvalidOfferID
	}
	answer.mutex.Lock()
	defer answer.mutex.Unlock()
	if answer.body != nil {
		return ErrAnswerRepeated
	}
	answer.body = sdp
	return nil
}

func (n *Negotiator) lookupAnswer(user, offerID uint64) ([]byte, error) {
	n.mutexAnswers.Lock()
	defer n.mutexAnswers.Unlock()
	answer, ok := n.answers[offerID]
	if !ok {
		return nil, ErrInvalidOfferID
	}
	answer.mutex.Lock()
	defer answer.mutex.Unlock()
	if answer.user != user {
		return nil, ErrNoAccess
	}

	if answer.body == nil {
		return nil, ErrAnswerPending
	}
	return answer.body, nil
}

func (n *Negotiator) autoPurge() {
	for {
		time.Sleep(n.ttl / 2)
		n.mutexAnswers.Lock()
		for offerID, answer := range n.answers {
			if time.Now().After(answer.expiry) {
				delete(n.answers, offerID)
			}
		}
		n.mutexAnswers.Unlock()
	}
}
