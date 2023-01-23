package rtcsocks

type RegisterOfferCallbackFunction func(user uint64, sdp []byte, groups ...uint64) (offerID uint64, err error)
type NextOfferCallbackFunction func(group uint64) (offerID uint64, sdp []byte, err error)
type RegisterAnswerCallbackFunction func(offerID uint64, sdp []byte) error
type LookupAnswerCallbackFunction func(user, offerID uint64) (sdp []byte, err error)

// NegotiatorAPI is the API for the Negotiator. It provides a customizable way for
// the Client and the Edge Server to access the Negotiator.
//
// NegotiatorAPI SHOULD implement support for authentication/authorization.
type NegotiatorAPI interface {
	SetRegisterOfferCallback(RegisterOfferCallbackFunction)

	// SetNextOfferCallback sets the callback function for the next offer.
	// It returns ErrNoOfferAvailable if there is no offer available for the specified group.
	SetNextOfferCallback(NextOfferCallbackFunction)
	SetRegisterAnswerCallback(RegisterAnswerCallbackFunction)
	SetLookupAnswerCallback(LookupAnswerCallbackFunction)
}

// ClientNegotiator is the helper interface for the Client to access the Negotiator via NegotiatorAPI.
type ClientNegotiator interface {
	// RegisterOffer registers an offer with the Negotiator to be accepted by 1(one)
	// Edge Server from one of the groups specified by groupID. It returns an offerID
	// assigned by the Negotiator to be used in the subsequent LookupAnswer call.
	RegisterOffer(sdp []byte, groupID ...uint64) (offerID uint64, err error)

	// LookupAnswer looks up the answer for the offer identified with the specified offerID.
	LookupAnswer(offerID uint64) (sdp []byte, err error)
}

// NextOfferHandlerFunction is the handler function to be called when the Edge Server receives a new offer
// from the Negotiator. It SHOULD NOT block the caller.
type NextOfferHandlerFunction func(offerID uint64, sdp []byte) error

// ServerNegotiator is the helper interface for the Edge Server to access the Negotiator via NegotiatorAPI.
type ServerNegotiator interface {
	// SetNextOfferHandler sets the handler function for the next offer.
	SetNextOfferHandler(NextOfferHandlerFunction)

	// RegisterAnswer registers the answer for the offer identified with the specified offerID.
	RegisterAnswer(offerID uint64, sdp []byte) error
}
