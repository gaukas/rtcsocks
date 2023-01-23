package http

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strconv"

	"github.com/gaukas/rtcsocks"
	"github.com/gofiber/fiber/v2"
)

type API struct {
	fiberApp *fiber.App

	userpass    map[uint64]string // userpass[uid] = password
	groupSecret map[uint64]string // groupSecret[gid] = secret

	registerOfferCallback  rtcsocks.RegisterOfferCallbackFunction
	nextOfferCallback      rtcsocks.NextOfferCallbackFunction
	registerAnswerCallback rtcsocks.RegisterAnswerCallbackFunction
	lookupAnswerCallback   rtcsocks.LookupAnswerCallbackFunction
}

func NewAPI(userpass, groupSecret map[uint64]string) *API {
	return &API{
		userpass:    userpass,
		groupSecret: groupSecret,
	}
}

func (a *API) Listen(addr string) error {
	if a.fiberApp == nil {
		a.fiberApp = fiber.New()
	}

	if a.userpass == nil {
		a.userpass = make(map[uint64]string)
	}

	if a.groupSecret == nil {
		a.groupSecret = make(map[uint64]string)
	}

	rtcsocks := a.fiberApp.Group("/rtcsocks")
	offer := rtcsocks.Group("/offer")
	offer.Post("/new", a.registerOffer)
	offer.Post("/next", a.nextOffer)

	answer := rtcsocks.Group("/answer")
	answer.Post("/new", a.registerAnswer)
	answer.Post("/lookup", a.lookupAnswer)

	return a.fiberApp.Listen(addr)
}

func (a *API) SetRegisterOfferCallback(f rtcsocks.RegisterOfferCallbackFunction) {
	a.registerOfferCallback = f
}

func (a *API) SetNextOfferCallback(f rtcsocks.NextOfferCallbackFunction) {
	a.nextOfferCallback = f
}

func (a *API) SetRegisterAnswerCallback(f rtcsocks.RegisterAnswerCallbackFunction) {
	a.registerAnswerCallback = f
}

func (a *API) SetLookupAnswerCallback(f rtcsocks.LookupAnswerCallbackFunction) {
	a.lookupAnswerCallback = f
}

func (a *API) registerOffer(c *fiber.Ctx) error {
	var postForm struct {
		SDP    string   `json:"offer"` // Offer SDP body, base64
		HMAC   string   `json:"hmac"`  // HMAC, base64
		UID    string   `json:"uid"`   // User ID, hex
		Groups []uint64 `json:"gid"`   // Group ID, int array
	}

	if err := c.BodyParser(&postForm); err != nil {
		return c.SendStatus(fiber.StatusNotFound)
	}

	uid, err := strconv.ParseUint(postForm.UID, 16, 64)
	if err != nil {
		return c.SendStatus(fiber.StatusNotFound)
	}

	offer, err := base64.StdEncoding.DecodeString(postForm.SDP)
	if err != nil {
		return c.SendStatus(fiber.StatusNotFound)
	}

	hmac, err := base64.StdEncoding.DecodeString(postForm.HMAC)
	if err != nil {
		return c.SendStatus(fiber.StatusNotFound)
	}

	if !a.verifyHMAC(uid, offer, hmac) {
		return c.SendStatus(fiber.StatusNotFound)
	}

	offerID, err := a.registerOfferCallback(uid, offer, postForm.Groups...)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":    "error",
			"reference": err.Error(),
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":   "success",
		"offer_id": fmt.Sprintf("%x", offerID),
	})
}

func (a *API) nextOffer(c *fiber.Ctx) error {
	var postForm struct {
		GID    string `json:"gid"`    // Group ID, hex
		Secret string `json:"secret"` // Group Secret, plaintext
	}

	if err := c.BodyParser(&postForm); err != nil {
		return c.SendStatus(fiber.StatusNotFound)
	}

	gid, err := strconv.ParseUint(postForm.GID, 16, 64)
	if err != nil {
		return c.SendStatus(fiber.StatusNotFound)
	}

	if secret, ok := a.groupSecret[gid]; !ok || secret != postForm.Secret {
		return c.SendStatus(fiber.StatusNotFound)
	}

	offerID, offer, err := a.nextOfferCallback(gid)
	if err != nil {
		if err == rtcsocks.ErrNoOfferAvailable {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"status": "pending",
			})
		}

		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":    "error",
			"reference": err.Error(),
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":   "success",
		"offer_id": fmt.Sprintf("%x", offerID),
		"offer":    base64.StdEncoding.EncodeToString(offer),
	})
}

func (a *API) registerAnswer(c *fiber.Ctx) error {
	var postForm struct {
		GID     string `json:"gid"` // Group ID, hex
		Secret  string `json:"secret"`
		OfferID string `json:"offer_id"` // Offer ID, hex
		SDP     string `json:"answer"`   // Answer SDP body, base64
	}

	if err := c.BodyParser(&postForm); err != nil {
		return c.SendStatus(fiber.StatusNotFound)
	}

	gid, err := strconv.ParseUint(postForm.GID, 16, 64)
	if err != nil {
		return c.SendStatus(fiber.StatusNotFound)
	}

	// Authenticate the server per group
	if secret, ok := a.groupSecret[gid]; !ok || secret != postForm.Secret {
		return c.SendStatus(fiber.StatusNotFound)
	}

	offerID, err := strconv.ParseUint(postForm.OfferID, 16, 64)
	if err != nil {
		return c.SendStatus(fiber.StatusNotFound)
	}

	answer, err := base64.StdEncoding.DecodeString(postForm.SDP)
	if err != nil {
		return c.SendStatus(fiber.StatusNotFound)
	}

	if err := a.registerAnswerCallback(offerID, answer); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":    "error",
			"reference": err.Error(),
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status": "success",
	})
}

func (a *API) lookupAnswer(c *fiber.Ctx) error {
	var postForm struct {
		OfferID string `json:"offer_id"` // Offer ID, hex
		UID     string `json:"uid"`      // User ID, hex
		HMAC    string `json:"hmac"`     // HMAC, base64
	}

	if err := c.BodyParser(&postForm); err != nil {
		return c.SendStatus(fiber.StatusNotFound)
	}

	offerID, err := strconv.ParseUint(postForm.OfferID, 16, 64)
	if err != nil {
		return c.SendStatus(fiber.StatusNotFound)
	}

	uid, err := strconv.ParseUint(postForm.UID, 16, 64)
	if err != nil {
		return c.SendStatus(fiber.StatusNotFound)
	}

	hmac, err := base64.StdEncoding.DecodeString(postForm.HMAC)
	if err != nil {
		return c.SendStatus(fiber.StatusNotFound)
	}

	if !a.verifyHMAC(uid, []byte(postForm.OfferID), hmac) {
		return c.SendStatus(fiber.StatusNotFound)
	}

	answer, err := a.lookupAnswerCallback(offerID, uid)
	if err != nil {
		if err == rtcsocks.ErrAnswerPending {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"status": "pending",
			})
		} else {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"status":    "error",
				"reference": err.Error(),
			})
		}
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status": "success",
		"answer": base64.StdEncoding.EncodeToString(answer),
	})
}

// constant-time verification of HMAC
func (a *API) verifyHMAC(uid uint64, offer []byte, mac []byte) bool {
	secret, ok := a.userpass[uid]
	if !ok {
		return false
	}

	h := hmac.New(sha256.New, []byte(secret))
	// Write Data to it
	h.Write([]byte(offer))

	if !ok {
		return hmac.Equal([]byte{0x00}, mac)
	}

	return hmac.Equal(h.Sum(nil), mac)
}
