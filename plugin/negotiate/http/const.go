package http

import (
	"errors"
	"time"
)

var (
	ErrInvalidServerAddr     = errors.New("invalid server address")
	ErrInvalidResponseFormat = errors.New("invalid response format")
)

const (
	defaultWaitAfterPending = 5 * time.Second
)
