package protocol

import (
	"errors"
	"io"

	"github.com/satori/go.uuid"
)

// Message IDs
const (
	// Client Server TCP Messages
	MessageLoginRequest      = 0x01
	MessageServerMessage     = 0x38
	MessageIDChange          = 0x40
	MessageOfferFiles        = 0x15
	MessageGetServerList     = 0x14
	MessageServerStatus      = 0x34
	MessageServerList        = 0x32
	MessageServerIdent       = 0x41
	MessageSearchRequest     = 0x16
	MessageSearchResult      = 0x16
	MessageGetSources        = 0x19
	MessageFoundSources      = 0x42
	MessageCallbackRequest   = 0x1C
	MessageCallbackRequested = 0x35
	MessageCallbackFailed    = 0x36
	MessageRejected          = 0x05
)

// errors
var (
	ErrShortBuffer      = io.ErrShortBuffer
	ErrWrongMessageType = errors.New("wrong message type")
)

// UID is user ID, it is a 128 bit (16 byte) GUID.
// the 6th and 15th (start from 1st) bytes values are 14 and 111 respectively.
type UID [16]byte

// NewUID creates a UID based on GUID
func NewUID() (uid UID) {
	uuid := uuid.NewV4()
	copy(uid[:], uuid[:])
	uid[5], uid[14] = 14, 111
	return
}

// Bytes returns a slice of 16-byte length.
func (uid UID) Bytes() []byte {
	return uid[:]
}

func (uid UID) String() string {
	return uuid.UUID(uid).String()
}
