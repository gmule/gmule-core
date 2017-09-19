package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// protocol ID
const (
	EDonkey = 0xE3
	EMule   = 0xC5
)

const (
	// HeaderLength is the length of message header.
	HeaderLength = 6
)

// Header is the message header.
type Header struct {
	// Protocol ID, 0xE3 for eDonkey and 0xC5 for eMule.
	Protocol uint8
	// The size of the message in bytes not including the protocol and size fields.
	Size uint32
	// A unique message ID.
	Type uint8
}

// Encode encodes the header to binary data.
func (h *Header) Encode() (data []byte, err error) {
	data = make([]byte, HeaderLength)
	if h == nil {
		return
	}
	data[0] = h.Protocol
	data[5] = h.Type
	binary.LittleEndian.PutUint32(data[1:5], h.Size)
	return
}

// Decode decodes the header from binary data.
func (h *Header) Decode(data []byte) (err error) {
	if len(data) < HeaderLength {
		return ErrShortBuffer
	}

	h.Protocol = data[0]
	h.Size = binary.LittleEndian.Uint32(data[1:5])
	h.Type = data[5]

	if h.Protocol == 0 || h.Size == 0 || h.Type == 0 {
		return errors.New("invalid message header")
	}
	return
}

func (h Header) String() string {
	return fmt.Sprintf("protocol: %#x, size: %d, type: %#x", h.Protocol, h.Size, h.Type)
}
