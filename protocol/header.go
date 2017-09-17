package protocol

import (
	"encoding/binary"
)

const (
	// EDonkey is the protocol ID for eDonkey
	EDonkey = 0xE3
	// EMule is the protocol ID for eMule
	EMule = 0xC5
)

const (
	// HeaderLength is the length of message header
	HeaderLength = 6
)

// Header is the message header
type Header struct {
	Protocol uint8
	Size     uint32
	Type     uint8
}

// Encode encodes the header to binary data
func (h *Header) Encode() (data []byte, err error) {
	data = []byte{h.Protocol, 0x00, 0x00, 0x00, 0x00, h.Type}
	binary.LittleEndian.PutUint32(data[1:5], h.Size)
	return
}

// Decode decodes the header from binary data
func (h *Header) Decode(data []byte) (err error) {
	if len(data) < HeaderLength {
		return ErrShortBuffer
	}

	h.Protocol = data[0]
	h.Size = binary.LittleEndian.Uint32(data[1:5])
	h.Type = data[5]

	return
}
