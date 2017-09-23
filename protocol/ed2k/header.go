package ed2k

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// protocol ID
const (
	ProtoEDonkey = 0xE3
	ProtoEMule   = 0xC5
	ProtoPacked  = 0xD4
)

const (
	// HeaderLength is the length of message header.
	// 1-byte protocol + 4-byte data size
	HeaderLength = 5
)

// errors
var (
	ErrInvalidProto = errors.New("invalid protocol")
)

// Header is the message header.
type Header struct {
	// Protocol ID, 0xE3 for eDonkey and 0xC5 for eMule.
	Protocol uint8
	// The size of the message in bytes not including the protocol and size fields.
	Size uint32
}

// Encode encodes the header to binary data.
func (h *Header) Encode() (data []byte, err error) {
	buf := new(bytes.Buffer)
	if _, err = h.WriteTo(buf); err != nil {
		return
	}
	data = buf.Bytes()
	return
}

// Decode decodes the header from binary data.
func (h *Header) Decode(data []byte) (err error) {
	_, err = h.ReadFrom(bytes.NewReader(data))
	return
}

// WriteTo writes header struct to w. The return value n is the number of bytes written.
func (h *Header) WriteTo(w io.Writer) (n int64, err error) {
	proto := h.Protocol
	if proto == 0 {
		proto = ProtoEDonkey
	}
	if proto != ProtoEDonkey && proto != ProtoEMule && proto != ProtoPacked {
		err = ErrInvalidProto
		return
	}
	data := make([]byte, HeaderLength)
	data[0] = proto
	binary.LittleEndian.PutUint32(data[1:5], h.Size)

	size, err := w.Write(data)
	n = int64(size)
	return
}

// ReadFrom reads structured binary data from r and parses data to header h.
func (h *Header) ReadFrom(r io.Reader) (n int64, err error) {
	data := make([]byte, HeaderLength)
	if _, err = io.ReadFull(r, data); err != nil {
		return
	}
	n = HeaderLength

	proto := data[0]
	if proto == 0 {
		proto = ProtoEDonkey
	}
	if proto != ProtoEDonkey && proto != ProtoEMule && proto != ProtoPacked {
		err = ErrInvalidProto
		return
	}
	h.Protocol = proto
	h.Size = binary.LittleEndian.Uint32(data[1:5])

	return
}

func (h Header) String() string {
	return fmt.Sprintf("protocol: %#x, size: %d", h.Protocol, h.Size)
}
