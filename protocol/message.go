package protocol

import (
	"bytes"
	"encoding/binary"
	"io"
)

// op-code
const (
	// Client Server TCP Messages
	LoginRequest      = 0x01
	ServerMessage     = 0x38
	IDChange          = 0x40
	OfferFiles        = 0x15
	ServerStatus      = 0x34
	ServerList        = 0x32
	ServerIdent       = 0x41
	SearchRequest     = 0x16
	SearchResult      = 0x16
	GetSources        = 0x19
	FoundSources      = 0x42
	CallbackRequest   = 0x1C
	CallbackRequested = 0x35
	CallbackFailed    = 0x36
	Rejected          = 0x05
)

// errors
var (
	ErrShortBuffer = io.ErrShortBuffer
)

// UID is user ID a 128 bit (16 byte) GUID.
// the 6th and 15th (start from 1st) bytes values are 14 and 111 respectively.
type UID [16]byte

// NewUID creates a UID based on GUID
func NewUID() *UID {
	uid := new(UID)
	uid[5], uid[14] = 14, 111
	return uid
}

// Bytes returns a slice of 16-byte length.
func (uid *UID) Bytes() []byte {
	return uid[:]
}

// LoginMessage is the first message send by the client to the server after TCP connection establishment.
type LoginMessage struct {
	Header   *Header
	UID      *UID
	ClientID uint32
	Port     uint16
	Name     string
	Version  int
	Flags    int
}

// Encode encodes the message to binary data
func (m *LoginMessage) Encode() (data []byte, err error) {
	buf := new(bytes.Buffer)

	header := m.Header
	if header == nil {
		header = &Header{
			Protocol: EDonkey,
			Type:     LoginRequest,
		}
	}

	b, err := m.Header.Encode()
	if err != nil {
		return
	}
	buf.Write(b)

	uid := m.UID
	if m.UID == nil {
		uid = NewUID()
	}
	buf.Write(uid.Bytes())

	binary.Write(buf, binary.LittleEndian, m.ClientID)
	binary.Write(buf, binary.LittleEndian, m.Port)

	tagCount := uint16(4)
	binary.Write(buf, binary.LittleEndian, tagCount)

	b, err = StringTag(1, m.Name).Encode()
	if err != nil {
		return
	}
	buf.Write(b)

	b, err = IntegerTag(0x11, int32(m.Version)).Encode()
	if err != nil {
		return
	}
	buf.Write(b)

	b, err = IntegerTag(0x0F, int32(m.Port)).Encode()
	if err != nil {
		return
	}
	buf.Write(b)

	b, err = IntegerTag(0x20, int32(m.Flags)).Encode()
	if err != nil {
		return
	}
	buf.Write(b)

	data = buf.Bytes()

	size := len(data) - HeaderLength
	binary.LittleEndian.PutUint32(data[1:5], uint32(size)) // message size

	return
}

// Decode decodes the message from binary data
func (m *LoginMessage) Decode(data []byte) (err error) {
	m.Header = &Header{}
	err = m.Header.Decode(data)
	if err != nil {
		return
	}

	pos := HeaderLength
	if len(data) < pos+int(m.Header.Size) {
		return ErrShortBuffer
	}
	m.UID = new(UID)
	copy(m.UID[:], data[pos:pos+16])

	pos += 16
	m.ClientID = binary.LittleEndian.Uint32(data[pos : pos+4])

	pos += 4
	m.Port = binary.LittleEndian.Uint16(data[pos : pos+2])

	pos += 2
	tagCount := binary.LittleEndian.Uint32(data[pos : pos+4])

	pos += 4
	for i := 0; i < int(tagCount); i++ {

	}
	return
}
