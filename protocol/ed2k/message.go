package ed2k

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/satori/go.uuid"
)

// Message IDs
const (
	MessageNull = 0x00

	// Client-Server TCP Messages
	MessageLoginRequest      = 0x01
	MessageRejected          = 0x05
	MessageGetServerList     = 0x14
	MessageOfferFiles        = 0x15
	MessageSearchRequest     = 0x16
	MessageDisconnect        = 0x18
	MessageSearchUser        = 0x1A
	MessageGetSources        = 0x19
	MessageGetSourcesOBFU    = 0x23
	MessageCallbackRequest   = 0x1C
	MessageMoreResult        = 0x21
	MessageServerList        = 0x32
	MessageSearchResult      = 0x33
	MessageServerStatus      = 0x34
	MessageCallbackRequested = 0x35
	MessageCallbackFailed    = 0x36
	MessageServerMessage     = 0x38
	MessageIDChange          = 0x40
	MessageServerIdent       = 0x41
	MessageFoundSources      = 0x42
	MessageUserList          = 0x43
	MessageFoundSourcesOBFU  = 0x44
)

// errors
var (
	ErrShortBuffer      = io.ErrShortBuffer
	ErrWrongMessageType = errors.New("wrong message type")
)

var constructors = map[uint8]func() Message{
	MessageLoginRequest:  func() Message { return &LoginMessage{} },
	MessageServerMessage: func() Message { return &ServerMessage{} },
	MessageIDChange:      func() Message { return &IDChangeMessage{} },
	MessageOfferFiles:    func() Message { return &OfferFilesMessage{} },
	MessageGetServerList: func() Message { return &GetServerListMessage{} },
	MessageServerList:    func() Message { return &ServerListMessage{} },
	MessageServerStatus:  func() Message { return &ServerStatusMessage{} },
	MessageServerIdent:   func() Message { return &ServerIdentMessage{} },
	MessageSearchRequest: func() Message { return &SearchRequestMessage{} },
	MessageSearchResult:  func() Message { return &SearchResultMessage{} },
}

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
	return fmt.Sprintf("%X", uid[:])
}

// ClientID is an a 4 byte identifier provided by the server at their connection handshake.
// A client ID is valid only through the lifetime of a client-server TCP connection although in
// case the client has a high ID it will be assigned the same ID by all servers until its IP address changes.
//
// Client IDs are divided to low IDs and high IDs. The eMule server will typically
// assigns a client with a low ID when the client can’t accept incoming connections.
// Having a low ID restricts the client’s use of the eMule network and might result in the server’s rejecting the client’s connection.
//
// A high ID is given to clients that allow other clients to freely
// connect to eMule’s TCP port on their host machine (the default port number is 4662).
// A client with a high ID has no restrictions in its use of the eMule network.
//
// High IDs are calculated in the following way: assuming the host IP is X.Y.Z.W the ID will be
// X + 2^8 * Y + 2^16 * Z + 2^24 * W (big endian representation).
// A low ID is always lower than 16777216 (0x1000000).
type ClientID uint32

func (cid ClientID) String() string {
	return net.IPv4(uint8(cid&0xFF), uint8((cid>>8)&0xFF), uint8((cid>>16)&0xFF), uint8((cid>>24)&0xFF)).String()
}

// Message is message interface.
type Message interface {
	Protocol() uint8
	Type() uint8
	Encode() (data []byte, err error)
	Decode(data []byte) (err error)
	String() string
}

type message struct {
	Header Header
}

func (m *message) Protocol() uint8 {
	return m.Header.Protocol
}

// NullMessage is a message that it is size field of header is 0.
type NullMessage struct {
	message
}

// Encode encodes the message to binary data.
func (m *NullMessage) Encode() (data []byte, err error) {
	buf := new(bytes.Buffer)
	if _, err = m.Header.WriteTo(buf); err != nil {
		return
	}
	buf.WriteByte(MessageNull)

	data = buf.Bytes()
	binary.LittleEndian.PutUint32(data[1:5], 0) // message size
	return
}

// Decode decodes the message from binary data.
func (m *NullMessage) Decode(data []byte) (err error) {
	header := Header{}
	err = header.Decode(data)
	if err != nil {
		return
	}

	m.Header = header
	return
}

// Type is the message type
func (m NullMessage) Type() uint8 {
	return MessageNull
}

func (m NullMessage) String() string {
	b := bytes.Buffer{}
	b.WriteString("[null]\n")
	b.WriteString(m.Header.String())
	return b.String()
}

// ReadMessage reads structured binary data from r and parses the data to message.
func ReadMessage(r io.Reader) (m Message, err error) {
	data := make([]byte, 256)
	// read header
	if _, err = io.ReadFull(r, data[:HeaderLength]); err != nil {
		return
	}
	header := Header{}
	if err = header.Decode(data[:HeaderLength]); err != nil {
		return
	}

	if header.Size == 0 {
		return &NullMessage{message: message{Header: header}}, nil
	}

	mSize := HeaderLength + int(header.Size)
	if len(data) < mSize {
		b := data
		data = make([]byte, mSize)
		copy(data[:], b[:HeaderLength])
	}
	if _, err = io.ReadFull(r, data[HeaderLength:mSize]); err != nil {
		return
	}

	mType := data[5]
	fn, ok := constructors[mType]
	if !ok {
		err = fmt.Errorf("unknown message type: %v", mType)
		return
	}

	m = fn()
	err = m.Decode(data)
	return
}
