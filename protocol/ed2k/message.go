package ed2k

import (
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/satori/go.uuid"
)

// Message IDs
const (
	// Client-Server TCP Messages
	MessageLoginRequest      = 0x01
	MessageRejected          = 0x05
	MessageGetServerList     = 0x14
	MessageOfferFiles        = 0x15
	MessageSearchRequest     = 0x16
	MessageGetSources        = 0x19
	MessageCallbackRequest   = 0x1C
	MessageServerList        = 0x32
	MessageServerStatus      = 0x34
	MessageCallbackRequested = 0x35
	MessageCallbackFailed    = 0x36
	MessageServerMessage     = 0x38
	MessageIDChange          = 0x40
	MessageServerIdent       = 0x41
	MessageFoundSources      = 0x42
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
	MessageServerList:    func() Message { return &ServerStatusMessage{} },
	MessageServerStatus:  func() Message { return &ServerStatusMessage{} },
	MessageServerIdent:   func() Message { return &ServerIdentMessage{} },
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

// ReadMessage reads structured binary data from r and parses the data to message.
func ReadMessage(r io.Reader) (m Message, err error) {
	data := make([]byte, 1500)
	// read header
	if _, err = io.ReadFull(r, data[:HeaderLength]); err != nil {
		return
	}
	header := Header{}
	if err = header.Decode(data[:HeaderLength]); err != nil {
		return
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
	}

	m = fn()
	err = m.Decode(data)
	return
}
