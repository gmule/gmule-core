package protocol

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strings"
)

// LoginMessage is the first message send by the client to the server after TCP connection establishment.
type LoginMessage struct {
	message
	UID      UID
	ClientID uint32
	// The TCP port used by the client, configurable.
	Port uint16
	// The user’s nickname, configurable.
	Name string
	// The eDonkey version supported by the client.
	Version uint32
	Flags   uint32
}

// Encode encodes the message to binary data.
func (m *LoginMessage) Encode() (data []byte, err error) {
	if m == nil {
		return
	}
	buf := new(bytes.Buffer)

	header := m.Header
	if header.Protocol == 0 {
		header.Protocol = EDonkey
	}
	header.Type = MessageLoginRequest
	b, err := header.Encode()
	if err != nil {
		return
	}
	buf.Write(b)
	buf.Write(m.UID.Bytes())

	if err = binary.Write(buf, binary.LittleEndian, m.ClientID); err != nil {
		return
	}
	if err = binary.Write(buf, binary.LittleEndian, m.Port); err != nil {
		return
	}

	tagCount := uint32(4)
	if err = binary.Write(buf, binary.LittleEndian, tagCount); err != nil {
		return
	}

	b, err = StringTag(TagNickname, m.Name).Encode()
	if err != nil {
		return
	}
	buf.Write(b)

	b, err = IntegerTag(TagVersion, int32(m.Version)).Encode()
	if err != nil {
		return
	}
	buf.Write(b)

	b, err = IntegerTag(TagPort, int32(m.Port)).Encode()
	if err != nil {
		return
	}
	buf.Write(b)

	b, err = IntegerTag(TagFlags, int32(m.Flags)).Encode()
	if err != nil {
		return
	}
	buf.Write(b)

	data = buf.Bytes()

	size := len(data) - HeaderLength + 1
	binary.LittleEndian.PutUint32(data[1:5], uint32(size)) // message size

	return
}

// Decode decodes the message from binary data.
func (m *LoginMessage) Decode(data []byte) (err error) {
	header := Header{}
	err = header.Decode(data)
	if err != nil {
		return
	}
	if header.Type != MessageLoginRequest {
		return ErrWrongMessageType
	}
	m.Header = header

	pos := HeaderLength
	if len(data) < pos+int(m.Header.Size)-1 ||
		len(data) < pos+16+4+2+4 {
		return ErrShortBuffer
	}

	copy(m.UID[:], data[pos:pos+16])

	pos += 16
	m.ClientID = binary.LittleEndian.Uint32(data[pos : pos+4])

	pos += 4
	m.Port = binary.LittleEndian.Uint16(data[pos : pos+2])

	pos += 2
	tagCount := binary.LittleEndian.Uint32(data[pos : pos+4])

	pos += 4
	r := bytes.NewReader(data[pos:])
	for i := 0; i < int(tagCount); i++ {
		tag, err := ReadTag(r)
		if err != nil {
			return err
		}
		name, _ := tag.Name().(int)
		switch name {
		case TagNickname:
			m.Name, _ = tag.Value().(string)
		case TagVersion:
			v, _ := tag.Value().(int32)
			m.Version = uint32(v)
		case TagPort:
		case TagFlags:
			flags, _ := tag.Value().(int32)
			m.Flags = uint32(flags)
		default:
			log.Println("unknown tag name:", name)
		}
	}
	return
}

func (m LoginMessage) String() string {
	b := bytes.Buffer{}
	b.WriteString(m.Header.String())
	b.WriteString("\n")
	fmt.Fprintf(&b, "uid: %s, clientID: %#x(%s), port: %d\n", m.UID, m.ClientID, ClientID(m.ClientID).String(), m.Port)
	fmt.Fprintf(&b, "name: %s, version: %#x, flags: %#x", m.Name, m.Version, m.Flags)
	return b.String()
}

// ServerMessage is variable length message that is sent from the server to client.
// A single server-message may contain several messages separated by new line characters ('\r','\n' or both).
// Messages that start with "server version", "warning", "error" and "emDynIP" have special meaning for the client.
type ServerMessage struct {
	message
	// A list of server messages separated by new lines.
	Messages string
}

// Encode encodes the message to binary data.
func (m *ServerMessage) Encode() (data []byte, err error) {
	if m == nil {
		return
	}
	buf := new(bytes.Buffer)

	header := m.Header
	if header.Protocol == 0 {
		header.Protocol = EDonkey
	}
	header.Type = MessageServerMessage
	b, err := header.Encode()
	if err != nil {
		return
	}
	buf.Write(b)

	size := len(m.Messages)
	if err = binary.Write(buf, binary.LittleEndian, uint16(size)); err != nil {
		return
	}
	if _, err = buf.WriteString(m.Messages); err != nil {
		return
	}

	data = buf.Bytes()
	size = len(data) - HeaderLength + 1
	binary.LittleEndian.PutUint32(data[1:5], uint32(size)) // message size

	return
}

// Decode decodes the message from binary data.
func (m *ServerMessage) Decode(data []byte) (err error) {
	header := Header{}
	err = header.Decode(data)
	if err != nil {
		return
	}
	if header.Type != MessageServerMessage {
		return ErrWrongMessageType
	}
	m.Header = header

	pos := HeaderLength
	if len(data) < pos+int(m.Header.Size)-1 ||
		len(data) < pos+2 {
		return ErrShortBuffer
	}

	size := binary.LittleEndian.Uint16(data[pos : pos+2])
	pos += 2
	if len(data) < pos+int(size) {
		return ErrShortBuffer
	}
	m.Messages = string(data[pos : pos+int(size)])
	return
}

func (m *ServerMessage) String() string {
	b := bytes.Buffer{}
	b.WriteString(m.Header.String())
	b.WriteString("\n")
	b.WriteString(m.Messages)
	return b.String()
}

// IDChangeMessage is the message sent by the server as a response to the login request message and
// signifies that the server has accepted the client connection.
type IDChangeMessage struct {
	message
	ClientID uint32
	// Currently only 1 bit (the LSB) has meaning, setting it to 1 signals that the server supports compression.
	Bitmap uint32
}

// Encode encodes the message to binary data.
func (m *IDChangeMessage) Encode() (data []byte, err error) {
	if m == nil {
		return
	}
	buf := new(bytes.Buffer)

	header := m.Header
	if header.Protocol == 0 {
		header.Protocol = EDonkey
	}
	header.Type = MessageIDChange
	b, err := header.Encode()
	if err != nil {
		return
	}
	buf.Write(b)

	if err = binary.Write(buf, binary.LittleEndian, m.ClientID); err != nil {
		return
	}
	if err = binary.Write(buf, binary.LittleEndian, m.Bitmap); err != nil {
		return
	}

	data = buf.Bytes()
	size := len(data) - HeaderLength + 1
	binary.LittleEndian.PutUint32(data[1:5], uint32(size)) // message size

	return
}

// Decode decodes the message from binary data.
func (m *IDChangeMessage) Decode(data []byte) (err error) {
	header := Header{}
	err = header.Decode(data)
	if err != nil {
		return
	}
	if header.Type != MessageIDChange {
		return ErrWrongMessageType
	}
	m.Header = header

	pos := HeaderLength
	if len(data) < pos+int(m.Header.Size)-1 ||
		len(data) < pos+8 {
		return ErrShortBuffer
	}

	m.ClientID = binary.LittleEndian.Uint32(data[pos : pos+4])
	pos += 4
	m.Bitmap = binary.LittleEndian.Uint32(data[pos : pos+4])

	return
}

func (m *IDChangeMessage) String() string {
	b := bytes.Buffer{}
	b.WriteString(m.Header.String())
	b.WriteString("\n")
	fmt.Fprintf(&b, "clientID: %#x(%s), bitmap: %#x", m.ClientID, ClientID(m.ClientID).String(), m.Bitmap)
	return b.String()
}

// OfferFilesMessage is used by the client to describe local files available for other clients to download.
type OfferFilesMessage struct {
	message
	// The number of files described within, in any case no more than 200.
	// The Server can also set a lower limit to this number.
	FileCount uint32
}

// GetServerListMessage is sent when the client is configured to expand its list of eMule servers by querying its current server.
// This message may be sent from the client to the server immediately after a successful handshake completion.
type GetServerListMessage struct {
	message
}

// Encode encodes the message to binary data.
func (m *GetServerListMessage) Encode() (data []byte, err error) {
	if m == nil {
		return
	}
	buf := new(bytes.Buffer)

	header := m.Header
	if header.Protocol == 0 {
		header.Protocol = EDonkey
	}
	header.Type = MessageGetServerList
	b, err := header.Encode()
	if err != nil {
		return
	}
	buf.Write(b)

	data = buf.Bytes()
	size := len(data) - HeaderLength + 1
	binary.LittleEndian.PutUint32(data[1:5], uint32(size)) // message size

	return
}

// Decode decodes the message from binary data.
func (m *GetServerListMessage) Decode(data []byte) (err error) {
	header := Header{}
	err = header.Decode(data)
	if err != nil {
		return
	}
	if header.Type != MessageGetServerList {
		return ErrWrongMessageType
	}
	m.Header = header

	return
}

func (m *GetServerListMessage) String() string {
	b := bytes.Buffer{}
	b.WriteString(m.Header.String())
	return b.String()
}

// ServerListMessage is sent from the server to the client.
// The message contains information about additional eMule servers to be used to expand the client’s server list.
type ServerListMessage struct {
	message
	// Server descriptor entries, each entry size is 6 bytes and contains 4 bytes IP address and then 2 byte TCP port.
	Servers []*net.TCPAddr
}

// Encode encodes the message to binary data.
func (m *ServerListMessage) Encode() (data []byte, err error) {
	if m == nil {
		return
	}
	buf := new(bytes.Buffer)

	header := m.Header
	if header.Protocol == 0 {
		header.Protocol = EDonkey
	}
	header.Type = MessageServerList
	b, err := header.Encode()
	if err != nil {
		return
	}
	buf.Write(b)

	buf.WriteByte(byte(len(m.Servers))) // entry count

	for _, addr := range m.Servers {
		if addr == nil {
			addr = &net.TCPAddr{
				IP:   net.IPv4zero,
				Port: 0,
			}
		}
		buf.Write(addr.IP.To4())
		binary.Write(buf, binary.LittleEndian, uint16(addr.Port))
	}

	data = buf.Bytes()
	size := len(data) - HeaderLength + 1
	binary.LittleEndian.PutUint32(data[1:5], uint32(size)) // message size

	return
}

// Decode decodes the message from binary data.
func (m *ServerListMessage) Decode(data []byte) (err error) {
	header := Header{}
	err = header.Decode(data)
	if err != nil {
		return
	}
	if header.Type != MessageServerList {
		return ErrWrongMessageType
	}
	m.Header = header

	pos := HeaderLength
	if len(data) < pos+int(m.Header.Size)-1 ||
		len(data) < pos+1 {
		return ErrShortBuffer
	}

	count := int(data[pos])
	pos++
	if len(data) < pos+count*6 {
		return ErrShortBuffer
	}

	for i := 0; i < count; i++ {
		m.Servers = append(m.Servers,
			&net.TCPAddr{
				IP:   net.IP(data[pos : pos+4]),
				Port: int(binary.LittleEndian.Uint16(data[pos+4 : pos+6])),
			})
		pos += 6
	}
	return
}

func (m *ServerListMessage) String() string {
	b := bytes.Buffer{}
	b.WriteString(m.Header.String())
	b.WriteString("\n")
	b.WriteString("servers:\n")
	var ss []string
	for _, addr := range m.Servers {
		ss = append(ss, addr.String())
	}
	b.WriteString(strings.Join(ss, ","))
	return b.String()
}

// ServerStatusMessage is sent from the server to the client.
// The message contains information on the current number of users and files on the server.
// The information in this message is both stored by the client and also displayed to the user.
type ServerStatusMessage struct {
	message
	// The number of users currently logged in to the server.
	UserCount uint32
	// The number of files that this server is informed about.
	FileCount uint32
}

// Encode encodes the message to binary data.
func (m *ServerStatusMessage) Encode() (data []byte, err error) {
	if m == nil {
		return
	}
	buf := new(bytes.Buffer)

	header := m.Header
	if header.Protocol == 0 {
		header.Protocol = EDonkey
	}
	header.Type = MessageServerStatus
	b, err := header.Encode()
	if err != nil {
		return
	}
	buf.Write(b)

	if err = binary.Write(buf, binary.LittleEndian, m.UserCount); err != nil {
		return
	}
	if err = binary.Write(buf, binary.LittleEndian, m.FileCount); err != nil {
		return
	}

	data = buf.Bytes()
	size := len(data) - HeaderLength + 1
	binary.LittleEndian.PutUint32(data[1:5], uint32(size)) // message size

	return
}

// Decode decodes the message from binary data.
func (m *ServerStatusMessage) Decode(data []byte) (err error) {
	header := Header{}
	err = header.Decode(data)
	if err != nil {
		return
	}
	if header.Type != MessageServerStatus {
		return ErrWrongMessageType
	}
	m.Header = header

	pos := HeaderLength
	if len(data) < pos+int(m.Header.Size)-1 ||
		len(data) < pos+8 {
		return ErrShortBuffer
	}

	m.UserCount = binary.LittleEndian.Uint32(data[pos : pos+4])
	pos += 4
	m.FileCount = binary.LittleEndian.Uint32(data[pos : pos+4])

	return
}

func (m *ServerStatusMessage) String() string {
	b := bytes.Buffer{}
	b.WriteString(m.Header.String())
	b.WriteString("\n")
	fmt.Fprintf(&b, "users: %d, files: %d", m.UserCount, m.FileCount)
	return b.String()
}
