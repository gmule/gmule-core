package ed2k

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

// HelloMessage message is the first message in the handshake between two e-mule clients.
type HelloMessage struct {
	message
	UID      UID
	ClientID ClientID
	Port     uint16
	Tags     []Tag
	// The address of the server to which the client is connected.
	Server *net.TCPAddr
}

// Encode encodes the message to binary data.
func (m *HelloMessage) Encode() (data []byte, err error) {
	if m == nil {
		return
	}
	buf := new(bytes.Buffer)
	if _, err = m.Header.WriteTo(buf); err != nil {
		return
	}
	buf.WriteByte(MessageHello)
	buf.WriteByte(16) // The size of the user hash field
	buf.Write(m.UID.Bytes())
	binary.Write(buf, binary.LittleEndian, m.ClientID)
	binary.Write(buf, binary.LittleEndian, m.Port)
	binary.Write(buf, binary.LittleEndian, uint32(len(m.Tags)))

	for _, tag := range m.Tags {
		if _, err = tag.WriteTo(buf); err != nil {
			return
		}
	}

	server := m.Server
	if server == nil {
		server = &net.TCPAddr{
			IP:   net.IPv4zero,
			Port: 0,
		}
	}
	buf.Write(server.IP.To4())
	binary.Write(buf, binary.LittleEndian, uint16(server.Port))

	data = buf.Bytes()
	size := len(data) - HeaderLength
	binary.LittleEndian.PutUint32(data[1:5], uint32(size)) // message size

	return
}

// Decode decodes the message from binary data.
func (m *HelloMessage) Decode(data []byte) (err error) {
	header := Header{}
	err = header.Decode(data)
	if err != nil {
		return
	}
	pos := HeaderLength
	if len(data) < pos+int(header.Size) ||
		len(data) < pos+1+1+16+4+2+4 {
		return ErrShortBuffer
	}
	if data[5] != MessageHello {
		return ErrWrongMessageType
	}
	m.Header = header
	pos++
	size := int(data[pos])
	pos++
	copy(m.UID[:], data[pos:pos+size])

	pos += size
	m.ClientID = ClientID(binary.LittleEndian.Uint32(data[pos : pos+4]))

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
		m.Tags = append(m.Tags, tag)
	}
	b := make([]byte, 6)
	if _, err = io.ReadFull(r, b); err != nil {
		return
	}
	m.Server = &net.TCPAddr{
		IP:   net.IP(b[:4]),
		Port: int(binary.LittleEndian.Uint16(b[4:6])),
	}

	return
}

// Type is the message type
func (m HelloMessage) Type() uint8 {
	return MessageHello
}

func (m HelloMessage) String() string {
	b := bytes.Buffer{}
	b.WriteString("[hello]\n")
	b.WriteString(m.Header.String())
	b.WriteString("\n")
	fmt.Fprintf(&b, "uid: %s, %s:%d\n", m.UID, m.ClientID, m.Port)
	for i, tag := range m.Tags {
		fmt.Fprintf(&b, "tag%d - %v: %v\n", i, tag.Name(), tag.Value())
	}
	b.WriteString("server: " + m.Server.String())
	return b.String()
}

// HelloAnswerMessage message is sent as an answer to a Hello message.
type HelloAnswerMessage struct {
	message
	UID      UID
	ClientID ClientID
	Port     uint16
	Tags     []Tag
	// The address of the server to which the client is connected.
	Server *net.TCPAddr
}

// Encode encodes the message to binary data.
func (m *HelloAnswerMessage) Encode() (data []byte, err error) {
	if m == nil {
		return
	}
	buf := new(bytes.Buffer)
	if _, err = m.Header.WriteTo(buf); err != nil {
		return
	}
	buf.WriteByte(MessageHello)
	buf.Write(m.UID.Bytes())
	binary.Write(buf, binary.LittleEndian, m.ClientID)
	binary.Write(buf, binary.LittleEndian, m.Port)

	binary.Write(buf, binary.LittleEndian, uint32(len(m.Tags)))
	for _, tag := range m.Tags {
		if _, err = tag.WriteTo(buf); err != nil {
			return
		}
	}

	server := m.Server
	if server == nil {
		server = &net.TCPAddr{
			IP:   net.IPv4zero,
			Port: 0,
		}
	}
	buf.Write(server.IP.To4())
	binary.Write(buf, binary.LittleEndian, uint16(server.Port))

	data = buf.Bytes()
	size := len(data) - HeaderLength
	binary.LittleEndian.PutUint32(data[1:5], uint32(size)) // message size

	return
}

// Decode decodes the message from binary data.
func (m *HelloAnswerMessage) Decode(data []byte) (err error) {
	header := Header{}
	err = header.Decode(data)
	if err != nil {
		return
	}
	pos := HeaderLength
	if len(data) < pos+int(header.Size) ||
		len(data) < pos+1+16+4+2+4 {
		return ErrShortBuffer
	}
	if data[5] != MessageHelloAnswer {
		return ErrWrongMessageType
	}
	m.Header = header
	pos++
	copy(m.UID[:], data[pos:pos+16])

	pos += 16
	m.ClientID = ClientID(binary.LittleEndian.Uint32(data[pos : pos+4]))

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
		m.Tags = append(m.Tags, tag)
	}
	b := make([]byte, 6)
	if _, err = io.ReadFull(r, b); err != nil {
		return
	}
	m.Server = &net.TCPAddr{
		IP:   net.IP(b[:4]),
		Port: int(binary.LittleEndian.Uint16(b[4:6])),
	}

	return
}

// Type is the message type.
func (m HelloAnswerMessage) Type() uint8 {
	return MessageHelloAnswer
}

func (m HelloAnswerMessage) String() string {
	b := bytes.Buffer{}
	b.WriteString("[hello-answer]\n")
	b.WriteString(m.Header.String())
	b.WriteString("\n")
	fmt.Fprintf(&b, "uid: %s, %s:%d\n", m.UID, m.ClientID, m.Port)
	for i, tag := range m.Tags {
		fmt.Fprintf(&b, "tag%d - %v: %v\n", i, tag.Name(), tag.Value())
	}
	b.WriteString("server: " + m.Server.String())
	return b.String()
}
