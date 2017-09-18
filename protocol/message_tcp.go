package protocol

import (
	"bytes"
	"encoding/binary"
	"log"
)

// LoginMessage is the first message send by the client to the server after TCP connection establishment.
type LoginMessage struct {
	Header   Header
	UID      UID
	ClientID uint32
	Port     uint16
	Name     string
	Version  uint32
	Flags    uint32
}

// Encode encodes the message to binary data.
func (m *LoginMessage) Encode() (data []byte, err error) {
	if m == nil {
		return
	}
	buf := new(bytes.Buffer)

	b, err := m.Header.Encode()
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

	size := len(data) - HeaderLength
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
	m.Header = header

	pos := HeaderLength
	if m.Header.Size == 0 ||
		len(data) < pos+int(m.Header.Size) ||
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

// ServerMessage is variable length message that is sent from the server to client.
// A single server-message may contain several messages separated by new line characters ('\r','\n' or both).
// Messages that start with "server version", "warning", "error" and "emDynIP" have special meaning for the client.
type ServerMessage struct {
	Header   Header
	Messages string
}

// Encode encodes the message to binary data.
func (m *ServerMessage) Encode() (data []byte, err error) {
	if m == nil {
		return
	}
	buf := new(bytes.Buffer)

	b, err := m.Header.Encode()
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
	size = len(data) - HeaderLength
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
	m.Header = header

	pos := HeaderLength
	if m.Header.Size == 0 ||
		len(data) < pos+int(m.Header.Size) ||
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

// IDChangeMessage is the message sent by the server as a response to the login request message and
// signifies that the server has accepted the client connection.
type IDChangeMessage struct {
	Header   Header
	ClientID uint32
	Bitmap   uint32
}

// Encode encodes the message to binary data.
func (m *IDChangeMessage) Encode() (data []byte, err error) {
	if m == nil {
		return
	}
	buf := new(bytes.Buffer)

	b, err := m.Header.Encode()
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
	size := len(data) - HeaderLength
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
	m.Header = header

	pos := HeaderLength
	if m.Header.Size == 0 ||
		len(data) < pos+int(m.Header.Size) ||
		len(data) < pos+8 {
		return ErrShortBuffer
	}

	m.ClientID = binary.LittleEndian.Uint32(data[pos : pos+4])
	pos += 4
	m.Bitmap = binary.LittleEndian.Uint32(data[pos : pos+4])

	return
}
