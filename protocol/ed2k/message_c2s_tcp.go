// Client Server TCP Messages

package ed2k

import (
	"bytes"
	"encoding/binary"
	"fmt"
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
	Tags []Tag
}

// Encode encodes the message to binary data.
func (m *LoginMessage) Encode() (data []byte, err error) {
	if m == nil {
		return
	}
	buf := new(bytes.Buffer)
	if _, err = m.Header.WriteTo(buf); err != nil {
		return
	}
	buf.WriteByte(MessageLoginRequest)
	buf.Write(m.UID.Bytes())

	binary.Write(buf, binary.LittleEndian, m.ClientID)
	binary.Write(buf, binary.LittleEndian, m.Port)
	binary.Write(buf, binary.LittleEndian, uint32(len(m.Tags)))

	for _, tag := range m.Tags {
		if _, err = tag.WriteTo(buf); err != nil {
			return
		}
	}

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
	pos := HeaderLength
	if len(data) < pos+int(header.Size) ||
		len(data) < pos+1+16+4+2+4 {
		return ErrShortBuffer
	}
	if data[5] != MessageLoginRequest {
		return ErrWrongMessageType
	}
	m.Header = header
	pos++
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
		m.Tags = append(m.Tags, tag)
	}
	return
}

// Type is the message type
func (m LoginMessage) Type() uint8 {
	return MessageLoginRequest
}

func (m LoginMessage) String() string {
	b := bytes.Buffer{}
	b.WriteString("[login]\n")
	b.WriteString(m.Header.String())
	b.WriteString("\n")
	fmt.Fprintf(&b, "uid: %s, clientID: %#x(%s), port: %d\n", m.UID, m.ClientID, ClientID(m.ClientID).String(), m.Port)
	for i, tag := range m.Tags {
		fmt.Fprintf(&b, "tag%d - %v: %v\n", i, tag.Name(), tag.Value())
	}
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

	if _, err = m.Header.WriteTo(buf); err != nil {
		return
	}
	buf.WriteByte(MessageServerMessage)

	size := len(m.Messages)
	binary.Write(buf, binary.LittleEndian, uint16(size))
	buf.WriteString(m.Messages)

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
	pos := HeaderLength
	if len(data) < pos+int(header.Size) ||
		len(data) < pos+3 {
		return ErrShortBuffer
	}
	if data[5] != MessageServerMessage {
		return ErrWrongMessageType
	}
	m.Header = header
	pos++
	size := binary.LittleEndian.Uint16(data[pos : pos+2])
	pos += 2
	if len(data) < pos+int(size) {
		return ErrShortBuffer
	}
	m.Messages = string(data[pos : pos+int(size)])
	return
}

// Type is the message type
func (m ServerMessage) Type() uint8 {
	return MessageServerMessage
}

func (m ServerMessage) String() string {
	b := bytes.Buffer{}
	b.WriteString("[server-message]\n")
	b.WriteString(m.Header.String())
	b.WriteString("\n")
	b.WriteString(m.Messages)
	return b.String()
}

// IDChangeMessage message is sent by the server as a response to the login request message and
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
	if _, err = m.Header.WriteTo(buf); err != nil {
		return
	}
	buf.WriteByte(MessageIDChange)

	binary.Write(buf, binary.LittleEndian, m.ClientID)
	binary.Write(buf, binary.LittleEndian, m.Bitmap)

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
	pos := HeaderLength
	if len(data) < pos+int(header.Size) ||
		len(data) < pos+9 {
		return ErrShortBuffer
	}
	if data[5] != MessageIDChange {
		return ErrWrongMessageType
	}
	m.Header = header
	pos++
	m.ClientID = binary.LittleEndian.Uint32(data[pos : pos+4])
	pos += 4
	m.Bitmap = binary.LittleEndian.Uint32(data[pos : pos+4])

	return
}

// Type is the message type
func (m IDChangeMessage) Type() uint8 {
	return MessageIDChange
}

func (m IDChangeMessage) String() string {
	b := bytes.Buffer{}
	b.WriteString("[id-change]\n")
	b.WriteString(m.Header.String())
	b.WriteString("\n")
	fmt.Fprintf(&b, "clientID: %#x(%s), bitmap: %#x", m.ClientID, ClientID(m.ClientID).String(), m.Bitmap)
	return b.String()
}

// OfferFilesMessage is used by the client to describe local files available for other clients to download.
// In case the client has files to offer, the offer-files message is sent immediately after the
// connection establishment. The message is also transmitted when the client’s shared file list changes.
type OfferFilesMessage struct {
	message
	// An optional list of files, in any case no more than 200.
	// The Server can also set a lower limit to this number.
	Files []File
}

// Encode encodes the message to binary data.
func (m *OfferFilesMessage) Encode() (data []byte, err error) {
	if m == nil {
		return
	}
	buf := new(bytes.Buffer)
	if _, err = m.Header.WriteTo(buf); err != nil {
		return
	}
	buf.WriteByte(MessageOfferFiles)
	binary.Write(buf, binary.LittleEndian, uint32(len(m.Files)))

	for _, file := range m.Files {
		if _, err = file.WriteTo(buf); err != nil {
			return
		}
	}

	data = buf.Bytes()
	size := len(data) - HeaderLength
	binary.LittleEndian.PutUint32(data[1:5], uint32(size)) // message size

	return
}

// Decode decodes the message from binary data.
func (m *OfferFilesMessage) Decode(data []byte) (err error) {
	header := Header{}
	err = header.Decode(data)
	if err != nil {
		return
	}
	pos := HeaderLength
	if len(data) < pos+int(header.Size) ||
		len(data) < pos+5 {
		return ErrShortBuffer
	}
	if data[5] != MessageOfferFiles {
		return ErrWrongMessageType
	}
	m.Header = header
	pos++
	fileCount := binary.LittleEndian.Uint32(data[pos : pos+4])
	pos += 4
	r := bytes.NewReader(data[pos:])
	for i := 0; i < int(fileCount); i++ {
		file, err := ReadFile(r)
		if err != nil {
			return err
		}
		m.Files = append(m.Files, *file)
	}
	return
}

// Type is the message type
func (m OfferFilesMessage) Type() uint8 {
	return MessageOfferFiles
}

func (m OfferFilesMessage) String() string {
	b := bytes.Buffer{}
	b.WriteString("[offer-files]\n")
	b.WriteString(m.Header.String())
	b.WriteString("\nfiles:\n")
	for i, file := range m.Files {
		fmt.Fprintf(&b, "file%d - %X %s:%d\n", i, file.Hash, ClientID(file.ClientID).String(), file.Port)
		for j, tag := range file.Tags {
			fmt.Fprintf(&b, "tag%d - %v: %v\n", j, tag.Name(), tag.Value())
		}

	}
	return b.String()
}

// GetServerListMessage message is sent when the client is configured to expand its list of eMule servers by querying its current server.
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
	if _, err = m.Header.WriteTo(buf); err != nil {
		return
	}
	buf.WriteByte(MessageGetServerList)

	data = buf.Bytes()
	size := len(data) - HeaderLength
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
	pos := HeaderLength
	if len(data) < pos+int(header.Size) ||
		len(data) < pos+1 {
		return ErrShortBuffer
	}
	if data[5] != MessageGetServerList {
		return ErrWrongMessageType
	}
	m.Header = header

	return
}

// Type is the message type
func (m GetServerListMessage) Type() uint8 {
	return MessageGetServerList
}

func (m GetServerListMessage) String() string {
	b := bytes.Buffer{}
	b.WriteString("[get-server-list]\n")
	b.WriteString(m.Header.String())
	return b.String()
}

// ServerListMessage message sent from the server to the client
// contains information about additional eMule servers to be used to expand the client’s server list.
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
	if _, err = m.Header.WriteTo(buf); err != nil {
		return
	}
	buf.WriteByte(MessageServerList)
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
	size := len(data) - HeaderLength
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
	pos := HeaderLength
	if len(data) < pos+int(header.Size) ||
		len(data) < pos+2 {
		return ErrShortBuffer
	}
	if data[5] != MessageServerList {
		return ErrWrongMessageType
	}
	m.Header = header
	pos++

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

// Type is the message type
func (m ServerListMessage) Type() uint8 {
	return MessageServerList
}

func (m ServerListMessage) String() string {
	b := bytes.Buffer{}
	b.WriteString("[server-list]\n")
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

// ServerStatusMessage message sent from the server to the client
// contains information on the current number of users and files on the server.
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
	if _, err = m.Header.WriteTo(buf); err != nil {
		return
	}
	buf.WriteByte(MessageServerStatus)
	binary.Write(buf, binary.LittleEndian, m.UserCount)
	binary.Write(buf, binary.LittleEndian, m.FileCount)

	data = buf.Bytes()
	size := len(data) - HeaderLength
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
	pos := HeaderLength
	if len(data) < pos+int(header.Size) ||
		len(data) < pos+9 {
		return ErrShortBuffer
	}
	if data[5] != MessageServerStatus {
		return ErrWrongMessageType
	}
	m.Header = header
	pos++

	m.UserCount = binary.LittleEndian.Uint32(data[pos : pos+4])
	pos += 4
	m.FileCount = binary.LittleEndian.Uint32(data[pos : pos+4])

	return
}

// Type is the message type
func (m ServerStatusMessage) Type() uint8 {
	return MessageServerStatus
}

func (m ServerStatusMessage) String() string {
	b := bytes.Buffer{}
	b.WriteString("[server-status]\n")
	b.WriteString(m.Header.String())
	b.WriteString("\n")
	fmt.Fprintf(&b, "users: %d, files: %d", m.UserCount, m.FileCount)
	return b.String()
}

// ServerIdentMessage message sent from the server to the client
// contains a server hash, the server IP address and
// TCP port (which may be useful when connecting through a proxy) and also server description information.
type ServerIdentMessage struct {
	message
	// A GUID of the server (seems to be used for debug).
	Hash [16]byte
	// The IP address of the server.
	IP uint32
	// The TCP port on which the server listens.
	Port uint16

	Tags []Tag
}

// Encode encodes the message to binary data.
func (m *ServerIdentMessage) Encode() (data []byte, err error) {
	if m == nil {
		return
	}
	buf := new(bytes.Buffer)
	if _, err = m.Header.WriteTo(buf); err != nil {
		return
	}
	buf.WriteByte(MessageServerIdent)
	buf.Write(m.Hash[:])
	binary.Write(buf, binary.LittleEndian, m.IP)
	binary.Write(buf, binary.LittleEndian, m.Port)
	binary.Write(buf, binary.LittleEndian, uint32(len(m.Tags)))
	for _, tag := range m.Tags {
		if _, err = tag.WriteTo(buf); err != nil {
			return
		}
	}

	data = buf.Bytes()
	size := len(data) - HeaderLength
	binary.LittleEndian.PutUint32(data[1:5], uint32(size)) // message size

	return
}

// Decode decodes the message from binary data.
func (m *ServerIdentMessage) Decode(data []byte) (err error) {
	header := Header{}
	err = header.Decode(data)
	if err != nil {
		return
	}
	pos := HeaderLength
	if len(data) < pos+int(m.Header.Size) ||
		len(data) < pos+29 {
		return ErrShortBuffer
	}
	if data[5] != MessageServerIdent {
		return ErrWrongMessageType
	}
	m.Header = header
	pos++

	pos += copy(m.Hash[:], data[pos:])
	m.IP = binary.LittleEndian.Uint32(data[pos : pos+4])
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
	return
}

// Type is the message type
func (m ServerIdentMessage) Type() uint8 {
	return MessageServerIdent
}

func (m ServerIdentMessage) String() string {
	b := bytes.Buffer{}
	b.WriteString("[server-ident]\n")
	b.WriteString(m.Header.String())
	b.WriteString("\n")
	fmt.Fprintf(&b, "addr: %s:%d, hash: %X\n",
		ClientID(m.IP).String(), m.Port, m.Hash)
	for i, tag := range m.Tags {
		fmt.Fprintf(&b, "tag%d - %v: %v\n", i, tag.Name(), tag.Value())
	}
	return b.String()
}

// SearchRequestMessage message is used to search for files by a user's search string.
// The search string may include the boolean conditions 'AND', 'OR', 'NOT'.
// The user may specify required file type and size and also set an availability
// threshold (e.g. show me results that are available from at least 5 other clients).
type SearchRequestMessage struct {
	message
	Searcher FileSearcher
}

// Encode encodes the message to binary data.
func (m *SearchRequestMessage) Encode() (data []byte, err error) {
	buf := new(bytes.Buffer)
	if _, err = m.Header.WriteTo(buf); err != nil {
		return
	}
	buf.WriteByte(MessageSearchRequest)

	b, err := m.Searcher.Encode()
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
func (m *SearchRequestMessage) Decode(data []byte) (err error) {
	// TODO: decode
	return nil
}

// Type is the message type
func (m *SearchRequestMessage) Type() uint8 {
	return MessageSearchRequest
}

func (m *SearchRequestMessage) String() string {
	b := bytes.Buffer{}
	b.WriteString("[search-request]\n")
	b.WriteString(m.Header.String())
	b.WriteString("\n")
	fmt.Fprint(&b, m.Searcher)
	return b.String()
}

// SearchResultMessage message sent from the server to the client as a reply to a search request.
// The message is usually compressed.
type SearchResultMessage struct {
	message
	Files []File
}

// Encode encodes the message to binary data.
func (m *SearchResultMessage) Encode() (data []byte, err error) {
	buf := new(bytes.Buffer)
	if _, err = m.Header.WriteTo(buf); err != nil {
		return
	}
	buf.WriteByte(MessageSearchResult)
	binary.Write(buf, binary.LittleEndian, uint32(len(m.Files)))

	for _, file := range m.Files {
		if _, err = file.WriteTo(buf); err != nil {
			return
		}
	}

	data = buf.Bytes()
	size := len(data) - HeaderLength
	binary.LittleEndian.PutUint32(data[1:5], uint32(size)) // message size
	return
}

// Decode decodes the message from binary data.
func (m *SearchResultMessage) Decode(data []byte) (err error) {
	header := Header{}
	err = header.Decode(data)
	if err != nil {
		return
	}
	pos := HeaderLength
	if len(data) < pos+int(header.Size) ||
		len(data) < pos+5 {
		return ErrShortBuffer
	}
	if data[5] != MessageSearchResult {
		return ErrWrongMessageType
	}
	m.Header = header
	pos++
	fileCount := binary.LittleEndian.Uint32(data[pos : pos+4])
	pos += 4
	r := bytes.NewReader(data[pos:])
	for i := 0; i < int(fileCount); i++ {
		file, err := ReadFile(r)
		if err != nil {
			return err
		}
		m.Files = append(m.Files, *file)
	}
	return
}

// Type is the message type
func (m SearchResultMessage) Type() uint8 {
	return MessageSearchResult
}

func (m SearchResultMessage) String() string {
	b := bytes.Buffer{}
	b.WriteString("[search-result]\n")
	b.WriteString(m.Header.String())
	b.WriteString("\nfiles:\n")
	for i, file := range m.Files {
		fmt.Fprintf(&b, "file%d - %X %s:%d\n", i, file.Hash, ClientID(file.ClientID).String(), file.Port)
		for j, tag := range file.Tags {
			fmt.Fprintf(&b, "tag%d - %v: %v\n", j, tag.Name(), tag.Value())
		}

	}
	return b.String()
}

// GetSourcesMessage message sent from the client to the server requesting sources (other clients) for a file.
type GetSourcesMessage struct {
	message
	Hash [16]byte
	Size uint32
}

// Encode encodes the message to binary data.
func (m *GetSourcesMessage) Encode() (data []byte, err error) {
	buf := new(bytes.Buffer)
	if _, err = m.Header.WriteTo(buf); err != nil {
		return
	}
	buf.WriteByte(MessageGetSources)
	buf.Write(m.Hash[:])
	binary.Write(buf, binary.LittleEndian, m.Size)

	data = buf.Bytes()
	size := len(data) - HeaderLength
	binary.LittleEndian.PutUint32(data[1:5], uint32(size)) // message size
	return
}

// Decode decodes the message from binary data.
func (m *GetSourcesMessage) Decode(data []byte) (err error) {
	header := Header{}
	err = header.Decode(data)
	if err != nil {
		return
	}
	pos := HeaderLength
	if len(data) < pos+int(header.Size) ||
		len(data) < pos+21 {
		return ErrShortBuffer
	}
	if data[5] != MessageGetSources {
		return ErrWrongMessageType
	}
	m.Header = header
	pos++

	copy(m.Hash[:], data[pos:pos+16])
	pos += 16
	m.Size = binary.LittleEndian.Uint32(data[pos : pos+4])

	return
}

// Type is the message type
func (m GetSourcesMessage) Type() uint8 {
	return MessageGetSources
}

func (m GetSourcesMessage) String() string {
	b := bytes.Buffer{}
	b.WriteString("[get-sources]\n")
	b.WriteString(m.Header.String())
	b.WriteString("\n")
	fmt.Fprintf(&b, "hash: %X, size: %d", m.Hash, m.Size)
	return b.String()
}

// FoundSourcesMessage message sent from the server to the client with sources (other clients) for a file requested by the client for a file.
type FoundSourcesMessage struct {
	message
	Hash    [16]byte
	Sources []*net.TCPAddr
}

// Encode encodes the message to binary data.
func (m *FoundSourcesMessage) Encode() (data []byte, err error) {
	buf := new(bytes.Buffer)
	if _, err = m.Header.WriteTo(buf); err != nil {
		return
	}
	buf.WriteByte(MessageFoundSources)
	buf.Write(m.Hash[:])
	binary.Write(buf, binary.LittleEndian, uint32(len(m.Sources)))

	for _, source := range m.Sources {
		if source == nil {
			source = &net.TCPAddr{
				IP:   net.IPv4zero,
				Port: 0,
			}
		}
		buf.Write(source.IP.To4())
		binary.Write(buf, binary.LittleEndian, uint16(source.Port))
	}

	data = buf.Bytes()
	size := len(data) - HeaderLength
	binary.LittleEndian.PutUint32(data[1:5], uint32(size)) // message size
	return
}

// Decode decodes the message from binary data.
func (m *FoundSourcesMessage) Decode(data []byte) (err error) {
	header := Header{}
	err = header.Decode(data)
	if err != nil {
		return
	}
	pos := HeaderLength
	if len(data) < pos+int(header.Size) ||
		len(data) < pos+18 {
		return ErrShortBuffer
	}
	if data[5] != MessageFoundSources {
		return ErrWrongMessageType
	}
	m.Header = header
	pos++

	copy(m.Hash[:], data[pos:pos+16])
	pos += 16

	count := int(data[pos])
	pos++
	if len(data) < pos+count*6 {
		return ErrShortBuffer
	}

	for i := 0; i < count; i++ {
		m.Sources = append(m.Sources,
			&net.TCPAddr{
				IP:   net.IP(data[pos : pos+4]),
				Port: int(binary.LittleEndian.Uint16(data[pos+4 : pos+6])),
			})
		pos += 6
	}

	return
}

// Type is the message type
func (m FoundSourcesMessage) Type() uint8 {
	return MessageFoundSources
}

func (m FoundSourcesMessage) String() string {
	b := bytes.Buffer{}
	b.WriteString("[found-sources]\n")
	b.WriteString(m.Header.String())
	b.WriteString("\nsources:\n")
	var ss []string
	for _, src := range m.Sources {
		ss = append(ss, src.String())
	}
	b.WriteString(strings.Join(ss, ","))
	return b.String()
}

// CallbackRequestMessage message sent from the client to the server, requesting another client to call back - e.g.
// connect to the requesting client. The message is sent by a client that has a high ID who wishes to connect to a low ID client.
type CallbackRequestMessage struct {
	message
	ClientID uint32
}

// Encode encodes the message to binary data.
func (m *CallbackRequestMessage) Encode() (data []byte, err error) {
	buf := new(bytes.Buffer)
	if _, err = m.Header.WriteTo(buf); err != nil {
		return
	}
	buf.WriteByte(MessageCallbackRequest)
	binary.Write(buf, binary.LittleEndian, m.ClientID)

	data = buf.Bytes()
	size := len(data) - HeaderLength
	binary.LittleEndian.PutUint32(data[1:5], uint32(size)) // message size
	return
}

// Decode decodes the message from binary data.
func (m *CallbackRequestMessage) Decode(data []byte) (err error) {
	header := Header{}
	err = header.Decode(data)
	if err != nil {
		return
	}
	pos := HeaderLength
	if len(data) < pos+int(header.Size) ||
		len(data) < pos+5 {
		return ErrShortBuffer
	}
	if data[5] != MessageCallbackRequest {
		return ErrWrongMessageType
	}
	m.Header = header
	pos++

	m.ClientID = binary.LittleEndian.Uint32(data[pos : pos+4])
	return
}

// Type is the message type
func (m CallbackRequestMessage) Type() uint8 {
	return MessageCallbackRequest
}

func (m CallbackRequestMessage) String() string {
	b := bytes.Buffer{}
	b.WriteString("[callback-request]\n")
	b.WriteString(m.Header.String())
	b.WriteString("\nclient:\n")
	b.WriteString(ClientID(m.ClientID).String())
	return b.String()
}

// CallbackRequestedMessage message sent from the server to the client indicating another client asks the receiving client
// to connect to it. The message is sent when the receiving client has a low ID.
// The receiving client tries to connect to the IP and port specified by the callback request packet.
type CallbackRequestedMessage struct {
	message
	IP   uint32
	Port uint16
}

// Encode encodes the message to binary data.
func (m *CallbackRequestedMessage) Encode() (data []byte, err error) {
	buf := new(bytes.Buffer)
	if _, err = m.Header.WriteTo(buf); err != nil {
		return
	}
	buf.WriteByte(MessageCallbackRequested)
	binary.Write(buf, binary.LittleEndian, m.IP)
	binary.Write(buf, binary.LittleEndian, m.Port)

	data = buf.Bytes()
	size := len(data) - HeaderLength
	binary.LittleEndian.PutUint32(data[1:5], uint32(size)) // message size
	return
}

// Decode decodes the message from binary data.
func (m *CallbackRequestedMessage) Decode(data []byte) (err error) {
	header := Header{}
	err = header.Decode(data)
	if err != nil {
		return
	}
	pos := HeaderLength
	if len(data) < pos+int(header.Size) ||
		len(data) < pos+7 {
		return ErrShortBuffer
	}
	if data[5] != MessageCallbackRequested {
		return ErrWrongMessageType
	}
	m.Header = header
	pos++

	m.IP = binary.LittleEndian.Uint32(data[pos : pos+4])
	pos += 4
	m.Port = binary.BigEndian.Uint16(data[pos : pos+2])
	return
}

// Type is the message type
func (m CallbackRequestedMessage) Type() uint8 {
	return MessageCallbackRequested
}

func (m CallbackRequestedMessage) String() string {
	b := bytes.Buffer{}
	b.WriteString("[callback-requested]\n")
	b.WriteString(m.Header.String())
	b.WriteString("\nclient:\n")
	fmt.Fprintf(&b, "%s:%d", ClientID(m.IP).String(), m.Port)
	return b.String()
}

// CallbackFailedMessage message sent from the server to the client indicating that the client’s callback request has failed.
type CallbackFailedMessage struct {
	message
}

// Encode encodes the message to binary data.
func (m *CallbackFailedMessage) Encode() (data []byte, err error) {
	buf := new(bytes.Buffer)
	if _, err = m.Header.WriteTo(buf); err != nil {
		return
	}
	buf.WriteByte(MessageCallbackFailed)

	data = buf.Bytes()
	size := len(data) - HeaderLength
	binary.LittleEndian.PutUint32(data[1:5], uint32(size)) // message size
	return
}

// Decode decodes the message from binary data.
func (m *CallbackFailedMessage) Decode(data []byte) (err error) {
	header := Header{}
	err = header.Decode(data)
	if err != nil {
		return
	}
	pos := HeaderLength
	if len(data) < pos+int(header.Size) ||
		len(data) < pos+1 {
		return ErrShortBuffer
	}
	if data[5] != MessageCallbackFailed {
		return ErrWrongMessageType
	}
	m.Header = header
	return
}

// Type is the message type
func (m CallbackFailedMessage) Type() uint8 {
	return MessageCallbackFailed
}

func (m CallbackFailedMessage) String() string {
	b := bytes.Buffer{}
	b.WriteString("[callback-failed]\n")
	b.WriteString(m.Header.String())
	return b.String()
}

// RejectedMessage message sent from the server to the client indicating that the server rejected the last command sent by the client.
type RejectedMessage struct {
	message
}

// Encode encodes the message to binary data.
func (m *RejectedMessage) Encode() (data []byte, err error) {
	buf := new(bytes.Buffer)
	if _, err = m.Header.WriteTo(buf); err != nil {
		return
	}
	buf.WriteByte(MessageRejected)

	data = buf.Bytes()
	size := len(data) - HeaderLength
	binary.LittleEndian.PutUint32(data[1:5], uint32(size)) // message size
	return
}

// Decode decodes the message from binary data.
func (m *RejectedMessage) Decode(data []byte) (err error) {
	header := Header{}
	err = header.Decode(data)
	if err != nil {
		return
	}
	pos := HeaderLength
	if len(data) < pos+int(header.Size) ||
		len(data) < pos+1 {
		return ErrShortBuffer
	}
	if data[5] != MessageRejected {
		return ErrWrongMessageType
	}
	m.Header = header
	return
}

// Type is the message type
func (m RejectedMessage) Type() uint8 {
	return MessageRejected
}

func (m RejectedMessage) String() string {
	b := bytes.Buffer{}
	b.WriteString("[rejected]\n")
	b.WriteString(m.Header.String())
	return b.String()
}
