package ed2k

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
)

// tag names
const (
	TagName         = 0x01
	TagSize         = 0x02
	TagType         = 0x03
	TagFormat       = 0x04
	TagDesc         = 0x0B
	TagVersion      = 0x11
	TagPort         = 0x0F
	TagServerFlags  = 0x20 // currently only used to inform a server about supported features.
	TagEMuleVersion = 0xFB

	// tag flags for internal usage

	// This flag indicates that the flag name is just 1 byte without size field.
	// The MSB of tag type will be turned on if set.
	TagCompactNameFlag = 0x100
)

// Tag types
const (
	TagHash16    = 0x01
	TagString    = 0x02
	TagUint32    = 0x03
	TagInteger   = 0x03 // uint32 alias
	TagFloat32   = 0x04
	TagFloat     = 0x04 // float32 alias
	TagBool      = 0x05
	TagBoolArray = 0x06
	TagBlob      = 0x07
	TagUint16    = 0x08
	TagUint8     = 0x09
	TagBsob      = 0x0A
	TagUint64    = 0x0B

	// Compressed string types
	TagStr0  = 0x10 // start tag
	TagStr1  = 0x11
	TagStr2  = 0x12
	TagStr3  = 0x13
	TagStr4  = 0x14
	TagStr5  = 0x15
	TagStr6  = 0x16
	TagStr7  = 0x17
	TagStr8  = 0x18
	TagStr9  = 0x19
	TagStr10 = 0x1A
	TagStr11 = 0x1B
	TagStr12 = 0x1C
	TagStr13 = 0x1D
	TagStr14 = 0x1E
	TagStr15 = 0x1F
	TagStr16 = 0x20

	// Additional media meta data tags from eDonkeyHybrid (note also the uppercase/lowercase)
	FileMediaArtist  = "Artist"
	FileMediaAlbum   = "Album"
	FileMediaTitle   = "Title"
	FileMediaLength  = "length"
	FileMediaBitrate = "bitrate"
	FileMediaCodec   = "codec"
)

// tag name type
const (
	TagStringName = 0
	TagIntName    = 1
)

// Server capabilities, values for flags
const (
	CapZlib         = 0x0001
	CapIPInLogin    = 0x0002
	CapAuxPort      = 0x0004
	CapNewTag       = 0x0008
	CapUnicode      = 0x0010
	CapLargeFiles   = 0x0100
	CapSupportCrypt = 0x0200
	CapRequestCrypt = 0x0400
	CapRequireCrypt = 0x0800
)

// Tag is TLV-like (Type, Length, Value) structure which is used for appending optional data to eMule messages.
type Tag interface {
	Type() uint8
	Name() interface{}
	Value() interface{}
	Encode() ([]byte, error)
	Decode([]byte) error
	ReadFrom(r io.Reader) (n int64, err error)
	WriteTo(w io.Writer) (n int64, err error)
}

type tag struct {
	tagType uint8
	name    interface{}
	value   interface{}
}

func (t *tag) Type() uint8 {
	return t.tagType
}

func (t *tag) Name() interface{} {
	switch v := t.name.(type) {
	case int:
		return v & 0xFF
	case string:
		return v
	default:
		return ""
	}
}

func (t *tag) Value() interface{} {
	return t.value
}

// ReadTag reads structured binary data from r and parses the data to tag.
func ReadTag(r io.Reader) (Tag, error) {
	if r == nil {
		return nil, io.EOF
	}

	tag := &tag{}
	if _, err := tag.ReadFrom(r); err != nil {
		return nil, err
	}
	return tag, nil
}

func (t *tag) Encode() (data []byte, err error) {
	buf := new(bytes.Buffer)
	if _, err = t.WriteTo(buf); err != nil {
		return
	}
	data = buf.Bytes()
	return
}

func (t *tag) Decode(data []byte) (err error) {
	buf := bytes.NewReader(data)
	_, err = t.ReadFrom(buf)
	return
}

func (t *tag) ReadFrom(r io.Reader) (n int64, err error) {
	b := make([]byte, 1024) // TODO: we should check buffer size when reading from r.
	if _, err = io.ReadFull(r, b[:1]); err != nil {
		return
	}
	t.tagType = b[0] & 0x7F
	n++

	nlen := 0
	flags := 0
	if b[0]&0x80 > 0 {
		nlen = 1
		flags |= TagCompactNameFlag
	} else {
		if _, err = io.ReadFull(r, b[1:3]); err != nil {
			return
		}
		nlen = int(binary.LittleEndian.Uint16(b[1:3]))
		n += 2
	}

	if nlen > 0 {
		if _, err = io.ReadFull(r, b[:nlen]); err != nil {
			return
		}
		if nlen == 1 {
			t.name = int(b[0]) | flags
		} else {
			t.name = string(b[:nlen])
		}
		n += int64(nlen)
	} else {
		t.name = ""
	}

	switch t.tagType {
	case TagBool:
		var v uint8
		if err = binary.Read(r, binary.LittleEndian, &v); err != nil {
			return
		}
		t.value = false
		if v > 0 {
			t.value = true
		}
		n++

	case TagUint8:
		var v uint8
		if err = binary.Read(r, binary.LittleEndian, &v); err != nil {
			return
		}
		t.value = v
		n++

	case TagUint16:
		var v uint16
		if err = binary.Read(r, binary.LittleEndian, &v); err != nil {
			return
		}
		t.value = v
		n += 2

	case TagUint32:
		var v uint32
		if err = binary.Read(r, binary.LittleEndian, &v); err != nil {
			return
		}
		t.value = v
		n += 4

	case TagUint64:
		var v uint64
		if err = binary.Read(r, binary.LittleEndian, &v); err != nil {
			return
		}
		t.value = v
		n += 8

	case TagFloat32:
		var v float32
		if err = binary.Read(r, binary.LittleEndian, &v); err != nil {
			return
		}
		t.value = v
		n += 4

	case TagString:
		var vlen uint16
		if err = binary.Read(r, binary.LittleEndian, &vlen); err != nil {
			return
		}
		n += 2

		t.value = ""
		if vlen > 0 {
			if _, err = io.ReadFull(r, b[:int(vlen)]); err != nil {
				return
			}
			t.value = string(b[:int(vlen)])
		}
		n += int64(vlen)

	case TagStr1, TagStr2, TagStr3, TagStr4, TagStr5, TagStr6, TagStr7, TagStr8,
		TagStr9, TagStr10, TagStr11, TagStr12, TagStr13, TagStr14, TagStr15, TagStr16:
		vlen := int(t.tagType - TagStr0)
		if _, err = io.ReadFull(r, b[:vlen]); err != nil {
			return
		}
		t.value = string(b[:vlen])
		n += int64(vlen)

	case TagHash16:
		vlen := 16
		if _, err = io.ReadFull(r, b[:vlen]); err != nil {
			return
		}
		t.value = b[:vlen]
		n += int64(vlen)

	default:
		err = errors.New("invalid type")
		return
	}
	return
}

func (t *tag) WriteTo(w io.Writer) (n int64, err error) {
	if t.name == nil {
		err = errors.New("name is nil")
		return
	}
	if t.value == nil {
		err = errors.New("value is nil")
		return
	}

	tagType := t.tagType & 0x7F
	switch v := t.name.(type) {
	case int:
		var b []byte
		if v&TagCompactNameFlag != 0 {
			b = []byte{tagType | 0x80, uint8(v & 0xFF)}
		} else {
			b = []byte{tagType, 0x01, 0x00, uint8(v & 0xFF)}
		}
		if _, err = w.Write(b); err != nil {
			return
		}
		n += int64(len(b))

	case string:
		if _, err = w.Write([]byte{tagType}); err != nil {
			return
		}

		nlen := len(v)
		if err = binary.Write(w, binary.LittleEndian, uint16(nlen)); err != nil {
			return
		}
		n += 2
		if _, err = w.Write([]byte(v)); err != nil {
			return
		}
		n += int64(nlen)

	default:
		err = fmt.Errorf("invalid name: %v", t.name)
		return
	}

	switch tagType {
	case TagBool:
		v, _ := t.value.(bool)
		if err = binary.Write(w, binary.LittleEndian, v); err != nil {
			return
		}
		n++

	case TagUint8:
		v, _ := t.value.(uint8)
		if err = binary.Write(w, binary.LittleEndian, v); err != nil {
			return
		}
		n++

	case TagUint16:
		v, _ := t.value.(uint16)
		if err = binary.Write(w, binary.LittleEndian, v); err != nil {
			return
		}
		n += 2

	case TagUint32:
		v, _ := t.value.(uint32)
		if err = binary.Write(w, binary.LittleEndian, v); err != nil {
			return
		}
		n += 4

	case TagUint64:
		v, _ := t.value.(uint64)
		if err = binary.Write(w, binary.LittleEndian, v); err != nil {
			return
		}
		n += 8

	case TagFloat32:
		v, _ := t.value.(float32)
		if err = binary.Write(w, binary.LittleEndian, v); err != nil {
			return
		}
		n += 4

	case TagString:
		v, _ := t.value.(string)
		vlen := len(v)
		if err = binary.Write(w, binary.LittleEndian, uint16(vlen)); err != nil {
			return
		}
		n += 2

		if _, err = w.Write([]byte(v)); err != nil {
			return
		}
		n += int64(vlen)

	case TagStr1, TagStr2, TagStr3, TagStr4, TagStr5, TagStr6, TagStr7, TagStr8,
		TagStr9, TagStr10, TagStr11, TagStr12, TagStr13, TagStr14, TagStr15, TagStr16:
		v, _ := t.value.(string)
		if len(v) == 0 {
			err = errors.New("empty string value")
			break
		}
		vlen := tagType - TagStr0
		if _, err = w.Write([]byte(v[:vlen])); err != nil {
			return
		}
		n += int64(vlen)

	case TagHash16:
		v, _ := t.value.([16]byte)
		vlen := len(v)
		if _, err = w.Write(v[:]); err != nil {
			return
		}
		n += int64(vlen)

	default:
		err = fmt.Errorf("invalid tag type: %v", t.tagType)
		return
	}

	return
}

// StringTag is a tag with String value, it supports compressing if length is less than or equal to 16-byte.
// the type of name must be int or string.
func StringTag(name interface{}, value string, compress bool) Tag {
	types := TagString
	if len(value) <= 16 && compress {
		types = TagStr0 + len(value)
	}

	return &tag{
		tagType: uint8(types),
		name:    name,
		value:   value,
	}
}

// BoolTag is a tag with bool value.
// the type of name must be int or string.
func BoolTag(name interface{}, value bool) Tag {
	return &tag{
		tagType: TagBool,
		name:    name,
		value:   value,
	}
}

// Uint8Tag is a tag with uint8 integer value.
// the type of name must be int or string.
func Uint8Tag(name interface{}, value uint8) Tag {
	return &tag{
		tagType: TagUint8,
		name:    name,
		value:   value,
	}
}

// Uint16Tag is a tag with uint16 integer value.
// the type of name must be int or string.
func Uint16Tag(name interface{}, value uint16) Tag {
	return &tag{
		tagType: TagUint16,
		name:    name,
		value:   value,
	}
}

// IntegerTag is a tag with integer value, the actual tag type is based on integer value v.
// the type of name must be int or string.
func IntegerTag(name interface{}, v uint64) Tag {
	tag := &tag{
		name: name,
	}

	if v <= math.MaxUint8 {
		tag.tagType = TagUint8
		tag.value = uint8(v)
	} else if v <= math.MaxUint16 {
		tag.tagType = TagUint16
		tag.value = uint16(v)
	} else if v <= math.MaxUint32 {
		tag.tagType = TagUint32
		tag.value = uint32(v)
	} else {
		tag.tagType = TagUint64
		tag.value = uint64(v)
	}
	return tag
}

// Uint32Tag is a tag with uint32 integer value.
// the type of name must be int or string.
func Uint32Tag(name interface{}, value uint32) Tag {
	return &tag{
		tagType: TagUint32,
		name:    name,
		value:   value,
	}
}

// Uint64Tag is a tag with uint64 integer value.
// the type of name must be int or string.
func Uint64Tag(name interface{}, value uint64) Tag {
	return &tag{
		tagType: TagUint64,
		name:    name,
		value:   value,
	}
}

// FloatTag is a tag with float32 value.
// the type of name must be int or string.
func FloatTag(name interface{}, value float32) Tag {
	return &tag{
		tagType: TagFloat32,
		name:    name,
		value:   value,
	}
}

// Float32Tag is a tag with float32 value.
// the type of name must be int or string.
func Float32Tag(name interface{}, value float32) Tag {
	return &tag{
		tagType: TagFloat32,
		name:    name,
		value:   value,
	}
}

// Hash16Tag is a tag with 16-byte hash value.
// the type of name must be int or string.
func Hash16Tag(name interface{}, value [16]byte) Tag {
	return &tag{
		tagType: TagHash16,
		name:    name,
		value:   value[:],
	}
}
