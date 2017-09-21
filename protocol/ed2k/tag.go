package ed2k

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// tag names
const (
	TagName    = 0x01
	TagSize    = 0x02
	TagType    = 0x03
	TagFormat  = 0x04
	TagDesc    = 0x0B
	TagVersion = 0x11
	TagPort    = 0x0F
	TagFlags   = 0x20
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
	WriteTo(w io.Writer) (n int64, err error)
}

type tag struct {
	types uint8
	name  interface{}
	value interface{}
}

func (t *tag) Type() uint8 {
	return t.types
}

func (t *tag) Name() interface{} {
	return t.name
}

func (t *tag) Value() interface{} {
	return t.value
}

// ReadTag reads structured binary data from r and parses the data to tag.
func ReadTag(r io.Reader) (Tag, error) {
	if r == nil {
		return nil, io.EOF
	}
	b := make([]byte, 1024)
	if _, err := io.ReadFull(r, b[:3]); err != nil {
		return nil, err
	}
	tag := &tag{}
	tag.types = b[0]
	nlen := int(binary.LittleEndian.Uint16(b[1:3]))

	if nlen > 0 {
		if _, err := io.ReadFull(r, b[:nlen]); err != nil {
			return nil, err
		}
		if nlen == 1 {
			tag.name = int(b[0])
		} else {
			tag.name = string(b[:nlen])
		}
	} else {
		tag.name = ""
	}

	switch tag.types {
	case TagUint32:
		var v uint32
		if err := binary.Read(r, binary.LittleEndian, &v); err != nil {
			return nil, err
		}
		tag.value = int32(v)
	case TagFloat32:
		var v float32
		if err := binary.Read(r, binary.LittleEndian, &v); err != nil {
			return nil, err
		}
		tag.value = v
	case TagString:
		var vlen uint16
		if err := binary.Read(r, binary.LittleEndian, &vlen); err != nil {
			return nil, err
		}
		tag.value = ""
		if vlen > 0 {
			if _, err := io.ReadFull(r, b[:int(vlen)]); err != nil {
				return nil, err
			}
			tag.value = string(b[:int(vlen)])
		}
	default:
		return nil, errors.New("invalid type")
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
	if len(data) < 4 {
		return ErrShortBuffer
	}
	t.types = data[0]
	nlen := int(binary.LittleEndian.Uint16(data[1:]))
	if nlen == 1 {
		t.name = int(data[3])
	} else {
		if len(data) < 3+nlen {
			return ErrShortBuffer
		}
		t.name = string(data[3 : 3+nlen])
	}
	pos := 3 + nlen
	switch t.types {
	case TagUint32:
		if len(data) < pos+4 {
			return ErrShortBuffer
		}
		t.value = int32(binary.LittleEndian.Uint32(data[pos : pos+4]))
	case TagFloat32:
		if len(data) < pos+4 {
			return ErrShortBuffer
		}
		var value float32
		err = binary.Read(bytes.NewReader(data[pos:pos+4]), binary.LittleEndian, &value)
		t.value = value
	case TagString:
		if len(data) < pos+2 {
			return ErrShortBuffer
		}
		vlen := binary.LittleEndian.Uint16(data[pos : pos+2])
		pos += 2
		if len(data) < pos+int(vlen) {
			return ErrShortBuffer
		}
		t.value = string(data[pos : pos+int(vlen)])
	default:
		return errors.New("invalid type")
	}

	return
}

func (t *tag) WriteTo(w io.Writer) (n int64, err error) {
	size := 0
	if _, err = w.Write([]byte{t.types}); err != nil {
		return
	}
	size++

	if t.name == nil {
		err = errors.New("name is nil")
		return
	}
	if t.value == nil {
		err = errors.New("value is nil")
		return
	}

	switch v := t.name.(type) {
	case int:
		if _, err = w.Write([]byte{0x01, 0x00, uint8(v)}); err != nil {
			return
		}
		size += 3
	case string:
		nlen := len(v)
		if err = binary.Write(w, binary.LittleEndian, uint16(nlen)); err != nil {
			return
		}
		size += 2
		if _, err = w.Write([]byte(v)); err != nil {
			return
		}
		size += nlen
	default:
		err = fmt.Errorf("invalid name: %v", t.name)
		return
	}

	switch t.types {
	case TagUint32, TagFloat32:
		if err = binary.Write(w, binary.LittleEndian, t.value); err != nil {
			return
		}
		size += 4
	case TagString:
		v, ok := t.value.(string)
		if !ok {
			err = errors.New("value type invalid, expect string")
			return
		}
		vlen := len(v)
		if err = binary.Write(w, binary.LittleEndian, uint16(vlen)); err != nil {
			return
		}
		size += 2
		if _, err = w.Write([]byte(v)); err != nil {
			return
		}
		size += vlen
	default:
		err = fmt.Errorf("invalid tag type: %v", t.types)
		return
	}

	n = int64(size)
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
		types: uint8(types),
		name:  name,
		value: value,
	}
}

// IntegerTag is a tag with int32 integer value.
// the type of name must be int or string.
func IntegerTag(name interface{}, value int32) Tag {
	return &tag{
		types: TagInteger,
		name:  name,
		value: uint32(value),
	}
}

// Uint32Tag is a tag with uint32 integer value.
// the type of name must be int or string.
func Uint32Tag(name interface{}, value uint32) Tag {
	return &tag{
		types: TagUint32,
		name:  name,
		value: value,
	}
}

// Uint64Tag is a tag with uint64 integer value.
// the type of name must be int or string.
func Uint64Tag(name interface{}, value uint64) Tag {
	return &tag{
		types: TagUint64,
		name:  name,
		value: value,
	}
}

// Uint16Tag is a tag with uint16 integer value.
// the type of name must be int or string.
func Uint16Tag(name interface{}, value uint16) Tag {
	return &tag{
		types: TagUint16,
		name:  name,
		value: value,
	}
}

// Uint8Tag is a tag with uint8 integer value.
// the type of name must be int or string.
func Uint8Tag(name interface{}, value uint8) Tag {
	return &tag{
		types: TagUint8,
		name:  name,
		value: value,
	}
}

// BoolTag is a tag with bool value.
// the type of name must be int or string.
func BoolTag(name interface{}, value bool) Tag {
	return &tag{
		types: TagBool,
		name:  name,
		value: value,
	}
}

// FloatTag is a tag with float32 value.
// the type of name must be int or string.
func FloatTag(name interface{}, value float32) Tag {
	return &tag{
		types: TagFloat32,
		name:  name,
		value: value,
	}
}

// Float32Tag is a tag with float32 value.
// the type of name must be int or string.
func Float32Tag(name interface{}, value float32) Tag {
	return &tag{
		types: TagFloat32,
		name:  name,
		value: value,
	}
}
