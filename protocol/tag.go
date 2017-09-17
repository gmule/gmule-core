package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// type of tags
const (
	String  = 0x02
	Integer = 0x03
	Float   = 0x04
)

// Tag is TLV-like (Type, Length, Value) structure which is used for appending optional data to eMule messages.
type Tag interface {
	Type() uint8
	Name() interface{}
	Value() interface{}
	Encode() ([]byte, error)
	Decode([]byte) error
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
	case Integer:
		var v uint32
		if err := binary.Read(r, binary.LittleEndian, &v); err != nil {
			return nil, err
		}
		tag.value = int32(v)
	case Float:
		var v float32
		if err := binary.Read(r, binary.LittleEndian, &v); err != nil {
			return nil, err
		}
		tag.value = v
	case String:
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
	buf.WriteByte(t.types)

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
		buf.Write([]byte{0x01, 0x00, uint8(v)})
	case string:
		nlen := len(v)
		binary.Write(buf, binary.LittleEndian, uint16(nlen))
		buf.WriteString(v)
	default:
		err = fmt.Errorf("invalid name: %v", t.name)
		return
	}

	switch t.types {
	case Integer, Float:
		if err = binary.Write(buf, binary.LittleEndian, t.value); err != nil {
			return
		}
	case String:
		v, ok := t.value.(string)
		if !ok {
			err = errors.New("value type invalid, expect string")
			return
		}
		vlen := len(v)
		binary.Write(buf, binary.LittleEndian, uint16(vlen))
		buf.WriteString(v)
	default:
		err = fmt.Errorf("invalid tag type: %v", t.types)
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
	case Integer:
		if len(data) < pos+4 {
			return ErrShortBuffer
		}
		t.value = int32(binary.LittleEndian.Uint32(data[pos : pos+4]))
	case Float:
		if len(data) < pos+4 {
			return ErrShortBuffer
		}
		var value float32
		err = binary.Read(bytes.NewReader(data[pos:pos+4]), binary.LittleEndian, &value)
		t.value = value
	case String:
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

// IntegerTag is a tag with Integer value.
// the type of name must be int or string.
func IntegerTag(name interface{}, value int32) Tag {
	return &tag{
		types: Integer,
		name:  name,
		value: value,
	}
}

// FloatTag is a tag with Float value.
// the type of name must be int or string.
func FloatTag(name interface{}, value float32) Tag {
	return &tag{
		types: Float,
		name:  name,
		value: value,
	}
}

// StringTag is a tag with String value.
// the type of name must be int or string.
func StringTag(name interface{}, value string) Tag {
	return &tag{
		types: String,
		name:  name,
		value: value,
	}
}
