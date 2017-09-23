package ed2k

import (
	"bytes"
	"io"
	"testing"
)

func TestReadTag(t *testing.T) {
	testCases := []struct {
		in  []byte
		out Tag
	}{
		{nil, nil},
		{[]byte{}, nil},
		{[]byte{0}, nil},
		{[]byte{0, 0}, nil},
		{[]byte{0, 0, 0}, nil},
		{[]byte{0, 0, 0, 0}, nil},
		{[]byte{0xFF, 0, 0, 0, 0}, nil},

		{[]byte{TagInteger}, nil},
		{[]byte{TagInteger, 0}, nil},
		{[]byte{TagInteger, 0, 0}, nil},
		{[]byte{TagInteger, 0, 0, 0}, nil},
		{[]byte{TagInteger, 2, 0, 0}, nil},
		{[]byte{TagInteger, 1, 0, 1}, nil},
		{[]byte{TagInteger, 0, 0, 0, 0}, nil},
		{[]byte{TagInteger, 0, 0, 0, 0, 0}, nil},
		{[]byte{TagInteger, 0, 0, 0, 0, 0, 0}, IntegerTag("", 0)},
		{[]byte{TagInteger, 0, 0, 0, 0, 0, 0, 0}, IntegerTag("", 0)},
		{[]byte{TagInteger, 1, 0, 1, 0}, nil},
		{[]byte{TagInteger, 1, 0, 0, 0, 0, 0}, nil},
		{[]byte{TagInteger, 1, 0, 1, 0, 0, 0, 0}, IntegerTag(1, 0)},
		{[]byte{TagInteger, 1, 0, 1, 0, 0, 0, 0, 0}, IntegerTag(1, 0)},
		{[]byte{TagInteger, 1, 0, 'a', 0, 0, 0, 0}, IntegerTag(int('a'), 0)},
		{[]byte{TagInteger, 0, 0, 1, 0, 0, 0}, IntegerTag("", 1)},
		{[]byte{TagInteger, 0, 0, 1, 0, 0, 0, 0}, IntegerTag("", 1)},
		{[]byte{TagInteger, 1, 0, 1, 1, 0, 0, 0}, IntegerTag(1, 1)},
		{[]byte{TagInteger, 1, 0, 'a', 1, 0, 0, 0}, IntegerTag(int('a'), 1)},
		{[]byte{TagInteger, 1, 0, 1, 1, 0, 0, 0, 1}, IntegerTag(1, 1)},
		{[]byte{TagInteger, 3, 0, 'a', 'b', 'c'}, nil},
		{[]byte{TagInteger, 3, 0, 0, 0, 0, 0}, nil},
		{[]byte{TagInteger, 3, 0, 'a', 0, 0, 0, 0}, nil},
		{[]byte{TagInteger, 3, 0, 'a', 'b', 0, 0, 0, 0}, nil},
		{[]byte{TagInteger, 3, 0, 'a', 'b', 'c', 0, 0, 0, 0}, IntegerTag("abc", 0)},
		{[]byte{TagInteger, 3, 0, 'a', 'b', 'c', 1, 0, 0, 0}, IntegerTag("abc", 1)},
		{[]byte{TagInteger, 3, 0, 'a', 'b', 'c', 1, 0, 0, 0, 1}, IntegerTag("abc", 1)},

		{[]byte{TagFloat}, nil},
		{[]byte{TagFloat, 0}, nil},
		{[]byte{TagFloat, 0, 0}, nil},
		{[]byte{TagFloat, 0, 0, 0}, nil},
		{[]byte{TagFloat, 2, 0, 0}, nil},
		{[]byte{TagFloat, 1, 0, 1}, nil},
		{[]byte{TagFloat, 0, 0, 0, 0}, nil},
		{[]byte{TagFloat, 0, 0, 0, 0, 0}, nil},
		{[]byte{TagFloat, 0, 0, 0, 0, 0, 0}, FloatTag("", 0)},
		{[]byte{TagFloat, 0, 0, 0, 0, 0, 0, 0}, FloatTag("", 0)},
		{[]byte{TagFloat, 1, 0, 1, 0}, nil},
		{[]byte{TagFloat, 1, 0, 0, 0, 0, 0}, nil},
		{[]byte{TagFloat, 1, 0, 1, 0, 0, 0, 0}, FloatTag(1, 0)},
		{[]byte{TagFloat, 1, 0, 1, 0, 0, 0, 0, 0}, FloatTag(1, 0)},
		{[]byte{TagFloat, 1, 0, 'a', 0, 0, 0, 0}, FloatTag(int('a'), 0)},
		{[]byte{TagFloat, 0, 0, 0, 0, 0x80, 0x3F}, FloatTag("", 1)},
		{[]byte{TagFloat, 0, 0, 0, 0, 0x80, 0x3F, 0}, FloatTag("", 1)},
		{[]byte{TagFloat, 1, 0, 1, 0, 0, 0x80, 0x3F}, FloatTag(1, 1)},
		{[]byte{TagFloat, 1, 0, 'a', 0, 0, 0x80, 0x3F}, FloatTag(int('a'), 1)},
		{[]byte{TagFloat, 1, 0, 1, 0, 0, 0x80, 0x3F, 1}, FloatTag(1, 1)},
		{[]byte{TagFloat, 3, 0, 'a', 'b', 'c'}, nil},
		{[]byte{TagFloat, 3, 0, 0, 0, 0, 0}, nil},
		{[]byte{TagFloat, 3, 0, 'a', 0, 0, 0, 0}, nil},
		{[]byte{TagFloat, 3, 0, 'a', 'b', 0, 0, 0, 0}, nil},
		{[]byte{TagFloat, 3, 0, 'a', 'b', 'c', 0, 0, 0, 0}, FloatTag("abc", 0)},
		{[]byte{TagFloat, 3, 0, 'a', 'b', 'c', 0, 0, 0x80, 0x3F}, FloatTag("abc", 1)},
		{[]byte{TagFloat, 3, 0, 'a', 'b', 'c', 0, 0, 0x80, 0x3F, 1}, FloatTag("abc", 1)},

		{[]byte{TagString}, nil},
		{[]byte{TagString, 0}, nil},
		{[]byte{TagString, 0, 0}, nil},
		{[]byte{TagString, 0, 0, 0}, nil},
		{[]byte{TagString, 2, 0, 0}, nil},
		{[]byte{TagString, 1, 0, 1}, nil},
		{[]byte{TagString, 0, 0, 0, 0}, StringTag("", "", false)},
		{[]byte{TagString, 0, 0, 0, 0, 0}, StringTag("", "", false)},
		{[]byte{TagString, 0, 0, 0, 0, 0, 0}, StringTag("", "", false)},
		{[]byte{TagString, 0, 0, 0, 0, 0, 0, 0}, StringTag("", "", false)},
		{[]byte{TagString, 1, 0, 0, 0}, nil},
		{[]byte{TagString, 1, 0, 0, 0, 0}, StringTag(0, "", false)},
		{[]byte{TagString, 1, 0, 0, 0, 0, 0}, StringTag(0, "", false)},
		{[]byte{TagString, 1, 0, 1, 0}, nil},
		{[]byte{TagString, 1, 0, 1, 0, 0}, StringTag(1, "", false)},
		{[]byte{TagString, 1, 0, 1, 0, 0, 0, 0}, StringTag(1, "", false)},
		{[]byte{TagString, 1, 0, 1, 0, 0, 0, 0, 0}, StringTag(1, "", false)},
		{[]byte{TagString, 1, 0, 'a', 0, 0}, StringTag(int('a'), "", false)},
		{[]byte{TagString, 1, 0, 'a', 0, 0, 0}, StringTag(int('a'), "", false)},
		{[]byte{TagString, 0, 0, 1, 0}, nil},
		{[]byte{TagString, 0, 0, 1, 0, 0}, StringTag("", string(0), false)},
		{[]byte{TagString, 0, 0, 1, 0, 'a'}, StringTag("", "a", false)},
		{[]byte{TagString, 0, 0, 2, 0}, nil},
		{[]byte{TagString, 0, 0, 2, 0, 'a'}, nil},
		{[]byte{TagString, 0, 0, 1, 0, 'a', 0, 0}, StringTag("", "a", false)},
		{[]byte{TagString, 1, 0, 1, 1, 0}, nil},
		{[]byte{TagString, 1, 0, 1, 1, 0, 0}, StringTag(1, string(0), false)},
		{[]byte{TagString, 1, 0, 'a', 1, 0, 'a', 'b'}, StringTag(int('a'), "a", false)},
		{[]byte{TagString, 3, 0, 0, 0, 0}, nil},
		{[]byte{TagString, 3, 0, 'a', 'b', 'c'}, nil},
		{[]byte{TagString, 3, 0, 'a', 'b', 'c', 0, 0}, StringTag("abc", "", false)},
		{[]byte{TagString, 3, 0, 'a', 'b', 'c', 1, 0}, nil},
		{[]byte{TagString, 3, 0, 'a', 'b', 'c', 1, 0, 0}, StringTag("abc", string(0), false)},
		{[]byte{TagString, 3, 0, 'a', 'b', 'c', 1, 0, 0, 'a'}, StringTag("abc", string(0), false)},
		{[]byte{TagString, 3, 0, 'a', 'b', 'c', 3, 0, 'a', 'b'}, nil},
		{[]byte{TagString, 3, 0, 'a', 'b', 'c', 3, 0, 'a', 'b', 'c'}, StringTag("abc", "abc", false)},
		{[]byte{TagString, 3, 0, 'a', 'b', 'c', 3, 0, 'a', 'b', 'c', 'd'}, StringTag("abc", "abc", false)},
	}

	for i, tc := range testCases {
		var r io.Reader
		if tc.in != nil {
			r = bytes.NewReader(tc.in)
		}
		tag, err := ReadTag(r)
		if err != nil {
			t.Log(i, err)
		}
		if !tagEqual(tag, tc.out) {
			t.Fail()
		}
	}
}

func tagEqual(t1, t2 Tag) bool {
	if t1 == t2 {
		return true
	}
	if t1 == nil || t2 == nil {
		return false
	}
	return t1.Type() == t2.Type() && t1.Name() == t2.Name() && t1.Value() == t2.Value()
}

func TestTagEncode(t *testing.T) {
	testCases := []struct {
		in  Tag
		out []byte
	}{
		{&tag{}, nil},
		{&tag{name: 1}, nil},
		{&tag{value: 0.1}, nil},
		{&tag{name: 1, value: 1}, nil},
		{&tag{tagType: 1, name: 1, value: [16]byte{}}, []byte{TagHash16, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
		{&tag{tagType: TagInteger, name: 1, value: 1}, []byte{TagInteger, 1, 0, 1, 0, 0, 0, 0}},
		{&tag{tagType: TagInteger, name: 1, value: uint32(1)}, []byte{TagInteger, 1, 0, 1, 1, 0, 0, 0}},
		{&tag{tagType: TagString, name: 0, value: 1}, []byte{TagString, 1, 0, 0, 0, 0}},
	}

	for i, tc := range testCases {
		b, err := tc.in.Encode()
		if err != nil {
			t.Log(i, err)
		}
		if !bytes.Equal(b, tc.out) {
			t.Log(i, "failed")
			t.Fail()
		}
	}
}

func TestTagDecode(t *testing.T) {
	testCases := []struct {
		in  []byte
		out Tag
	}{
		{nil, &tag{}},
		{[]byte{}, &tag{}},
		{[]byte{0}, &tag{}},
		{[]byte{0, 0}, &tag{}},
		{[]byte{0, 0, 0}, &tag{name: ""}},
		{[]byte{0, 0, 0, 0}, &tag{name: ""}},
		{[]byte{0xFF, 0, 0, 0, 0}, &tag{tagType: 0x7F, name: 0x0100}},
		{[]byte{TagInteger}, &tag{tagType: TagInteger}},
		{[]byte{TagInteger, 0}, &tag{tagType: TagInteger}},
		{[]byte{TagInteger, 0, 0}, &tag{tagType: TagInteger, name: ""}},
		{[]byte{TagInteger, 0, 0, 0}, &tag{tagType: TagInteger, name: ""}},
		{[]byte{TagInteger, 2, 0, 0}, &tag{tagType: TagInteger}},
		{[]byte{TagInteger, 1, 0, 1}, &tag{tagType: TagInteger, name: 1}},
		{[]byte{TagFloat, 0, 0, 0}, &tag{tagType: TagFloat, name: ""}},
		{[]byte{TagFloat, 2, 0, 0}, &tag{tagType: TagFloat}},
		{[]byte{TagFloat, 1, 0, 1}, &tag{tagType: TagFloat, name: 1}},
		{[]byte{TagString, 0, 0, 0}, &tag{tagType: TagString, name: ""}},
		{[]byte{TagString, 0, 0, 1, 0}, &tag{tagType: TagString, name: "", value: ""}},
		{[]byte{TagString, 0, 0, 0, 0}, &tag{tagType: TagString, name: "", value: ""}},
	}

	for i, tc := range testCases {
		tag := &tag{}
		if err := tag.Decode(tc.in); err != nil {
			t.Log(i, err)
		}
		if !tagEqual(tag, tc.out) {
			t.Log(i, "failed")
			t.Fail()
		}
	}
}

func TestIntegerTagEncode(t *testing.T) {
	testCases := []struct {
		in  Tag
		out []byte
	}{
		{IntegerTag(int32(1), 0), nil},
		{IntegerTag(1.0, 0), nil},
		{IntegerTag(0, 0), []byte{TagInteger, 1, 0, 0, 0, 0, 0, 0}},
		{IntegerTag(1, 0), []byte{TagInteger, 1, 0, 1, 0, 0, 0, 0}},
		{IntegerTag(0, 1), []byte{TagInteger, 1, 0, 0, 1, 0, 0, 0}},
		{IntegerTag(1, 1), []byte{TagInteger, 1, 0, 1, 1, 0, 0, 0}},
		{IntegerTag(1, -1), []byte{TagInteger, 1, 0, 1, 0xFF, 0xFF, 0xFF, 0xFF}},
		{IntegerTag("", 0), []byte{TagInteger, 0, 0, 0, 0, 0, 0}},
		{IntegerTag("", 1), []byte{TagInteger, 0, 0, 1, 0, 0, 0}},
		{IntegerTag("abc", 0), []byte{TagInteger, 3, 0, 'a', 'b', 'c', 0, 0, 0, 0}},
		{IntegerTag("abc", 1), []byte{TagInteger, 3, 0, 'a', 'b', 'c', 1, 0, 0, 0}},
		{IntegerTag("abc", -1), []byte{TagInteger, 3, 0, 'a', 'b', 'c', 0xFF, 0xFF, 0xFF, 0xFF}},
	}

	for _, tc := range testCases {
		b, err := tc.in.Encode()
		if err != nil {
			t.Log(err)
		}
		if !bytes.Equal(b, tc.out) {
			t.Fail()
		}
	}
}

func TestIntegerTagDecode(t *testing.T) {
	testCases := []struct {
		in  []byte
		out Tag
	}{
		{[]byte{TagInteger, 1, 0, 0, 0, 0, 0, 0}, IntegerTag(0, 0)},
		{[]byte{TagInteger, 1, 0, 1, 0, 0, 0, 0}, IntegerTag(1, 0)},
		{[]byte{TagInteger, 1, 0, 0, 1, 0, 0, 0}, IntegerTag(0, 1)},
		{[]byte{TagInteger, 1, 0, 1, 1, 0, 0, 0}, IntegerTag(1, 1)},
		{[]byte{TagInteger, 1, 0, 1, 0xFF, 0xFF, 0xFF, 0xFF}, IntegerTag(1, -1)},
		{[]byte{TagInteger, 0, 0, 0, 0, 0, 0}, IntegerTag("", 0)},
		{[]byte{TagInteger, 0, 0, 1, 0, 0, 0}, IntegerTag("", 1)},
		{[]byte{TagInteger, 3, 0, 'a', 'b', 'c', 0, 0, 0, 0}, IntegerTag("abc", 0)},
		{[]byte{TagInteger, 3, 0, 'a', 'b', 'c', 1, 0, 0, 0}, IntegerTag("abc", 1)},
		{[]byte{TagInteger, 3, 0, 'a', 'b', 'c', 0xFF, 0xFF, 0xFF, 0xFF}, IntegerTag("abc", -1)},
	}

	for _, tc := range testCases {
		tag := &tag{}
		if err := tag.Decode(tc.in); err != nil {
			t.Log(err)
		}
		if !tagEqual(tag, tc.out) {
			t.Fail()
		}
	}
}

func TestFloatTagEncode(t *testing.T) {
	testCases := []struct {
		in  Tag
		out []byte
	}{
		{FloatTag(int32(1), 0), nil},
		{FloatTag(1.0, 0), nil},
		{FloatTag(0, 0), []byte{TagFloat, 1, 0, 0, 0, 0, 0, 0}},
		{FloatTag(1, 0), []byte{TagFloat, 1, 0, 1, 0, 0, 0, 0}},
		{FloatTag(0, 1), []byte{TagFloat, 1, 0, 0, 0, 0, 0x80, 0x3F}},
		{FloatTag(1, 1), []byte{TagFloat, 1, 0, 1, 0, 0, 0x80, 0x3F}},
		{FloatTag(1, -1), []byte{TagFloat, 1, 0, 1, 0, 0, 0x80, 0xBF}},
		{FloatTag("", 0), []byte{TagFloat, 0, 0, 0, 0, 0, 0}},
		{FloatTag("", 1), []byte{TagFloat, 0, 0, 0, 0, 0x80, 0x3F}},
		{FloatTag("abc", 0), []byte{TagFloat, 3, 0, 'a', 'b', 'c', 0, 0, 0, 0}},
		{FloatTag("abc", 1), []byte{TagFloat, 3, 0, 'a', 'b', 'c', 0, 0, 0x80, 0x3F}},
		{FloatTag("abc", -1), []byte{TagFloat, 3, 0, 'a', 'b', 'c', 0, 0, 0x80, 0xBF}},
	}

	for _, tc := range testCases {
		b, err := tc.in.Encode()
		if err != nil {
			t.Log(err)
		}
		if !bytes.Equal(b, tc.out) {
			t.Fail()
		}
	}
}

func TestFloatTagDecode(t *testing.T) {
	testCases := []struct {
		in  []byte
		out Tag
	}{
		{[]byte{TagFloat, 1, 0, 0, 0, 0, 0, 0}, FloatTag(0, 0)},
		{[]byte{TagFloat, 1, 0, 1, 0, 0, 0, 0}, FloatTag(1, 0)},
		{[]byte{TagFloat, 1, 0, 0, 0, 0, 0x80, 0x3F}, FloatTag(0, 1)},
		{[]byte{TagFloat, 1, 0, 1, 0, 0, 0x80, 0x3F}, FloatTag(1, 1)},
		{[]byte{TagFloat, 1, 0, 1, 0, 0, 0x80, 0xBF}, FloatTag(1, -1)},
		{[]byte{TagFloat, 0, 0, 0, 0, 0, 0}, FloatTag("", 0)},
		{[]byte{TagFloat, 0, 0, 0, 0, 0x80, 0x3F}, FloatTag("", 1)},
		{[]byte{TagFloat, 3, 0, 'a', 'b', 'c', 0, 0, 0, 0}, FloatTag("abc", 0)},
		{[]byte{TagFloat, 3, 0, 'a', 'b', 'c', 0, 0, 0x80, 0x3F}, FloatTag("abc", 1)},
		{[]byte{TagFloat, 3, 0, 'a', 'b', 'c', 0, 0, 0x80, 0xBF}, FloatTag("abc", -1)},
	}

	for _, tc := range testCases {
		tag := &tag{}
		if err := tag.Decode(tc.in); err != nil {
			t.Log(err)
		}
		if !tagEqual(tag, tc.out) {
			t.Fail()
		}
	}
}

func TestStringTagEncode(t *testing.T) {
	testCases := []struct {
		in  Tag
		out []byte
	}{
		{StringTag(int32(1), "", false), nil},
		{StringTag(1.0, "", false), nil},
		{StringTag(0, "", false), []byte{TagString, 1, 0, 0, 0, 0}},
		{StringTag(1, "", false), []byte{TagString, 1, 0, 1, 0, 0}},
		{StringTag(0, "abc", false), []byte{TagString, 1, 0, 0, 3, 0, 'a', 'b', 'c'}},
		{StringTag(1, "abc", false), []byte{TagString, 1, 0, 1, 3, 0, 'a', 'b', 'c'}},
		{StringTag("", "", false), []byte{TagString, 0, 0, 0, 0}},
		{StringTag("", "abc", false), []byte{TagString, 0, 0, 3, 0, 'a', 'b', 'c'}},
		{StringTag("abc", "", false), []byte{TagString, 3, 0, 'a', 'b', 'c', 0, 0}},
		{StringTag("abc", "abc", false), []byte{TagString, 3, 0, 'a', 'b', 'c', 3, 0, 'a', 'b', 'c'}},
	}

	for _, tc := range testCases {
		b, err := tc.in.Encode()
		if err != nil {
			t.Log(err)
		}
		if !bytes.Equal(b, tc.out) {
			t.Fail()
		}
	}
}

func TestStringTagDecode(t *testing.T) {
	testCases := []struct {
		in  []byte
		out Tag
	}{
		{[]byte{TagString, 1, 0, 0, 0, 0}, StringTag(0, "", false)},
		{[]byte{TagString, 1, 0, 1, 0, 0}, StringTag(1, "", false)},
		{[]byte{TagString, 1, 0, 0, 3, 0, 'a', 'b', 'c'}, StringTag(0, "abc", false)},
		{[]byte{TagString, 1, 0, 1, 3, 0, 'a', 'b', 'c'}, StringTag(1, "abc", false)},
		{[]byte{TagString, 0, 0, 0, 0}, StringTag("", "", false)},
		{[]byte{TagString, 0, 0, 3, 0, 'a', 'b', 'c'}, StringTag("", "abc", false)},
		{[]byte{TagString, 3, 0, 'a', 'b', 'c', 0, 0}, StringTag("abc", "", false)},
		{[]byte{TagString, 3, 0, 'a', 'b', 'c', 3, 0, 'a', 'b', 'c'}, StringTag("abc", "abc", false)},
	}

	for _, tc := range testCases {
		tag := &tag{}
		if err := tag.Decode(tc.in); err != nil {
			t.Log(err)
		}
		if !tagEqual(tag, tc.out) {
			t.Fail()
		}
	}
}
