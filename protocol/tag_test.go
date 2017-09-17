package protocol

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

		{[]byte{Integer}, nil},
		{[]byte{Integer, 0}, nil},
		{[]byte{Integer, 0, 0}, nil},
		{[]byte{Integer, 0, 0, 0}, nil},
		{[]byte{Integer, 2, 0, 0}, nil},
		{[]byte{Integer, 1, 0, 1}, nil},
		{[]byte{Integer, 0, 0, 0, 0}, nil},
		{[]byte{Integer, 0, 0, 0, 0, 0}, nil},
		{[]byte{Integer, 0, 0, 0, 0, 0, 0}, IntegerTag("", 0)},
		{[]byte{Integer, 0, 0, 0, 0, 0, 0, 0}, IntegerTag("", 0)},
		{[]byte{Integer, 1, 0, 1, 0}, nil},
		{[]byte{Integer, 1, 0, 0, 0, 0, 0}, nil},
		{[]byte{Integer, 1, 0, 1, 0, 0, 0, 0}, IntegerTag(1, 0)},
		{[]byte{Integer, 1, 0, 1, 0, 0, 0, 0, 0}, IntegerTag(1, 0)},
		{[]byte{Integer, 1, 0, 'a', 0, 0, 0, 0}, IntegerTag(int('a'), 0)},
		{[]byte{Integer, 0, 0, 1, 0, 0, 0}, IntegerTag("", 1)},
		{[]byte{Integer, 0, 0, 1, 0, 0, 0, 0}, IntegerTag("", 1)},
		{[]byte{Integer, 1, 0, 1, 1, 0, 0, 0}, IntegerTag(1, 1)},
		{[]byte{Integer, 1, 0, 'a', 1, 0, 0, 0}, IntegerTag(int('a'), 1)},
		{[]byte{Integer, 1, 0, 1, 1, 0, 0, 0, 1}, IntegerTag(1, 1)},
		{[]byte{Integer, 3, 0, 'a', 'b', 'c'}, nil},
		{[]byte{Integer, 3, 0, 0, 0, 0, 0}, nil},
		{[]byte{Integer, 3, 0, 'a', 0, 0, 0, 0}, nil},
		{[]byte{Integer, 3, 0, 'a', 'b', 0, 0, 0, 0}, nil},
		{[]byte{Integer, 3, 0, 'a', 'b', 'c', 0, 0, 0, 0}, IntegerTag("abc", 0)},
		{[]byte{Integer, 3, 0, 'a', 'b', 'c', 1, 0, 0, 0}, IntegerTag("abc", 1)},
		{[]byte{Integer, 3, 0, 'a', 'b', 'c', 1, 0, 0, 0, 1}, IntegerTag("abc", 1)},

		{[]byte{Float}, nil},
		{[]byte{Float, 0}, nil},
		{[]byte{Float, 0, 0}, nil},
		{[]byte{Float, 0, 0, 0}, nil},
		{[]byte{Float, 2, 0, 0}, nil},
		{[]byte{Float, 1, 0, 1}, nil},
		{[]byte{Float, 0, 0, 0, 0}, nil},
		{[]byte{Float, 0, 0, 0, 0, 0}, nil},
		{[]byte{Float, 0, 0, 0, 0, 0, 0}, FloatTag("", 0)},
		{[]byte{Float, 0, 0, 0, 0, 0, 0, 0}, FloatTag("", 0)},
		{[]byte{Float, 1, 0, 1, 0}, nil},
		{[]byte{Float, 1, 0, 0, 0, 0, 0}, nil},
		{[]byte{Float, 1, 0, 1, 0, 0, 0, 0}, FloatTag(1, 0)},
		{[]byte{Float, 1, 0, 1, 0, 0, 0, 0, 0}, FloatTag(1, 0)},
		{[]byte{Float, 1, 0, 'a', 0, 0, 0, 0}, FloatTag(int('a'), 0)},
		{[]byte{Float, 0, 0, 0, 0, 0x80, 0x3F}, FloatTag("", 1)},
		{[]byte{Float, 0, 0, 0, 0, 0x80, 0x3F, 0}, FloatTag("", 1)},
		{[]byte{Float, 1, 0, 1, 0, 0, 0x80, 0x3F}, FloatTag(1, 1)},
		{[]byte{Float, 1, 0, 'a', 0, 0, 0x80, 0x3F}, FloatTag(int('a'), 1)},
		{[]byte{Float, 1, 0, 1, 0, 0, 0x80, 0x3F, 1}, FloatTag(1, 1)},
		{[]byte{Float, 3, 0, 'a', 'b', 'c'}, nil},
		{[]byte{Float, 3, 0, 0, 0, 0, 0}, nil},
		{[]byte{Float, 3, 0, 'a', 0, 0, 0, 0}, nil},
		{[]byte{Float, 3, 0, 'a', 'b', 0, 0, 0, 0}, nil},
		{[]byte{Float, 3, 0, 'a', 'b', 'c', 0, 0, 0, 0}, FloatTag("abc", 0)},
		{[]byte{Float, 3, 0, 'a', 'b', 'c', 0, 0, 0x80, 0x3F}, FloatTag("abc", 1)},
		{[]byte{Float, 3, 0, 'a', 'b', 'c', 0, 0, 0x80, 0x3F, 1}, FloatTag("abc", 1)},

		{[]byte{String}, nil},
		{[]byte{String, 0}, nil},
		{[]byte{String, 0, 0}, nil},
		{[]byte{String, 0, 0, 0}, nil},
		{[]byte{String, 2, 0, 0}, nil},
		{[]byte{String, 1, 0, 1}, nil},
		{[]byte{String, 0, 0, 0, 0}, StringTag("", "")},
		{[]byte{String, 0, 0, 0, 0, 0}, StringTag("", "")},
		{[]byte{String, 0, 0, 0, 0, 0, 0}, StringTag("", "")},
		{[]byte{String, 0, 0, 0, 0, 0, 0, 0}, StringTag("", "")},
		{[]byte{String, 1, 0, 0, 0}, nil},
		{[]byte{String, 1, 0, 0, 0, 0}, StringTag(0, "")},
		{[]byte{String, 1, 0, 0, 0, 0, 0}, StringTag(0, "")},
		{[]byte{String, 1, 0, 1, 0}, nil},
		{[]byte{String, 1, 0, 1, 0, 0}, StringTag(1, "")},
		{[]byte{String, 1, 0, 1, 0, 0, 0, 0}, StringTag(1, "")},
		{[]byte{String, 1, 0, 1, 0, 0, 0, 0, 0}, StringTag(1, "")},
		{[]byte{String, 1, 0, 'a', 0, 0}, StringTag(int('a'), "")},
		{[]byte{String, 1, 0, 'a', 0, 0, 0}, StringTag(int('a'), "")},
		{[]byte{String, 0, 0, 1, 0}, nil},
		{[]byte{String, 0, 0, 1, 0, 0}, StringTag("", string(0))},
		{[]byte{String, 0, 0, 1, 0, 'a'}, StringTag("", "a")},
		{[]byte{String, 0, 0, 2, 0}, nil},
		{[]byte{String, 0, 0, 2, 0, 'a'}, nil},
		{[]byte{String, 0, 0, 1, 0, 'a', 0, 0}, StringTag("", "a")},
		{[]byte{String, 1, 0, 1, 1, 0}, nil},
		{[]byte{String, 1, 0, 1, 1, 0, 0}, StringTag(1, string(0))},
		{[]byte{String, 1, 0, 'a', 1, 0, 'a', 'b'}, StringTag(int('a'), "a")},
		{[]byte{String, 3, 0, 0, 0, 0}, nil},
		{[]byte{String, 3, 0, 'a', 'b', 'c'}, nil},
		{[]byte{String, 3, 0, 'a', 'b', 'c', 0, 0}, StringTag("abc", "")},
		{[]byte{String, 3, 0, 'a', 'b', 'c', 1, 0}, nil},
		{[]byte{String, 3, 0, 'a', 'b', 'c', 1, 0, 0}, StringTag("abc", string(0))},
		{[]byte{String, 3, 0, 'a', 'b', 'c', 1, 0, 0, 'a'}, StringTag("abc", string(0))},
		{[]byte{String, 3, 0, 'a', 'b', 'c', 3, 0, 'a', 'b'}, nil},
		{[]byte{String, 3, 0, 'a', 'b', 'c', 3, 0, 'a', 'b', 'c'}, StringTag("abc", "abc")},
		{[]byte{String, 3, 0, 'a', 'b', 'c', 3, 0, 'a', 'b', 'c', 'd'}, StringTag("abc", "abc")},
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
		if tag == nil || tc.out == nil {
			if tag != tc.out {
				t.Fail()
			}
			continue
		}
		if tag.Type() != tc.out.Type() || tag.Name() != tc.out.Name() || tag.Value() != tc.out.Value() {
			t.Fail()
		}
	}
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
		{&tag{types: 1, name: 1, value: 1}, nil},
		{&tag{types: Integer, name: 1, value: 1}, nil},
		{&tag{types: Integer, name: 1, value: int32(0)}, []byte{Integer, 1, 0, 1, 0, 0, 0, 0}},
		{&tag{types: String, name: 0, value: 1}, nil},
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

func TestTagDecode(t *testing.T) {
	testCases := []struct {
		in  []byte
		out Tag
	}{
		{nil, &tag{}},
		{[]byte{}, &tag{}},
		{[]byte{0}, &tag{}},
		{[]byte{0, 0}, &tag{}},
		{[]byte{0, 0, 0}, &tag{}},
		{[]byte{0, 0, 0, 0}, &tag{name: ""}},
		{[]byte{0xFF, 0, 0, 0, 0}, &tag{types: 0xFF, name: ""}},
		{[]byte{Integer}, &tag{}},
		{[]byte{Integer, 0}, &tag{}},
		{[]byte{Integer, 0, 0}, &tag{}},
		{[]byte{Integer, 0, 0, 0}, &tag{types: Integer, name: ""}},
		{[]byte{Integer, 2, 0, 0}, &tag{types: Integer}},
		{[]byte{Integer, 1, 0, 1}, &tag{types: Integer, name: 1}},
		{[]byte{Float, 0, 0, 0}, &tag{types: Float, name: ""}},
		{[]byte{Float, 2, 0, 0}, &tag{types: Float}},
		{[]byte{Float, 1, 0, 1}, &tag{types: Float, name: 1}},
		{[]byte{String, 0, 0, 0}, &tag{types: String, name: ""}},
		{[]byte{String, 0, 0, 1, 0}, &tag{types: String, name: ""}},
		{[]byte{String, 0, 0, 0, 0}, &tag{types: String, name: "", value: ""}},
	}

	for _, tc := range testCases {
		tag := &tag{}
		if err := tag.Decode(tc.in); err != nil {
			t.Log(err)
		}
		if tag.Type() != tc.out.Type() || tag.Name() != tc.out.Name() || tag.Value() != tc.out.Value() {
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
		{IntegerTag(0, 0), []byte{Integer, 1, 0, 0, 0, 0, 0, 0}},
		{IntegerTag(1, 0), []byte{Integer, 1, 0, 1, 0, 0, 0, 0}},
		{IntegerTag(0, 1), []byte{Integer, 1, 0, 0, 1, 0, 0, 0}},
		{IntegerTag(1, 1), []byte{Integer, 1, 0, 1, 1, 0, 0, 0}},
		{IntegerTag(1, -1), []byte{Integer, 1, 0, 1, 0xFF, 0xFF, 0xFF, 0xFF}},
		{IntegerTag("", 0), []byte{Integer, 0, 0, 0, 0, 0, 0}},
		{IntegerTag("", 1), []byte{Integer, 0, 0, 1, 0, 0, 0}},
		{IntegerTag("abc", 0), []byte{Integer, 3, 0, 'a', 'b', 'c', 0, 0, 0, 0}},
		{IntegerTag("abc", 1), []byte{Integer, 3, 0, 'a', 'b', 'c', 1, 0, 0, 0}},
		{IntegerTag("abc", -1), []byte{Integer, 3, 0, 'a', 'b', 'c', 0xFF, 0xFF, 0xFF, 0xFF}},
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
		{[]byte{Integer, 1, 0, 0, 0, 0, 0, 0}, IntegerTag(0, 0)},
		{[]byte{Integer, 1, 0, 1, 0, 0, 0, 0}, IntegerTag(1, 0)},
		{[]byte{Integer, 1, 0, 0, 1, 0, 0, 0}, IntegerTag(0, 1)},
		{[]byte{Integer, 1, 0, 1, 1, 0, 0, 0}, IntegerTag(1, 1)},
		{[]byte{Integer, 1, 0, 1, 0xFF, 0xFF, 0xFF, 0xFF}, IntegerTag(1, -1)},
		{[]byte{Integer, 0, 0, 0, 0, 0, 0}, IntegerTag("", 0)},
		{[]byte{Integer, 0, 0, 1, 0, 0, 0}, IntegerTag("", 1)},
		{[]byte{Integer, 3, 0, 'a', 'b', 'c', 0, 0, 0, 0}, IntegerTag("abc", 0)},
		{[]byte{Integer, 3, 0, 'a', 'b', 'c', 1, 0, 0, 0}, IntegerTag("abc", 1)},
		{[]byte{Integer, 3, 0, 'a', 'b', 'c', 0xFF, 0xFF, 0xFF, 0xFF}, IntegerTag("abc", -1)},
	}

	for _, tc := range testCases {
		tag := &tag{}
		if err := tag.Decode(tc.in); err != nil {
			t.Log(err)
		}
		if tag.Type() != tc.out.Type() || tag.Name() != tc.out.Name() || tag.Value() != tc.out.Value() {
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
		{FloatTag(0, 0), []byte{Float, 1, 0, 0, 0, 0, 0, 0}},
		{FloatTag(1, 0), []byte{Float, 1, 0, 1, 0, 0, 0, 0}},
		{FloatTag(0, 1), []byte{Float, 1, 0, 0, 0, 0, 0x80, 0x3F}},
		{FloatTag(1, 1), []byte{Float, 1, 0, 1, 0, 0, 0x80, 0x3F}},
		{FloatTag(1, -1), []byte{Float, 1, 0, 1, 0, 0, 0x80, 0xBF}},
		{FloatTag("", 0), []byte{Float, 0, 0, 0, 0, 0, 0}},
		{FloatTag("", 1), []byte{Float, 0, 0, 0, 0, 0x80, 0x3F}},
		{FloatTag("abc", 0), []byte{Float, 3, 0, 'a', 'b', 'c', 0, 0, 0, 0}},
		{FloatTag("abc", 1), []byte{Float, 3, 0, 'a', 'b', 'c', 0, 0, 0x80, 0x3F}},
		{FloatTag("abc", -1), []byte{Float, 3, 0, 'a', 'b', 'c', 0, 0, 0x80, 0xBF}},
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
		{[]byte{Float, 1, 0, 0, 0, 0, 0, 0}, FloatTag(0, 0)},
		{[]byte{Float, 1, 0, 1, 0, 0, 0, 0}, FloatTag(1, 0)},
		{[]byte{Float, 1, 0, 0, 0, 0, 0x80, 0x3F}, FloatTag(0, 1)},
		{[]byte{Float, 1, 0, 1, 0, 0, 0x80, 0x3F}, FloatTag(1, 1)},
		{[]byte{Float, 1, 0, 1, 0, 0, 0x80, 0xBF}, FloatTag(1, -1)},
		{[]byte{Float, 0, 0, 0, 0, 0, 0}, FloatTag("", 0)},
		{[]byte{Float, 0, 0, 0, 0, 0x80, 0x3F}, FloatTag("", 1)},
		{[]byte{Float, 3, 0, 'a', 'b', 'c', 0, 0, 0, 0}, FloatTag("abc", 0)},
		{[]byte{Float, 3, 0, 'a', 'b', 'c', 0, 0, 0x80, 0x3F}, FloatTag("abc", 1)},
		{[]byte{Float, 3, 0, 'a', 'b', 'c', 0, 0, 0x80, 0xBF}, FloatTag("abc", -1)},
	}

	for _, tc := range testCases {
		tag := &tag{}
		if err := tag.Decode(tc.in); err != nil {
			t.Log(err)
		}
		if tag.Type() != tc.out.Type() || tag.Name() != tc.out.Name() || tag.Value() != tc.out.Value() {
			t.Fail()
		}
	}
}

func TestStringTagEncode(t *testing.T) {
	testCases := []struct {
		in  Tag
		out []byte
	}{
		{StringTag(int32(1), ""), nil},
		{StringTag(1.0, ""), nil},
		{StringTag(0, ""), []byte{String, 1, 0, 0, 0, 0}},
		{StringTag(1, ""), []byte{String, 1, 0, 1, 0, 0}},
		{StringTag(0, "abc"), []byte{String, 1, 0, 0, 3, 0, 'a', 'b', 'c'}},
		{StringTag(1, "abc"), []byte{String, 1, 0, 1, 3, 0, 'a', 'b', 'c'}},
		{StringTag("", ""), []byte{String, 0, 0, 0, 0}},
		{StringTag("", "abc"), []byte{String, 0, 0, 3, 0, 'a', 'b', 'c'}},
		{StringTag("abc", ""), []byte{String, 3, 0, 'a', 'b', 'c', 0, 0}},
		{StringTag("abc", "abc"), []byte{String, 3, 0, 'a', 'b', 'c', 3, 0, 'a', 'b', 'c'}},
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
		{[]byte{String, 1, 0, 0, 0, 0}, StringTag(0, "")},
		{[]byte{String, 1, 0, 1, 0, 0}, StringTag(1, "")},
		{[]byte{String, 1, 0, 0, 3, 0, 'a', 'b', 'c'}, StringTag(0, "abc")},
		{[]byte{String, 1, 0, 1, 3, 0, 'a', 'b', 'c'}, StringTag(1, "abc")},
		{[]byte{String, 0, 0, 0, 0}, StringTag("", "")},
		{[]byte{String, 0, 0, 3, 0, 'a', 'b', 'c'}, StringTag("", "abc")},
		{[]byte{String, 3, 0, 'a', 'b', 'c', 0, 0}, StringTag("abc", "")},
		{[]byte{String, 3, 0, 'a', 'b', 'c', 3, 0, 'a', 'b', 'c'}, StringTag("abc", "abc")},
	}

	for _, tc := range testCases {
		tag := &tag{}
		if err := tag.Decode(tc.in); err != nil {
			t.Log(err)
		}
		if tag.Type() != tc.out.Type() || tag.Name() != tc.out.Name() || tag.Value() != tc.out.Value() {
			t.Fail()
		}
	}
}