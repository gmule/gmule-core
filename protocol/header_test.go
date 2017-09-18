package protocol

import (
	"bytes"
	"testing"
)

func TestHeaderEncode(t *testing.T) {
	testCases := []struct {
		in  Header
		out []byte
	}{
		{Header{}, []byte{0, 0, 0, 0, 0, 0}},
		{Header{Protocol: EDonkey}, []byte{EDonkey, 0, 0, 0, 0, 0}},
		{Header{Protocol: EDonkey, Size: 1}, []byte{EDonkey, 1, 0, 0, 0, 0}},
		{Header{Protocol: EDonkey, Size: 1, Type: 1}, []byte{EDonkey, 1, 0, 0, 0, 1}},
		{Header{Protocol: EMule, Size: 1, Type: 1}, []byte{EMule, 1, 0, 0, 0, 1}},
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

func TestHeaderDecode(t *testing.T) {
	testCases := []struct {
		in  []byte
		out Header
	}{
		{nil, Header{}},
		{[]byte{EDonkey, 0, 0, 0, 0}, Header{}},
		{[]byte{0, 0, 0, 0, 0, 0}, Header{}},
		{[]byte{EDonkey, 0, 0, 0, 0, 0}, Header{Protocol: EDonkey}},
		{[]byte{EDonkey, 1, 0, 0, 0, 0}, Header{Protocol: EDonkey, Size: 1}},
		{[]byte{EDonkey, 1, 0, 0, 0, 1}, Header{Protocol: EDonkey, Size: 1, Type: 1}},
		{[]byte{EMule, 1, 0, 0, 0, 1}, Header{Protocol: EMule, Size: 1, Type: 1}},
	}

	for _, tc := range testCases {
		h := Header{}
		if err := h.Decode(tc.in); err != nil {
			t.Log(err)
		}
		if h != tc.out {
			t.Fail()
		}
	}
}
