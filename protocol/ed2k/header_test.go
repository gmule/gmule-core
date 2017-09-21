package ed2k

import (
	"bytes"
	"testing"
)

func TestHeaderEncode(t *testing.T) {
	testCases := []struct {
		in  Header
		out []byte
	}{
		{Header{}, []byte{0, 0, 0, 0, 0}},
		{Header{Protocol: ProtoEDonkey}, []byte{ProtoEDonkey, 0, 0, 0, 0}},
		{Header{Protocol: ProtoEDonkey, Size: 1}, []byte{ProtoEDonkey, 1, 0, 0, 0}},
		{Header{Protocol: ProtoEDonkey, Size: 1}, []byte{ProtoEDonkey, 1, 0, 0, 0}},
		{Header{Protocol: ProtoEMule, Size: 1}, []byte{ProtoEMule, 1, 0, 0, 0}},
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
		{[]byte{ProtoEDonkey, 0, 0, 0, 0}, Header{Protocol: ProtoEDonkey}},
		{[]byte{0, 0, 0, 0, 0}, Header{}},
		{[]byte{ProtoEDonkey, 0, 0, 0, 0}, Header{Protocol: ProtoEDonkey}},
		{[]byte{ProtoEDonkey, 1, 0, 0, 0}, Header{Protocol: ProtoEDonkey, Size: 1}},
		{[]byte{ProtoEDonkey, 1, 0, 0, 0}, Header{Protocol: ProtoEDonkey, Size: 1}},
		{[]byte{ProtoEMule, 1, 0, 0, 0}, Header{Protocol: ProtoEMule, Size: 1}},
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
