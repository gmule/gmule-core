package protocol

import (
	"bytes"
	"testing"
)

func TestLoginMessageEncode(t *testing.T) {
	uid := NewUID()

	testCases := []struct {
		in  *LoginMessage
		out []byte
	}{
		{
			nil, nil,
		},
		{
			&LoginMessage{},
			[]byte{
				0,           // protocol
				57, 0, 0, 0, // size
				0,                                              // type
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // user hash
				0, 0, 0, 0, // client ID
				0, 0, // port
				4, 0, 0, 0, // tag count
				String, 1, 0, TagNickname, 0, 0, // name tag
				Integer, 1, 0, TagVersion, 0, 0, 0, 0, // version tag
				Integer, 1, 0, TagPort, 0, 0, 0, 0, // port tag
				Integer, 1, 0, TagFlags, 0, 0, 0, 0, // flags tag
			},
		},
		{
			&LoginMessage{Header: Header{}},
			[]byte{
				0,           // protocol
				57, 0, 0, 0, // size
				0,                                              // type
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // user hash
				0, 0, 0, 0, // client ID
				0, 0, // port
				4, 0, 0, 0, // tag count
				String, 1, 0, TagNickname, 0, 0, // name tag
				Integer, 1, 0, TagVersion, 0, 0, 0, 0, // version tag
				Integer, 1, 0, TagPort, 0, 0, 0, 0, // port tag
				Integer, 1, 0, TagFlags, 0, 0, 0, 0, // flags tag
			},
		},
		{
			&LoginMessage{Header: Header{Protocol: EMule, Size: 1, Type: MessageLoginRequest}},
			[]byte{
				EMule,       // protocol
				57, 0, 0, 0, // size
				MessageLoginRequest,                            // type
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // user hash
				0, 0, 0, 0, // client ID
				0, 0, // port
				4, 0, 0, 0, // tag count
				String, 1, 0, TagNickname, 0, 0, // name tag
				Integer, 1, 0, TagVersion, 0, 0, 0, 0, // version tag
				Integer, 1, 0, TagPort, 0, 0, 0, 0, // port tag
				Integer, 1, 0, TagFlags, 0, 0, 0, 0, // flags tag
			},
		},
		{
			&LoginMessage{
				Header: Header{Protocol: EDonkey, Type: MessageLoginRequest},
				UID:    uid,
			},
			[]byte{
				EDonkey,     // protocol
				57, 0, 0, 0, // size
				MessageLoginRequest, // type
				uid[0], uid[1], uid[2], uid[3], uid[4], uid[5], uid[6], uid[7],
				uid[8], uid[9], uid[10], uid[11], uid[12], uid[13], uid[14], uid[15], // user hash
				0, 0, 0, 0, // client ID
				0, 0, // port
				4, 0, 0, 0, // tag count
				String, 1, 0, TagNickname, 0, 0, // name tag
				Integer, 1, 0, TagVersion, 0, 0, 0, 0, // version tag
				Integer, 1, 0, TagPort, 0, 0, 0, 0, // port tag
				Integer, 1, 0, TagFlags, 0, 0, 0, 0, // flags tag
			},
		},
		{
			&LoginMessage{
				Header:   Header{Protocol: EDonkey, Type: MessageLoginRequest},
				UID:      uid,
				ClientID: 0xFFFFFFFF,
			},
			[]byte{
				EDonkey,     // protocol
				57, 0, 0, 0, // size
				MessageLoginRequest, // type
				uid[0], uid[1], uid[2], uid[3], uid[4], uid[5], uid[6], uid[7],
				uid[8], uid[9], uid[10], uid[11], uid[12], uid[13], uid[14], uid[15], // user hash
				0xFF, 0xFF, 0xFF, 0xFF, // client ID
				0, 0, // port
				4, 0, 0, 0, // tag count
				String, 1, 0, TagNickname, 0, 0, // name tag
				Integer, 1, 0, TagVersion, 0, 0, 0, 0, // version tag
				Integer, 1, 0, TagPort, 0, 0, 0, 0, // port tag
				Integer, 1, 0, TagFlags, 0, 0, 0, 0, // flags tag
			},
		},
		{
			&LoginMessage{
				Header:   Header{Protocol: EDonkey, Type: MessageLoginRequest},
				UID:      uid,
				ClientID: 0xFFFFFFFF,
				Port:     4662,
			},
			[]byte{
				EDonkey,     // protocol
				57, 0, 0, 0, // size
				MessageLoginRequest, // type
				uid[0], uid[1], uid[2], uid[3], uid[4], uid[5], uid[6], uid[7],
				uid[8], uid[9], uid[10], uid[11], uid[12], uid[13], uid[14], uid[15], // user hash
				0xFF, 0xFF, 0xFF, 0xFF, // client ID
				0x36, 0x12, // port
				4, 0, 0, 0, // tag count
				String, 1, 0, TagNickname, 0, 0, // name tag
				Integer, 1, 0, TagVersion, 0, 0, 0, 0, // version tag
				Integer, 1, 0, TagPort, 0x36, 0x12, 0, 0, // port tag
				Integer, 1, 0, TagFlags, 0, 0, 0, 0, // flags tag
			},
		},
		{
			&LoginMessage{
				Header:   Header{Protocol: EDonkey, Type: MessageLoginRequest},
				UID:      uid,
				ClientID: 0xFFFFFFFF,
				Port:     4662,
				Name:     "gmule",
			},
			[]byte{
				EDonkey,     // protocol
				62, 0, 0, 0, // size
				MessageLoginRequest, // type
				uid[0], uid[1], uid[2], uid[3], uid[4], uid[5], uid[6], uid[7],
				uid[8], uid[9], uid[10], uid[11], uid[12], uid[13], uid[14], uid[15], // user hash
				0xFF, 0xFF, 0xFF, 0xFF, // client ID
				0x36, 0x12, // port
				4, 0, 0, 0, // tag count
				String, 1, 0, TagNickname, 5, 0, 'g', 'm', 'u', 'l', 'e', // name tag
				Integer, 1, 0, TagVersion, 0, 0, 0, 0, // version tag
				Integer, 1, 0, TagPort, 0x36, 0x12, 0, 0, // port tag
				Integer, 1, 0, TagFlags, 0, 0, 0, 0, // flags tag
			},
		},
		{
			&LoginMessage{
				Header:   Header{Protocol: EDonkey, Type: MessageLoginRequest},
				UID:      uid,
				ClientID: 0xFFFFFFFF,
				Port:     4662,
				Name:     "gmule",
				Version:  1,
			},
			[]byte{
				EDonkey,     // protocol
				62, 0, 0, 0, // size
				MessageLoginRequest, // type
				uid[0], uid[1], uid[2], uid[3], uid[4], uid[5], uid[6], uid[7],
				uid[8], uid[9], uid[10], uid[11], uid[12], uid[13], uid[14], uid[15], // user hash
				0xFF, 0xFF, 0xFF, 0xFF, // client ID
				0x36, 0x12, // port
				4, 0, 0, 0, // tag count
				String, 1, 0, TagNickname, 5, 0, 'g', 'm', 'u', 'l', 'e', // name tag
				Integer, 1, 0, TagVersion, 1, 0, 0, 0, // version tag
				Integer, 1, 0, TagPort, 0x36, 0x12, 0, 0, // port tag
				Integer, 1, 0, TagFlags, 0, 0, 0, 0, // flags tag
			},
		},
		{
			&LoginMessage{
				Header:   Header{Protocol: EDonkey, Type: MessageLoginRequest},
				UID:      uid,
				ClientID: 0xFFFFFFFF,
				Port:     4662,
				Name:     "gmule",
				Version:  1,
				Flags:    0xFFFFFFFF,
			},
			[]byte{
				EDonkey,     // protocol
				62, 0, 0, 0, // size
				MessageLoginRequest, // type
				uid[0], uid[1], uid[2], uid[3], uid[4], uid[5], uid[6], uid[7],
				uid[8], uid[9], uid[10], uid[11], uid[12], uid[13], uid[14], uid[15], // user hash
				0xFF, 0xFF, 0xFF, 0xFF, // client ID
				0x36, 0x12, // port
				4, 0, 0, 0, // tag count
				String, 1, 0, TagNickname, 5, 0, 'g', 'm', 'u', 'l', 'e', // name tag
				Integer, 1, 0, TagVersion, 1, 0, 0, 0, // version tag
				Integer, 1, 0, TagPort, 0x36, 0x12, 0, 0, // port tag
				Integer, 1, 0, TagFlags, 0xFF, 0xFF, 0xFF, 0xFF, // flags tag
			},
		},
	}

	for i, tc := range testCases {
		b, err := tc.in.Encode()
		if err != nil {
			t.Log(i, err)
		}
		t.Logf("%# x", b)
		if !bytes.Equal(b, tc.out) {
			t.Fail()
			t.Log(i, "failed")
		}
	}
}

func TestLoginMessageDecode(t *testing.T) {
	uid := NewUID()

	testCases := []struct {
		in  []byte
		out *LoginMessage
	}{
		{
			nil, &LoginMessage{},
		},
		{
			[]byte{}, &LoginMessage{},
		},
		{
			[]byte{
				0,          // protocol
				0, 0, 0, 0, // size
				0, // type
			},
			&LoginMessage{},
		},
		{
			[]byte{
				0,          // protocol
				1, 0, 0, 0, // size
				0, // type
			},
			&LoginMessage{Header: Header{Size: 1}},
		},
		{
			[]byte{
				0,                      // protocol
				0xFF, 0xFF, 0xFF, 0xFF, // size
				0, // type
				0,
			}, &LoginMessage{Header: Header{Size: 0xFFFFFFFF}},
		},
		{
			[]byte{
				EDonkey,    // protocol
				1, 0, 0, 0, // size
				MessageLoginRequest,                            // type
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // user hash
			},
			&LoginMessage{
				Header: Header{Protocol: EDonkey, Size: 1, Type: MessageLoginRequest},
			},
		},
		{
			[]byte{
				EDonkey,     // protocol
				17, 0, 0, 0, // size
				MessageLoginRequest, // type
				uid[0], uid[1], uid[2], uid[3], uid[4], uid[5], uid[6], uid[7],
				uid[8], uid[9], uid[10], uid[11], uid[12], uid[13], uid[14], uid[15], // user hash
			},
			&LoginMessage{
				Header: Header{Protocol: EDonkey, Size: 17, Type: MessageLoginRequest},
			},
		},
		{
			[]byte{
				EDonkey,     // protocol
				21, 0, 0, 0, // size
				MessageLoginRequest, // type
				uid[0], uid[1], uid[2], uid[3], uid[4], uid[5], uid[6], uid[7],
				uid[8], uid[9], uid[10], uid[11], uid[12], uid[13], uid[14], uid[15], // user hash
				0, 0, 0, 0, // client ID
			},
			&LoginMessage{
				Header: Header{Protocol: EDonkey, Size: 21, Type: MessageLoginRequest},
			},
		},
		{
			[]byte{
				EDonkey,     // protocol
				23, 0, 0, 0, // size
				MessageLoginRequest, // type
				uid[0], uid[1], uid[2], uid[3], uid[4], uid[5], uid[6], uid[7],
				uid[8], uid[9], uid[10], uid[11], uid[12], uid[13], uid[14], uid[15], // user hash
				0, 0, 0, 0, // client ID
				0, 0, // port
			},
			&LoginMessage{
				Header: Header{Protocol: EDonkey, Size: 23, Type: MessageLoginRequest},
			},
		},
		{
			[]byte{
				EDonkey,     // protocol
				27, 0, 0, 0, // size
				MessageLoginRequest, // type
				uid[0], uid[1], uid[2], uid[3], uid[4], uid[5], uid[6], uid[7],
				uid[8], uid[9], uid[10], uid[11], uid[12], uid[13], uid[14], uid[15], // user hash
				0, 0, 0, 0, // client ID
				0, 0, // port
				0, 0, 0, 0, // tag count
			},
			&LoginMessage{
				Header: Header{Protocol: EDonkey, Size: 27, Type: MessageLoginRequest},
				UID:    uid,
			},
		},
		{
			[]byte{
				EDonkey,     // protocol
				33, 0, 0, 0, // size
				MessageLoginRequest,                            // type
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // user hash
				0, 0, 0, 0, // client ID
				0, 0, // port
				0, 0, 0, 0, // tag count
				String, 1, 0, TagNickname, 0, 0, // name tag
			},
			&LoginMessage{
				Header: Header{Protocol: EDonkey, Size: 33, Type: MessageLoginRequest},
			},
		},
		{
			[]byte{
				EDonkey,     // protocol
				27, 0, 0, 0, // size
				MessageLoginRequest,                            // type
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // user hash
				0, 0, 0, 0, // client ID
				0, 0, // port
				4, 0, 0, 0, // tag count
			},
			&LoginMessage{
				Header: Header{Protocol: EDonkey, Size: 27, Type: MessageLoginRequest},
			},
		},
		{
			[]byte{
				EDonkey,     // protocol
				33, 0, 0, 0, // size
				MessageLoginRequest,                            // type
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // user hash
				0, 0, 0, 0, // client ID
				0, 0, // port
				4, 0, 0, 0, // tag count
				String, 1, 0, TagNickname, 0, 0, // name tag
			},
			&LoginMessage{
				Header: Header{Protocol: EDonkey, Size: 33, Type: MessageLoginRequest},
			},
		},
		{
			[]byte{
				EDonkey,     // protocol
				36, 0, 0, 0, // size
				MessageLoginRequest,                            // type
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // user hash
				0, 0, 0, 0, // client ID
				0, 0, // port
				4, 0, 0, 0, // tag count
				String, 1, 0, TagNickname, 3, 0, 'a', 'b', 'c', // name tag
			},
			&LoginMessage{
				Header: Header{Protocol: EDonkey, Size: 36, Type: MessageLoginRequest},
				Name:   "abc",
			},
		},
		{
			[]byte{
				EDonkey,     // protocol
				44, 0, 0, 0, // size
				MessageLoginRequest,                            // type
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // user hash
				0, 0, 0, 0, // client ID
				0, 0, // port
				4, 0, 0, 0, // tag count
				String, 1, 0, TagNickname, 3, 0, 'a', 'b', 'c', // name tag
				Integer, 1, 0, TagVersion, 1, 0, 0, 0, // version tag
			},
			&LoginMessage{
				Header:  Header{Protocol: EDonkey, Size: 44, Type: MessageLoginRequest},
				Name:    "abc",
				Version: 1,
			},
		},
		{
			[]byte{
				EDonkey,     // protocol
				52, 0, 0, 0, // size
				MessageLoginRequest,                            // type
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // user hash
				0, 0, 0, 0, // client ID
				0, 0, // port
				4, 0, 0, 0, // tag count
				String, 1, 0, TagNickname, 3, 0, 'a', 'b', 'c', // name tag
				Integer, 1, 0, TagVersion, 1, 0, 0, 0, // version tag
				Integer, 1, 0, TagPort, 1, 0, 0, 0, // port tag
			},
			&LoginMessage{
				Header:  Header{Protocol: EDonkey, Size: 52, Type: MessageLoginRequest},
				Name:    "abc",
				Version: 1,
			},
		},
		{
			[]byte{
				EDonkey,     // protocol
				62, 0, 0, 0, // size
				MessageLoginRequest,                            // type
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // user hash
				0, 0, 0, 0, // client ID
				0, 0, // port
				4, 0, 0, 0, // tag count
				String, 1, 0, TagNickname, 5, 0, 'g', 'm', 'u', 'l', 'e', // name tag
				Integer, 1, 0, TagVersion, 1, 0, 0, 0, // version tag
				Integer, 1, 0, TagPort, 1, 0, 0, 0, // port tag
				Integer, 1, 0, TagFlags, 1, 0, 0, 0, // flags tag
			},
			&LoginMessage{
				Header:  Header{Protocol: EDonkey, Size: 62, Type: MessageLoginRequest},
				Name:    "gmule",
				Version: 1,
				Flags:   1,
			},
		},
		{
			[]byte{
				EMule,       // protocol
				57, 0, 0, 0, // size
				MessageLoginRequest,                            // type
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // user hash
				0, 0, 0, 0, // client ID
				0, 0, // port
				4, 0, 0, 0, // tag count
				String, 1, 0, TagNickname, 0, 0, // name tag
				Integer, 1, 0, TagVersion, 0, 0, 0, 0, // version tag
				Integer, 1, 0, TagPort, 0, 0, 0, 0, // port tag
				Integer, 1, 0, TagFlags, 0, 0, 0, 0, // flags tag
			},
			&LoginMessage{Header: Header{Protocol: EMule, Size: 57, Type: MessageLoginRequest}},
		},
		{
			[]byte{
				EDonkey,     // protocol
				57, 0, 0, 0, // size
				MessageLoginRequest, // type
				uid[0], uid[1], uid[2], uid[3], uid[4], uid[5], uid[6], uid[7],
				uid[8], uid[9], uid[10], uid[11], uid[12], uid[13], uid[14], uid[15], // user hash
				0, 0, 0, 0, // client ID
				0, 0, // port
				4, 0, 0, 0, // tag count
				String, 1, 0, TagNickname, 0, 0, // name tag
				Integer, 1, 0, TagVersion, 0, 0, 0, 0, // version tag
				Integer, 1, 0, TagPort, 0, 0, 0, 0, // port tag
				Integer, 1, 0, TagFlags, 0, 0, 0, 0, // flags tag
			},
			&LoginMessage{
				Header: Header{Protocol: EDonkey, Size: 57, Type: MessageLoginRequest},
				UID:    uid,
			},
		},
		{
			[]byte{
				EDonkey,     // protocol
				57, 0, 0, 0, // size
				MessageLoginRequest, // type
				uid[0], uid[1], uid[2], uid[3], uid[4], uid[5], uid[6], uid[7],
				uid[8], uid[9], uid[10], uid[11], uid[12], uid[13], uid[14], uid[15], // user hash
				0xFF, 0xFF, 0xFF, 0xFF, // client ID
				0, 0, // port
				4, 0, 0, 0, // tag count
				String, 1, 0, TagNickname, 0, 0, // name tag
				Integer, 1, 0, TagVersion, 0, 0, 0, 0, // version tag
				Integer, 1, 0, TagPort, 0, 0, 0, 0, // port tag
				Integer, 1, 0, TagFlags, 0, 0, 0, 0, // flags tag
			},
			&LoginMessage{
				Header:   Header{Protocol: EDonkey, Size: 57, Type: MessageLoginRequest},
				UID:      uid,
				ClientID: 0xFFFFFFFF,
			},
		},
		{
			[]byte{
				EDonkey,     // protocol
				57, 0, 0, 0, // size
				MessageLoginRequest, // type
				uid[0], uid[1], uid[2], uid[3], uid[4], uid[5], uid[6], uid[7],
				uid[8], uid[9], uid[10], uid[11], uid[12], uid[13], uid[14], uid[15], // user hash
				0xFF, 0xFF, 0xFF, 0xFF, // client ID
				0x36, 0x12, // port
				4, 0, 0, 0, // tag count
				String, 1, 0, TagNickname, 0, 0, // name tag
				Integer, 1, 0, TagVersion, 0, 0, 0, 0, // version tag
				Integer, 1, 0, TagPort, 0x36, 0x12, 0, 0, // port tag
				Integer, 1, 0, TagFlags, 0, 0, 0, 0, // flags tag
			},
			&LoginMessage{
				Header:   Header{Protocol: EDonkey, Size: 57, Type: MessageLoginRequest},
				UID:      uid,
				ClientID: 0xFFFFFFFF,
				Port:     4662,
			},
		},
		{
			[]byte{
				EDonkey,     // protocol
				62, 0, 0, 0, // size
				MessageLoginRequest, // type
				uid[0], uid[1], uid[2], uid[3], uid[4], uid[5], uid[6], uid[7],
				uid[8], uid[9], uid[10], uid[11], uid[12], uid[13], uid[14], uid[15], // user hash
				0xFF, 0xFF, 0xFF, 0xFF, // client ID
				0x36, 0x12, // port
				4, 0, 0, 0, // tag count
				String, 1, 0, TagNickname, 5, 0, 'g', 'm', 'u', 'l', 'e', // name tag
				Integer, 1, 0, TagVersion, 0, 0, 0, 0, // version tag
				Integer, 1, 0, TagPort, 0x36, 0x12, 0, 0, // port tag
				Integer, 1, 0, TagFlags, 0, 0, 0, 0, // flags tag
			},
			&LoginMessage{
				Header:   Header{Protocol: EDonkey, Size: 62, Type: MessageLoginRequest},
				UID:      uid,
				ClientID: 0xFFFFFFFF,
				Port:     4662,
				Name:     "gmule",
			},
		},
		{
			[]byte{
				EDonkey,     // protocol
				62, 0, 0, 0, // size
				MessageLoginRequest, // type
				uid[0], uid[1], uid[2], uid[3], uid[4], uid[5], uid[6], uid[7],
				uid[8], uid[9], uid[10], uid[11], uid[12], uid[13], uid[14], uid[15], // user hash
				0xFF, 0xFF, 0xFF, 0xFF, // client ID
				0x36, 0x12, // port
				4, 0, 0, 0, // tag count
				String, 1, 0, TagNickname, 5, 0, 'g', 'm', 'u', 'l', 'e', // name tag
				Integer, 1, 0, TagVersion, 1, 0, 0, 0, // version tag
				Integer, 1, 0, TagPort, 0x36, 0x12, 0, 0, // port tag
				Integer, 1, 0, TagFlags, 0, 0, 0, 0, // flags tag
			},
			&LoginMessage{
				Header:   Header{Protocol: EDonkey, Size: 62, Type: MessageLoginRequest},
				UID:      uid,
				ClientID: 0xFFFFFFFF,
				Port:     4662,
				Name:     "gmule",
				Version:  1,
			},
		},
		{
			[]byte{
				EDonkey,     // protocol
				62, 0, 0, 0, // size
				MessageLoginRequest, // type
				uid[0], uid[1], uid[2], uid[3], uid[4], uid[5], uid[6], uid[7],
				uid[8], uid[9], uid[10], uid[11], uid[12], uid[13], uid[14], uid[15], // user hash
				0xFF, 0xFF, 0xFF, 0xFF, // client ID
				0x36, 0x12, // port
				4, 0, 0, 0, // tag count
				String, 1, 0, TagNickname, 5, 0, 'g', 'm', 'u', 'l', 'e', // name tag
				Integer, 1, 0, TagVersion, 1, 0, 0, 0, // version tag
				Integer, 1, 0, TagPort, 0x36, 0x12, 0, 0, // port tag
				Integer, 1, 0, TagFlags, 0xFF, 0xFF, 0xFF, 0xFF, // flags tag
			},
			&LoginMessage{
				Header:   Header{Protocol: EDonkey, Size: 62, Type: MessageLoginRequest},
				UID:      uid,
				ClientID: 0xFFFFFFFF,
				Port:     4662,
				Name:     "gmule",
				Version:  1,
				Flags:    0xFFFFFFFF,
			},
		},
		{
			[]byte{
				EDonkey,     // protocol
				70, 0, 0, 0, // size
				MessageLoginRequest, // type
				uid[0], uid[1], uid[2], uid[3], uid[4], uid[5], uid[6], uid[7],
				uid[8], uid[9], uid[10], uid[11], uid[12], uid[13], uid[14], uid[15], // user hash
				0xFF, 0xFF, 0xFF, 0xFF, // client ID
				0x36, 0x12, // port
				5, 0, 0, 0, // tag count
				String, 1, 0, TagNickname, 5, 0, 'g', 'm', 'u', 'l', 'e', // name tag
				Integer, 1, 0, TagVersion, 1, 0, 0, 0, // version tag
				Integer, 1, 0, TagPort, 0x36, 0x12, 0, 0, // port tag
				Integer, 1, 0, TagFlags, 0xFF, 0xFF, 0xFF, 0xFF, // flags tag
				Integer, 1, 0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // flags tag
			},
			&LoginMessage{
				Header:   Header{Protocol: EDonkey, Size: 70, Type: MessageLoginRequest},
				UID:      uid,
				ClientID: 0xFFFFFFFF,
				Port:     4662,
				Name:     "gmule",
				Version:  1,
				Flags:    0xFFFFFFFF,
			},
		},
	}

	for i, tc := range testCases {
		msg := &LoginMessage{}
		err := msg.Decode(tc.in)
		if err != nil {
			t.Log(i, err)
		}
		if msg == tc.out {
			continue
		}
		if msg == nil || tc.out == nil || *msg != *tc.out {
			t.Fail()
			t.Log(i, "failed")
			t.Log(msg)
		}
	}
}

func TestServerMessageEncode(t *testing.T) {
	testCases := []struct {
		in  *ServerMessage
		out []byte
	}{
		{
			nil, nil,
		},
		{
			&ServerMessage{},
			[]byte{
				0,          // protocol
				3, 0, 0, 0, // size
				0,    // type
				0, 0, // size
			},
		},
		{
			&ServerMessage{
				Messages: "abc",
			},
			[]byte{
				0,          // protocol
				6, 0, 0, 0, // size
				0,    // type
				3, 0, // size
				'a', 'b', 'c', // messages
			},
		},
		{
			&ServerMessage{
				Header: Header{Protocol: EDonkey, Type: MessageServerMessage},
			},
			[]byte{
				EDonkey,    // protocol
				3, 0, 0, 0, // size
				MessageServerMessage, // type
				0, 0,                 // size
			},
		},
		{
			&ServerMessage{
				Header:   Header{Protocol: EDonkey, Type: MessageServerMessage},
				Messages: "abc\ndef\nghi",
			},
			[]byte{
				EDonkey,     // protocol
				14, 0, 0, 0, // size
				MessageServerMessage, // type
				11, 0,                // size
				'a', 'b', 'c', '\n', // messages
				'd', 'e', 'f', '\n',
				'g', 'h', 'i',
			},
		},
	}

	for i, tc := range testCases {
		b, err := tc.in.Encode()
		if err != nil {
			t.Log(i, err)
		}
		t.Logf("%# x", b)
		if !bytes.Equal(b, tc.out) {
			t.Fail()
			t.Log(i, "failed")
		}
	}
}

func TestServerMessageDecode(t *testing.T) {
	testCases := []struct {
		in  []byte
		out *ServerMessage
	}{
		{
			nil, &ServerMessage{},
		},
		{
			[]byte{}, &ServerMessage{},
		},
		{
			[]byte{
				0,          // protocol
				0, 0, 0, 0, // size
				0, // type
			},
			&ServerMessage{},
		},
		{
			[]byte{
				0,          // protocol
				1, 0, 0, 0, // size
				0, // type
			},
			&ServerMessage{Header: Header{Size: 1}},
		},
		{
			[]byte{
				EDonkey,    // protocol
				0, 0, 0, 0, // size
				MessageServerMessage, // type
			},
			&ServerMessage{
				Header: Header{Protocol: EDonkey, Size: 0, Type: MessageServerMessage},
			},
		},
		{
			[]byte{
				EDonkey,    // protocol
				3, 0, 0, 0, // size
				MessageServerMessage, // type
				0, 0,
			},
			&ServerMessage{
				Header: Header{Protocol: EDonkey, Size: 3, Type: MessageServerMessage},
			},
		},
		{
			[]byte{
				EDonkey,    // protocol
				6, 0, 0, 0, // size
				MessageServerMessage, // type
				1, 0,
				'a', 'b', 'c',
			},
			&ServerMessage{
				Header:   Header{Protocol: EDonkey, Size: 6, Type: MessageServerMessage},
				Messages: "a",
			},
		},
		{
			[]byte{
				EDonkey,    // protocol
				7, 0, 0, 0, // size
				MessageServerMessage, // type
				3, 0,
				'a', 'b', 'c',
			},
			&ServerMessage{
				Header: Header{Protocol: EDonkey, Size: 7, Type: MessageServerMessage},
			},
		},
		{
			[]byte{
				EDonkey,    // protocol
				4, 0, 0, 0, // size
				MessageServerMessage, // type
				3, 0,
				'a',
			},
			&ServerMessage{
				Header: Header{Protocol: EDonkey, Size: 4, Type: MessageServerMessage},
			},
		},
		{
			[]byte{
				EDonkey,    // protocol
				6, 0, 0, 0, // size
				MessageServerMessage, // type
				3, 0,
				'a', 'b', 'c',
			},
			&ServerMessage{
				Header:   Header{Protocol: EDonkey, Size: 6, Type: MessageServerMessage},
				Messages: "abc",
			},
		},
		{
			[]byte{
				EDonkey,     // protocol
				13, 0, 0, 0, // size
				MessageServerMessage, // type
				10, 0,
				'a', 'b', 'c', '\r', '\n',
				'd', 'e', 'f', '\r', '\n',
			},
			&ServerMessage{
				Header:   Header{Protocol: EDonkey, Size: 13, Type: MessageServerMessage},
				Messages: "abc\r\ndef\r\n",
			},
		},
	}

	for i, tc := range testCases {
		msg := &ServerMessage{}
		err := msg.Decode(tc.in)
		if err != nil {
			t.Log(i, err)
		}
		if msg == tc.out {
			continue
		}
		if msg == nil || tc.out == nil || *msg != *tc.out {
			t.Fail()
		}

	}
}
