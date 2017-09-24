package ed2k

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
				ProtoEDonkey, // protocol
				27, 0, 0, 0,  // size
				MessageLoginRequest,                            // type
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // user hash
				0, 0, 0, 0, // client ID
				0, 0, // port
				0, 0, 0, 0, // tag count
			},
		},
		{
			&LoginMessage{
				message: message{Header: Header{Protocol: ProtoEMule, Size: 1}},
			},
			[]byte{
				ProtoEMule,  // protocol
				27, 0, 0, 0, // size
				MessageLoginRequest,                            // type
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // user hash
				0, 0, 0, 0, // client ID
				0, 0, // port
				0, 0, 0, 0, // tag count
			},
		},
		{
			&LoginMessage{
				message: message{
					Header: Header{Protocol: ProtoEDonkey},
				},
				UID: uid,
			},
			[]byte{
				ProtoEDonkey, // protocol
				27, 0, 0, 0,  // size
				MessageLoginRequest, // type
				uid[0], uid[1], uid[2], uid[3], uid[4], uid[5], uid[6], uid[7],
				uid[8], uid[9], uid[10], uid[11], uid[12], uid[13], uid[14], uid[15], // user hash
				0, 0, 0, 0, // client ID
				0, 0, // port
				0, 0, 0, 0, // tag count
			},
		},
		{
			&LoginMessage{
				message: message{
					Header: Header{Protocol: ProtoEDonkey},
				},
				UID:      uid,
				ClientID: 0xFFFFFFFF,
			},
			[]byte{
				ProtoEDonkey, // protocol
				27, 0, 0, 0,  // size
				MessageLoginRequest, // type
				uid[0], uid[1], uid[2], uid[3], uid[4], uid[5], uid[6], uid[7],
				uid[8], uid[9], uid[10], uid[11], uid[12], uid[13], uid[14], uid[15], // user hash
				0xFF, 0xFF, 0xFF, 0xFF, // client ID
				0, 0, // port
				0, 0, 0, 0, // tag count
			},
		},
		{
			&LoginMessage{
				message: message{
					Header: Header{Protocol: ProtoEDonkey},
				},
				UID:      uid,
				ClientID: 0xFFFFFFFF,
				Port:     4662,
			},
			[]byte{
				ProtoEDonkey, // protocol
				27, 0, 0, 0,  // size
				MessageLoginRequest, // type
				uid[0], uid[1], uid[2], uid[3], uid[4], uid[5], uid[6], uid[7],
				uid[8], uid[9], uid[10], uid[11], uid[12], uid[13], uid[14], uid[15], // user hash
				0xFF, 0xFF, 0xFF, 0xFF, // client ID
				0x36, 0x12, // port
				0, 0, 0, 0, // tag count
			},
		},
		{
			&LoginMessage{
				message: message{
					Header: Header{Protocol: ProtoEDonkey},
				},
				UID:      uid,
				ClientID: 0xFFFFFFFF,
				Port:     4662,
				Tags: []Tag{
					StringTag(TagName, "gmule", false),
				},
			},
			[]byte{
				ProtoEDonkey, // protocol
				38, 0, 0, 0,  // size
				MessageLoginRequest, // type
				uid[0], uid[1], uid[2], uid[3], uid[4], uid[5], uid[6], uid[7],
				uid[8], uid[9], uid[10], uid[11], uid[12], uid[13], uid[14], uid[15], // user hash
				0xFF, 0xFF, 0xFF, 0xFF, // client ID
				0x36, 0x12, // port
				1, 0, 0, 0, // tag count
				TagString, 1, 0, TagName, 5, 0, 'g', 'm', 'u', 'l', 'e', // name tag
			},
		},
		{
			&LoginMessage{
				message: message{
					Header: Header{Protocol: ProtoEDonkey},
				},
				UID:      uid,
				ClientID: 0xFFFFFFFF,
				Port:     4662,
				Tags: []Tag{
					StringTag(TagName, "gmule", false),
					Uint32Tag(TagVersion, 0),
					Uint32Tag(TagPort, 4662),
					Uint32Tag(TagServerFlags, 0),
				},
			},
			[]byte{
				ProtoEDonkey, // protocol
				62, 0, 0, 0,  // size
				MessageLoginRequest, // type
				uid[0], uid[1], uid[2], uid[3], uid[4], uid[5], uid[6], uid[7],
				uid[8], uid[9], uid[10], uid[11], uid[12], uid[13], uid[14], uid[15], // user hash
				0xFF, 0xFF, 0xFF, 0xFF, // client ID
				0x36, 0x12, // port
				4, 0, 0, 0, // tag count
				TagString, 1, 0, TagName, 5, 0, 'g', 'm', 'u', 'l', 'e', // name tag
				TagInteger, 1, 0, TagVersion, 0, 0, 0, 0, // version tag
				TagInteger, 1, 0, TagPort, 0x36, 0x12, 0, 0, // port tag
				TagInteger, 1, 0, TagServerFlags, 0, 0, 0, 0, // flags tag
			},
		},
		{
			&LoginMessage{
				message: message{
					Header: Header{Protocol: ProtoEDonkey},
				},
				UID:      uid,
				ClientID: 0xFFFFFFFF,
				Port:     4662,
				Tags: []Tag{
					StringTag(TagName, "gmule", false),
					Uint32Tag(TagVersion, 1),
					Uint32Tag(TagPort, 4662),
					Uint32Tag(TagServerFlags, 0),
				},
			},
			[]byte{
				ProtoEDonkey, // protocol
				62, 0, 0, 0,  // size
				MessageLoginRequest, // type
				uid[0], uid[1], uid[2], uid[3], uid[4], uid[5], uid[6], uid[7],
				uid[8], uid[9], uid[10], uid[11], uid[12], uid[13], uid[14], uid[15], // user hash
				0xFF, 0xFF, 0xFF, 0xFF, // client ID
				0x36, 0x12, // port
				4, 0, 0, 0, // tag count
				TagString, 1, 0, TagName, 5, 0, 'g', 'm', 'u', 'l', 'e', // name tag
				TagInteger, 1, 0, TagVersion, 1, 0, 0, 0, // version tag
				TagInteger, 1, 0, TagPort, 0x36, 0x12, 0, 0, // port tag
				TagInteger, 1, 0, TagServerFlags, 0, 0, 0, 0, // flags tag
			},
		},
		{
			&LoginMessage{
				message: message{
					Header: Header{Protocol: ProtoEDonkey},
				},
				UID:      uid,
				ClientID: 0xFFFFFFFF,
				Port:     4662,
				Tags: []Tag{
					StringTag(TagName, "gmule", false),
					Uint32Tag(TagVersion, 1),
					Uint32Tag(TagPort, 4662),
					Uint32Tag(TagServerFlags, 0xFFFFFFFF),
				},
			},
			[]byte{
				ProtoEDonkey, // protocol
				62, 0, 0, 0,  // size
				MessageLoginRequest, // type
				uid[0], uid[1], uid[2], uid[3], uid[4], uid[5], uid[6], uid[7],
				uid[8], uid[9], uid[10], uid[11], uid[12], uid[13], uid[14], uid[15], // user hash
				0xFF, 0xFF, 0xFF, 0xFF, // client ID
				0x36, 0x12, // port
				4, 0, 0, 0, // tag count
				TagString, 1, 0, TagName, 5, 0, 'g', 'm', 'u', 'l', 'e', // name tag
				TagInteger, 1, 0, TagVersion, 1, 0, 0, 0, // version tag
				TagInteger, 1, 0, TagPort, 0x36, 0x12, 0, 0, // port tag
				TagInteger, 1, 0, TagServerFlags, 0xFF, 0xFF, 0xFF, 0xFF, // flags tag
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
				ProtoEDonkey, // protocol
				0, 0, 0, 0,   // size
			},
			&LoginMessage{},
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
			&LoginMessage{},
		},
		{
			[]byte{
				0,                      // protocol
				0xFF, 0xFF, 0xFF, 0xFF, // size
				0, // type
				0,
			},
			&LoginMessage{},
		},
		{
			[]byte{
				ProtoEDonkey, // protocol
				0, 0, 0, 0,   // size
				MessageLoginRequest,                            // type
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // user hash
			},
			&LoginMessage{},
		},
		{
			[]byte{
				ProtoEDonkey, // protocol
				1, 0, 0, 0,   // size
				MessageLoginRequest,                            // type
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // user hash
			},
			&LoginMessage{},
		},
		{
			[]byte{
				ProtoEDonkey, // protocol
				17, 0, 0, 0,  // size
				MessageLoginRequest, // type
				uid[0], uid[1], uid[2], uid[3], uid[4], uid[5], uid[6], uid[7],
				uid[8], uid[9], uid[10], uid[11], uid[12], uid[13], uid[14], uid[15], // user hash
			},
			&LoginMessage{},
		},
		{
			[]byte{
				ProtoEDonkey, // protocol
				21, 0, 0, 0,  // size
				MessageLoginRequest, // type
				uid[0], uid[1], uid[2], uid[3], uid[4], uid[5], uid[6], uid[7],
				uid[8], uid[9], uid[10], uid[11], uid[12], uid[13], uid[14], uid[15], // user hash
				0, 0, 0, 0, // client ID
			},
			&LoginMessage{},
		},
		{
			[]byte{
				ProtoEDonkey, // protocol
				23, 0, 0, 0,  // size
				MessageLoginRequest, // type
				uid[0], uid[1], uid[2], uid[3], uid[4], uid[5], uid[6], uid[7],
				uid[8], uid[9], uid[10], uid[11], uid[12], uid[13], uid[14], uid[15], // user hash
				0, 0, 0, 0, // client ID
				0, 0, // port
			},
			&LoginMessage{},
		},
		{
			[]byte{
				ProtoEDonkey, // protocol
				27, 0, 0, 0,  // size
				MessageLoginRequest, // type
				uid[0], uid[1], uid[2], uid[3], uid[4], uid[5], uid[6], uid[7],
				uid[8], uid[9], uid[10], uid[11], uid[12], uid[13], uid[14], uid[15], // user hash
				0, 0, 0, 0, // client ID
				0, 0, // port
				0, 0, 0, 0, // tag count
			},
			&LoginMessage{
				message: message{
					Header: Header{Protocol: ProtoEDonkey, Size: 27},
				},
				UID: uid,
			},
		},
		{
			[]byte{
				ProtoEDonkey, // protocol
				33, 0, 0, 0,  // size
				MessageLoginRequest,                            // type
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // user hash
				0, 0, 0, 0, // client ID
				0, 0, // port
				0, 0, 0, 0, // tag count
				TagString, 1, 0, TagName, 0, 0, // name tag
			},
			&LoginMessage{
				message: message{
					Header: Header{Protocol: ProtoEDonkey, Size: 33},
				},
			},
		},
		{
			[]byte{
				ProtoEDonkey, // protocol
				27, 0, 0, 0,  // size
				MessageLoginRequest,                            // type
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // user hash
				0, 0, 0, 0, // client ID
				0, 0, // port
				4, 0, 0, 0, // tag count
			},
			&LoginMessage{
				message: message{
					Header: Header{Protocol: ProtoEDonkey, Size: 27},
				},
			},
		},
		{
			[]byte{
				ProtoEDonkey, // protocol
				33, 0, 0, 0,  // size
				MessageLoginRequest,                            // type
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // user hash
				0, 0, 0, 0, // client ID
				0, 0, // port
				4, 0, 0, 0, // tag count
				TagString, 1, 0, TagName, 0, 0, // name tag
			},
			&LoginMessage{
				message: message{
					Header: Header{Protocol: ProtoEDonkey, Size: 33},
				},
			},
		},
		{
			[]byte{
				ProtoEDonkey, // protocol
				36, 0, 0, 0,  // size
				MessageLoginRequest,                            // type
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // user hash
				0, 0, 0, 0, // client ID
				0, 0, // port
				4, 0, 0, 0, // tag count
				TagString, 1, 0, TagName, 3, 0, 'a', 'b', 'c', // name tag
			},
			&LoginMessage{
				message: message{
					Header: Header{Protocol: ProtoEDonkey, Size: 36},
				},
				Tags: []Tag{
					StringTag(TagName, "abc", false),
				},
			},
		},
		{
			[]byte{
				ProtoEDonkey, // protocol
				44, 0, 0, 0,  // size
				MessageLoginRequest,                            // type
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // user hash
				0, 0, 0, 0, // client ID
				0, 0, // port
				4, 0, 0, 0, // tag count
				TagString, 1, 0, TagName, 3, 0, 'a', 'b', 'c', // name tag
				TagInteger, 1, 0, TagVersion, 1, 0, 0, 0, // version tag
			},
			&LoginMessage{
				message: message{
					Header: Header{Protocol: ProtoEDonkey, Size: 44},
				},
				Tags: []Tag{
					StringTag(TagName, "abc", false),
					Uint32Tag(TagVersion, 1),
				},
			},
		},
		{
			[]byte{
				ProtoEDonkey, // protocol
				52, 0, 0, 0,  // size
				MessageLoginRequest,                            // type
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // user hash
				0, 0, 0, 0, // client ID
				0, 0, // port
				4, 0, 0, 0, // tag count
				TagString, 1, 0, TagName, 3, 0, 'a', 'b', 'c', // name tag
				TagInteger, 1, 0, TagVersion, 1, 0, 0, 0, // version tag
				TagInteger, 1, 0, TagPort, 1, 0, 0, 0, // port tag
			},
			&LoginMessage{
				message: message{
					Header: Header{Protocol: ProtoEDonkey, Size: 52},
				},
				Tags: []Tag{
					StringTag(TagName, "abc", false),
					Uint32Tag(TagVersion, 1),
				},
			},
		},
		{
			[]byte{
				ProtoEDonkey, // protocol
				62, 0, 0, 0,  // size
				MessageLoginRequest,                            // type
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // user hash
				0, 0, 0, 0, // client ID
				0, 0, // port
				4, 0, 0, 0, // tag count
				TagString, 1, 0, TagName, 5, 0, 'g', 'm', 'u', 'l', 'e', // name tag
				TagInteger, 1, 0, TagVersion, 1, 0, 0, 0, // version tag
				TagInteger, 1, 0, TagPort, 1, 0, 0, 0, // port tag
				TagInteger, 1, 0, TagServerFlags, 1, 0, 0, 0, // flags tag
			},
			&LoginMessage{
				message: message{
					Header: Header{Protocol: ProtoEDonkey, Size: 62},
				},
				Tags: []Tag{
					StringTag(TagName, "abc", false),
					Uint32Tag(TagVersion, 1),
					Uint32Tag(TagServerFlags, 1),
				},
			},
		},
		{
			[]byte{
				ProtoEMule,  // protocol
				57, 0, 0, 0, // size
				MessageLoginRequest,                            // type
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // user hash
				0, 0, 0, 0, // client ID
				0, 0, // port
				4, 0, 0, 0, // tag count
				TagString, 1, 0, TagName, 0, 0, // name tag
				TagInteger, 1, 0, TagVersion, 0, 0, 0, 0, // version tag
				TagInteger, 1, 0, TagPort, 0, 0, 0, 0, // port tag
				TagInteger, 1, 0, TagServerFlags, 0, 0, 0, 0, // flags tag
			},
			&LoginMessage{
				message: message{
					Header: Header{Protocol: ProtoEMule, Size: 57},
				},
			},
		},
		{
			[]byte{
				ProtoEDonkey, // protocol
				57, 0, 0, 0,  // size
				MessageLoginRequest, // type
				uid[0], uid[1], uid[2], uid[3], uid[4], uid[5], uid[6], uid[7],
				uid[8], uid[9], uid[10], uid[11], uid[12], uid[13], uid[14], uid[15], // user hash
				0, 0, 0, 0, // client ID
				0, 0, // port
				4, 0, 0, 0, // tag count
				TagString, 1, 0, TagName, 0, 0, // name tag
				TagInteger, 1, 0, TagVersion, 0, 0, 0, 0, // version tag
				TagInteger, 1, 0, TagPort, 0, 0, 0, 0, // port tag
				TagInteger, 1, 0, TagServerFlags, 0, 0, 0, 0, // flags tag
			},
			&LoginMessage{
				message: message{
					Header: Header{Protocol: ProtoEDonkey, Size: 57},
				},
				UID: uid,
			},
		},
		{
			[]byte{
				ProtoEDonkey, // protocol
				57, 0, 0, 0,  // size
				MessageLoginRequest, // type
				uid[0], uid[1], uid[2], uid[3], uid[4], uid[5], uid[6], uid[7],
				uid[8], uid[9], uid[10], uid[11], uid[12], uid[13], uid[14], uid[15], // user hash
				0xFF, 0xFF, 0xFF, 0xFF, // client ID
				0, 0, // port
				4, 0, 0, 0, // tag count
				TagString, 1, 0, TagName, 0, 0, // name tag
				TagInteger, 1, 0, TagVersion, 0, 0, 0, 0, // version tag
				TagInteger, 1, 0, TagPort, 0, 0, 0, 0, // port tag
				TagInteger, 1, 0, TagServerFlags, 0, 0, 0, 0, // flags tag
			},
			&LoginMessage{
				message: message{
					Header: Header{Protocol: ProtoEDonkey, Size: 57},
				},
				UID:      uid,
				ClientID: 0xFFFFFFFF,
			},
		},
		{
			[]byte{
				ProtoEDonkey, // protocol
				57, 0, 0, 0,  // size
				MessageLoginRequest, // type
				uid[0], uid[1], uid[2], uid[3], uid[4], uid[5], uid[6], uid[7],
				uid[8], uid[9], uid[10], uid[11], uid[12], uid[13], uid[14], uid[15], // user hash
				0xFF, 0xFF, 0xFF, 0xFF, // client ID
				0x36, 0x12, // port
				4, 0, 0, 0, // tag count
				TagString, 1, 0, TagName, 0, 0, // name tag
				TagInteger, 1, 0, TagVersion, 0, 0, 0, 0, // version tag
				TagInteger, 1, 0, TagPort, 0x36, 0x12, 0, 0, // port tag
				TagInteger, 1, 0, TagServerFlags, 0, 0, 0, 0, // flags tag
			},
			&LoginMessage{
				message: message{
					Header: Header{Protocol: ProtoEDonkey, Size: 57},
				},
				UID:      uid,
				ClientID: 0xFFFFFFFF,
				Port:     4662,
			},
		},
		{
			[]byte{
				ProtoEDonkey, // protocol
				62, 0, 0, 0,  // size
				MessageLoginRequest, // type
				uid[0], uid[1], uid[2], uid[3], uid[4], uid[5], uid[6], uid[7],
				uid[8], uid[9], uid[10], uid[11], uid[12], uid[13], uid[14], uid[15], // user hash
				0xFF, 0xFF, 0xFF, 0xFF, // client ID
				0x36, 0x12, // port
				4, 0, 0, 0, // tag count
				TagString, 1, 0, TagName, 5, 0, 'g', 'm', 'u', 'l', 'e', // name tag
				TagInteger, 1, 0, TagVersion, 0, 0, 0, 0, // version tag
				TagInteger, 1, 0, TagPort, 0x36, 0x12, 0, 0, // port tag
				TagInteger, 1, 0, TagServerFlags, 0, 0, 0, 0, // flags tag
			},
			&LoginMessage{
				message: message{
					Header: Header{Protocol: ProtoEDonkey, Size: 62},
				},
				UID:      uid,
				ClientID: 0xFFFFFFFF,
				Port:     4662,
				Tags: []Tag{
					StringTag(TagName, "gmule", false),
					Uint32Tag(TagVersion, 0),
					Uint32Tag(TagPort, 4662),
					Uint32Tag(TagServerFlags, 0),
				},
			},
		},
		{
			[]byte{
				ProtoEDonkey, // protocol
				62, 0, 0, 0,  // size
				MessageLoginRequest, // type
				uid[0], uid[1], uid[2], uid[3], uid[4], uid[5], uid[6], uid[7],
				uid[8], uid[9], uid[10], uid[11], uid[12], uid[13], uid[14], uid[15], // user hash
				0xFF, 0xFF, 0xFF, 0xFF, // client ID
				0x36, 0x12, // port
				4, 0, 0, 0, // tag count
				TagString, 1, 0, TagName, 5, 0, 'g', 'm', 'u', 'l', 'e', // name tag
				TagInteger, 1, 0, TagVersion, 1, 0, 0, 0, // version tag
				TagInteger, 1, 0, TagPort, 0x36, 0x12, 0, 0, // port tag
				TagInteger, 1, 0, TagServerFlags, 0, 0, 0, 0, // flags tag
			},
			&LoginMessage{
				message: message{
					Header: Header{Protocol: ProtoEDonkey, Size: 62},
				},
				UID:      uid,
				ClientID: 0xFFFFFFFF,
				Port:     4662,
				Tags: []Tag{
					StringTag(TagName, "gmule", false),
					Uint32Tag(TagVersion, 1),
					Uint32Tag(TagPort, 4662),
					Uint32Tag(TagServerFlags, 0),
				},
			},
		},
		{
			[]byte{
				ProtoEDonkey, // protocol
				62, 0, 0, 0,  // size
				MessageLoginRequest, // type
				uid[0], uid[1], uid[2], uid[3], uid[4], uid[5], uid[6], uid[7],
				uid[8], uid[9], uid[10], uid[11], uid[12], uid[13], uid[14], uid[15], // user hash
				0xFF, 0xFF, 0xFF, 0xFF, // client ID
				0x36, 0x12, // port
				4, 0, 0, 0, // tag count
				TagString, 1, 0, TagName, 5, 0, 'g', 'm', 'u', 'l', 'e', // name tag
				TagInteger, 1, 0, TagVersion, 1, 0, 0, 0, // version tag
				TagInteger, 1, 0, TagPort, 0x36, 0x12, 0, 0, // port tag
				TagInteger, 1, 0, TagServerFlags, 0xFF, 0xFF, 0xFF, 0xFF, // flags tag
			},
			&LoginMessage{
				message: message{
					Header: Header{Protocol: ProtoEDonkey, Size: 62},
				},
				UID:      uid,
				ClientID: 0xFFFFFFFF,
				Port:     4662,
				Tags: []Tag{
					StringTag(TagName, "gmule", false),
					Uint32Tag(TagVersion, 1),
					Uint32Tag(TagPort, 4662),
					Uint32Tag(TagServerFlags, 0xFFFFFFFF),
				},
			},
		},
		{
			[]byte{
				ProtoEDonkey, // protocol
				70, 0, 0, 0,  // size
				MessageLoginRequest, // type
				uid[0], uid[1], uid[2], uid[3], uid[4], uid[5], uid[6], uid[7],
				uid[8], uid[9], uid[10], uid[11], uid[12], uid[13], uid[14], uid[15], // user hash
				0xFF, 0xFF, 0xFF, 0xFF, // client ID
				0x36, 0x12, // port
				5, 0, 0, 0, // tag count
				TagString, 1, 0, TagName, 5, 0, 'g', 'm', 'u', 'l', 'e', // name tag
				TagInteger, 1, 0, TagVersion, 1, 0, 0, 0, // version tag
				TagInteger, 1, 0, TagPort, 0x36, 0x12, 0, 0, // port tag
				TagInteger, 1, 0, TagServerFlags, 0xFF, 0xFF, 0xFF, 0xFF, // flags tag
				TagInteger, 1, 0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // flags tag
			},
			&LoginMessage{
				message: message{
					Header: Header{Protocol: ProtoEDonkey, Size: 70},
				},
				UID:      uid,
				ClientID: 0xFFFFFFFF,
				Port:     4662,
				Tags: []Tag{
					StringTag(TagName, "gmule", false),
					Uint32Tag(TagVersion, 1),
					Uint32Tag(TagPort, 4662),
					Uint32Tag(TagServerFlags, 0xFFFFFFFF),
					Uint32Tag(TagServerFlags, 0xFFFFFFFF),
				},
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
		if msg == nil || tc.out == nil ||
			msg.message != tc.out.message || msg.UID != tc.out.UID ||
			msg.ClientID != tc.out.ClientID || msg.Port != tc.out.Port {
			t.Fail()
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
				MessageServerMessage, // type
				0, 0,                 // size
			},
		},
		{
			&ServerMessage{
				Messages: "abc",
			},
			[]byte{
				0,          // protocol
				6, 0, 0, 0, // size
				MessageServerMessage, // type
				3, 0,                 // size
				'a', 'b', 'c', // messages
			},
		},
		{
			&ServerMessage{
				message: message{
					Header: Header{Protocol: ProtoEDonkey},
				},
			},
			[]byte{
				ProtoEDonkey, // protocol
				3, 0, 0, 0,   // size
				MessageServerMessage, // type
				0, 0,                 // size
			},
		},
		{
			&ServerMessage{
				message: message{
					Header: Header{Protocol: ProtoEDonkey},
				},
			},
			[]byte{
				ProtoEDonkey, // protocol
				3, 0, 0, 0,   // size
				MessageServerMessage, // type
				0, 0,                 // size
			},
		},
		{
			&ServerMessage{
				message: message{
					Header: Header{Protocol: ProtoEDonkey},
				},
				Messages: "abc\ndef\nghi",
			},
			[]byte{
				ProtoEDonkey, // protocol
				14, 0, 0, 0,  // size
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
				ProtoEDonkey, // protocol
				0, 0, 0, 0,   // size
			},
			&ServerMessage{},
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
			&ServerMessage{},
		},
		{
			[]byte{
				ProtoEDonkey, // protocol
				0, 0, 0, 0,   // size
				MessageServerMessage, // type
			},
			&ServerMessage{},
		},
		{
			[]byte{
				ProtoEDonkey, // protocol
				3, 0, 0, 0,   // size
				MessageServerMessage, // type
				0, 0,
			},
			&ServerMessage{
				message: message{
					Header: Header{Protocol: ProtoEDonkey, Size: 3},
				},
			},
		},
		{
			[]byte{
				ProtoEDonkey, // protocol
				6, 0, 0, 0,   // size
				MessageServerMessage, // type
				1, 0,
				'a', 'b', 'c',
			},
			&ServerMessage{
				message: message{
					Header: Header{Protocol: ProtoEDonkey, Size: 6},
				},
				Messages: "a",
			},
		},
		{
			[]byte{
				ProtoEDonkey, // protocol
				7, 0, 0, 0,   // size
				MessageServerMessage, // type
				3, 0,
				'a', 'b', 'c',
			},
			&ServerMessage{},
		},
		{
			[]byte{
				ProtoEDonkey, // protocol
				4, 0, 0, 0,   // size
				MessageServerMessage, // type
				3, 0,
				'a',
			},
			&ServerMessage{
				message: message{
					Header: Header{Protocol: ProtoEDonkey, Size: 4},
				},
			},
		},
		{
			[]byte{
				ProtoEDonkey, // protocol
				6, 0, 0, 0,   // size
				MessageServerMessage, // type
				3, 0,
				'a', 'b', 'c',
			},
			&ServerMessage{
				message: message{
					Header: Header{Protocol: ProtoEDonkey, Size: 6},
				},
				Messages: "abc",
			},
		},
		{
			[]byte{
				ProtoEDonkey, // protocol
				13, 0, 0, 0,  // size
				MessageServerMessage, // type
				10, 0,
				'a', 'b', 'c', '\r', '\n',
				'd', 'e', 'f', '\r', '\n',
			},
			&ServerMessage{
				message: message{
					Header: Header{Protocol: ProtoEDonkey, Size: 13},
				},
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
