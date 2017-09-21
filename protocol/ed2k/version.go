package ed2k

// EMule clients
const (
	ClientEMule         = 0
	ClientCDonkey       = 1
	ClientLXMule        = 2
	ClientAMule         = 3
	ClientShareaza      = 4
	ClientEMulePlus     = 5
	ClientHydraNode     = 6
	ClientMLDonkeyNew2  = 0x0a
	ClientLPhant        = 0x14
	ClientShareazaNew2  = 0x28
	ClientEDonkeyHybrid = 0x32
	ClientEDonkey       = 0x33
	ClientMLDonkey      = 0x34
	ClientEMuleOld      = 0x35
	ClientUnknown       = 0x36
	ClientShareazaNew   = 0x44
	ClientMLDonkeyNew   = 0x98
	ClientCompat        = 0xFF
)

// client version
const (
	MajorVersion  = 2
	MinorVersion  = 4
	UpdateVersion = 0
)

const (
	// EDonkeyVerion is only used to server login. It has no real "version" meaning anymore.
	EDonkeyVerion = 0x3C
	// EMuleVersion is eMule Version (14-Mar-2004: requested by lugdunummaster (need for LowID clients which have no chance
	// to send an Hello packet to the server during the callback test)).
	EMuleVersion = ClientAMule<<24 | MajorVersion<<17 | MinorVersion<<10 | UpdateVersion<<7
)
