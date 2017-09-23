package ed2k

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/crypto/md4"
)

const (
	// FileChunkSize is the size of file chunk.
	FileChunkSize = 9728000
)

// FileHash is a 128 bit GUID hash calculated by the client and based on the file's contents.
type FileHash struct {
	Size     int64
	Hash     []byte
	PartHash [][]byte
}

func (h FileHash) String() string {
	b := bytes.Buffer{}
	fmt.Fprintf(&b, "size: %d, hash: %X\n", h.Size, h.Hash)
	b.WriteString("part hash:\n")
	for i, hash := range h.PartHash {
		fmt.Fprintf(&b, "%d - %X\n", i, hash)
	}
	return b.String()
}

// Hash calculates the part hash and final hash.
func Hash(r io.Reader) (hash *FileHash, err error) {
	b := make([]byte, FileChunkSize)
	var size int64
	h := md4.New()

	var partHash [][]byte
	for {
		n, er := io.ReadFull(r, b)
		size += int64(n)
		if er != nil {
			if er == io.ErrUnexpectedEOF {
				if _, err = h.Write(b[:n]); err != nil {
					return
				}
				partHash = append(partHash, h.Sum(nil))
				break
			} else if er == io.EOF {
				break
			} else {
				err = er
				return
			}
		}
		if _, err = h.Write(b); err != nil {
			return
		}
		partHash = append(partHash, h.Sum(nil))
		h.Reset()
	}

	hash = &FileHash{
		Size:     size,
		PartHash: partHash,
	}
	if len(partHash) > 0 {
		hash.Hash = partHash[0]
	}
	if size > FileChunkSize {
		h.Reset()
		if _, err = h.Write(bytes.Join(partHash, nil)); err != nil {
			return
		}
		hash.Hash = h.Sum(nil)
	}

	return
}

// File is a single file entry.
type File struct {
	// The result of a hash performed on the file contents.
	// The hash is used to uniquely identify files, ignoring name differences between clients.
	Hash [16]byte
	// The client ID in case the client has high ID, or zero otherwise.
	ClientID uint32
	// The Client’s TCP port or zero in case the client has low ID.
	Port uint16
	// File tags: name, size, type, etc.
	Tags []Tag
}

// ReadFile reads structured binary data from r and parses the data to file.
func ReadFile(r io.Reader) (*File, error) {
	if r == nil {
		return nil, io.EOF
	}
	var b [26]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return nil, err
	}

	file := &File{}
	pos := copy(file.Hash[:], b[:16])
	file.ClientID = binary.LittleEndian.Uint32(b[pos : pos+4])
	pos += 4
	file.Port = binary.LittleEndian.Uint16(b[pos : pos+2])
	pos += 2
	tagCount := binary.LittleEndian.Uint32(b[pos : pos+4])
	if err := file.readTag(r, int(tagCount)); err != nil {
		return nil, err
	}
	return file, nil
}

// Encode encodes file struct to binary data.
func (f *File) Encode() (data []byte, err error) {
	buf := new(bytes.Buffer)
	if _, err = f.WriteTo(buf); err != nil {
		return
	}
	data = buf.Bytes()
	return
}

// Decode decodes the file from binary data.
func (f *File) Decode(data []byte) (err error) {
	if len(data) < 26 {
		return ErrShortBuffer
	}

	pos := 0
	copy(f.Hash[:], data[pos:pos+16])

	pos += 16
	f.ClientID = binary.LittleEndian.Uint32(data[pos : pos+4])
	pos += 4
	f.Port = binary.LittleEndian.Uint16(data[pos : pos+2])
	pos += 2
	count := binary.LittleEndian.Uint32(data[pos : pos+4])
	pos += 4
	err = f.readTag(bytes.NewReader(data[pos:]), int(count))
	return
}

func (f *File) readTag(r io.Reader, count int) error {
	for i := 0; i < count; i++ {
		tag, err := ReadTag(r)
		if err != nil {
			return err
		}
		f.Tags = append(f.Tags, tag)
	}
	return nil
}

// WriteTo writes file struct to w. The return value n is the number of bytes written.
func (f *File) WriteTo(w io.Writer) (n int64, err error) {
	nn, err := w.Write(f.Hash[:])
	n += int64(nn)
	if err != nil {
		return
	}
	if err = binary.Write(w, binary.LittleEndian, f.ClientID); err != nil {
		return
	}
	n += 4

	if err = binary.Write(w, binary.LittleEndian, f.Port); err != nil {
		return
	}
	n += 2

	// tag count
	if err = binary.Write(w, binary.LittleEndian, uint32(len(f.Tags))); err != nil {
		return
	}
	n += 4

	for _, tag := range f.Tags {
		nn, er := tag.WriteTo(w)
		n += nn
		if er != nil {
			err = er
			return
		}
	}

	return
}
