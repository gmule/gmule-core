package protocol

import (
	"bytes"
	"fmt"
	"io"

	"golang.org/x/crypto/md4"
)

const (
	// FileChunkSize is the size of file chunk
	FileChunkSize = 9728000
)

// FileHash is a 128 bit GUID hash calculated by the client and based on the file's contents.
type FileHash struct {
	Hash     []byte
	PartHash [][]byte
}

func (h FileHash) String() string {
	b := bytes.Buffer{}
	fmt.Fprintf(&b, "hash: %X\n", h.Hash)
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
