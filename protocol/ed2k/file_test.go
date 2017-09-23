package ed2k

import (
	"os"
	"testing"
)

func TestHash(t *testing.T) {
	f, err := os.Open("/home/gerry/Downloads/test_file")
	if err != nil {
		t.Log(err)
		return
	}
	hash, err := Hash(f)
	if err != nil {
		t.Error(err)
		return
	}
	t.Log(hash)
}
