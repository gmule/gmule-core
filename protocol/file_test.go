package protocol

import (
	"os"
	"testing"
)

func TestHash(t *testing.T) {
	f, err := os.Open("/home/gerry/Downloads/amdgpu-pro-16.40-348864.tar.xz")
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
