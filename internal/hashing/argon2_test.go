package hashing

import (
	"strings"
	"testing"
)

func TestHashVerify(t *testing.T) {
	h := &Hasher{Pepper: []byte("0123456789abcdef0123456789abcdef"), Params: Default}
	phc, err := h.Hash("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(phc, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Fatalf("unexpected PHC %q", phc)
	}
	if ok, _, _ := h.Verify("correct horse battery", phc); !ok {
		t.Fatal("right password rejected")
	}
	if ok, _, _ := h.Verify("wrong horse battery", phc); ok {
		t.Fatal("wrong password accepted")
	}
	other := &Hasher{Pepper: []byte("ffffffffffffffffffffffffffffffff"), Params: Default}
	if ok, _, _ := other.Verify("correct horse battery", phc); ok {
		t.Fatal("hash verified without the right pepper")
	}
}

// BenchmarkHash measures one Argon2id hash at the production parameters;
// the design assumes about 15 ms per hash per core.
func BenchmarkHash(b *testing.B) {
	h := &Hasher{Pepper: make([]byte, 32), Params: Default}
	for b.Loop() {
		if _, err := h.Hash("benchmark password"); err != nil {
			b.Fatal(err)
		}
	}
}
