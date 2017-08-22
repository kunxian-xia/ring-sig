package ringsig

import (
	"fmt"
	"crypto/sha256"
	"crypto/elliptic"
	"testing"
	"crypto/ecdsa"
	"crypto/rand"
)
//
func TestSig(t *testing.T) {
	N := 5
	keys := make([]*ecdsa.PrivateKey, N)
	pubs := make([]ecdsa.PublicKey, N)
	var err error

	for i:=0; i < N; i++ {
		keys[i], err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Errorf("error: %s", err)
			return
		}
		pubs[i] = keys[i].PublicKey
	}
	j := 2
	msg := []byte("hello")
	opts := &SignerOpts{h: sha256.New(), rand: rand.Reader}
	sig := Sign(pubs, j, keys[j], msg, opts)
	if sig == nil {
		t.Errorf("error: cannot generate valid signature for %d-th signer", j+1)
	}
	res, err := Verify(pubs, sig, msg, opts)
	if err != nil {
		t.Errorf("error: %s", err)
	}
	fmt.Println(res)
}