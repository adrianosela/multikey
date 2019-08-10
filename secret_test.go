package multikey

import (
	"crypto/rsa"
	"log"
	"testing"

	"github.com/adrianosela/multikey/keys"
	"github.com/stretchr/testify/assert"
)

func TestEncryptDecryptEncodeDecode(t *testing.T) {
	privs, pubs := []*rsa.PrivateKey{}, []*rsa.PublicKey{}
	for i := 0; i < 10; i++ {
		pri, pub, err := keys.GenerateRSAKeyPair(2048)
		if err != nil {
			assert.Fail(t, "could not generate test keys")
		}
		privs = append(privs, pri)
		pubs = append(pubs, pub)
	}
	testSecret := []byte("test secret value")
	s, err := Encrypt("test secret name", testSecret, pubs, 1)
	if err != nil {
		assert.Fail(t, "could not encrypt test secret")
	}
	plain, err := s.Decrypt(privs)
	if err != nil {
		assert.Fail(t, "could not decrypt test secret")
	}
	pem, err := s.EncodePEM()
	if err != nil {
		log.Fatal(err)
	}
	sec, err := DecodePEM(pem)
	if err != nil {
		log.Fatal(err)
	}
	assert.EqualValues(t, sec.shards, s.shards)
	assert.Equal(t, plain, testSecret)
}
