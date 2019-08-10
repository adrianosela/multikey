package multikey

import (
	"crypto/rsa"
	"testing"

	"github.com/adrianosela/multikey/keys"
	"github.com/stretchr/testify/assert"
)

func TestEncryptDecrypt(t *testing.T) {
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
	s, err := Encrypt(testSecret, pubs, 1)
	if err != nil {
		assert.Fail(t, "could not encrypt test secret")
	}
	plain, err := Decrypt(s, privs)
	if err != nil {
		assert.Fail(t, "could not decrypt test secret")
	}
	assert.Equal(t, plain, testSecret)
}
