package multikey

import (
	"crypto/rsa"
	"testing"

	"github.com/adrianosela/multikey/keys"
	"github.com/stretchr/testify/assert"
)

// We test the following statement:
// For a secret encrypted with n required keys {n:n ∈ ℕ}, n keys are
// necessary and sufficient to decrypt the secret
func TestEncryptDecrypt(t *testing.T) {
	n := 10
	testSecret := []byte("test secret value")
	privs, pubs := []*rsa.PrivateKey{}, []*rsa.PublicKey{}
	// generate n keys
	for k := 0; k < n; k++ {
		pri, pub, err := keys.GenerateRSAKeyPair(2048)
		if err != nil {
			assert.Fail(t, "could not generate test keys")
		}
		privs = append(privs, pri)
		pubs = append(pubs, pub)
	}
	// encrypt with 2 to n keys
	for e := 2; e <= n; e++ {
		s, err := Encrypt(testSecret, pubs, e)
		if err != nil {
			assert.Fail(t, "could not encrypt test secret")
		}
		// decrypt unsuccessfully with 1 to e keys
		for d := 2; d < e; d++ {
			plain, _ := Decrypt(s, privs[:d])
			assert.NotEqual(t, plain, testSecret)
		}
		// decrypt successfully with e to n keys
		for d := e; d <= n; d++ {
			plain, err := Decrypt(s, privs[:d])
			assert.Nil(t, err)
			assert.Equal(t, plain, testSecret)
		}
	}
}
