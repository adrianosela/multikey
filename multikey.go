package multikey

import (
	"crypto/rsa"
	"errors"
	"fmt"

	"github.com/adrianosela/multikey/keys"
	"github.com/adrianosela/multikey/shamir"
)

const (
	errMsgRequireTooBig = "require must be less than or equal to the amount of keys provided"
)

// Encrypt encrypts a secret with a given set of public keys.
// The secret will be decryptable with `require` of the given keys.
func Encrypt(data []byte, pubs []*rsa.PublicKey, require int) (string, error) {
	if require > len(pubs) {
		return "", fmt.Errorf(errMsgRequireTooBig)
	}
	secret := &secret{
		shards: []*encryptedShard{},
	}
	parts, err := shamir.Split(data, len(pubs), require)
	if err != nil {
		return "", fmt.Errorf("error splitting rule components: %s", err)
	}
	for i, part := range parts {
		s, err := newShard(part)
		if err != nil {
			return "", fmt.Errorf("error creating new shard object: %s", err)
		}
		enc, err := s.encrypt(pubs[i])
		if err != nil {
			return "", fmt.Errorf("error encrypting shard: %s", err)
		}
		secret.shards = append(secret.shards, enc)
	}
	return secret.encodePEM()
}

// Decrypt decrypts a secret with a provided set of keys.
func Decrypt(enc string, privs []*rsa.PrivateKey) ([]byte, error) {
	s, err := decodePEM(enc)
	if err != nil {
		return nil, errors.New(errMsgCouldNotDecode)
	}
	decryptedShBytes := [][]byte{}
	for _, sh := range s.shards {
		if k, ok := getKey(privs, sh.KeyID); ok {
			decrypted, err := sh.decrypt(k)
			if err != nil {
				continue // pass
			}
			decryptedShBytes = append(decryptedShBytes, decrypted.Value)
		}
	}
	return shamir.Combine(decryptedShBytes)
}

func getKey(privs []*rsa.PrivateKey, id string) (*rsa.PrivateKey, bool) {
	for _, p := range privs {
		fp := keys.GetFingerprint(&p.PublicKey)
		if fp == id {
			return p, true
		}
	}
	return nil, false
}
