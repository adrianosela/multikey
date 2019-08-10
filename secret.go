package multikey

import (
	"crypto/rsa"
	"fmt"

	"github.com/adrianosela/multikey/keys"
	"github.com/adrianosela/multikey/shamir"
)

// Secret represents an encrypted secret
type Secret struct {
	shards []*encryptedShard
}

const (
	errMsgThresholdTooBig = "threshold must be less than or equal to the amount of keys provided"
)

// Encrypt encrypts a secret with a set of public keys.
// you need at least `threshold` keys to decrypt the resultant secret
func Encrypt(name string, data []byte, pubs []*rsa.PublicKey, threshold int) (*Secret, error) {
	if threshold > len(pubs) {
		return nil, fmt.Errorf(errMsgThresholdTooBig)
	}
	secret := &Secret{
		shards: []*encryptedShard{},
	}
	if threshold == 1 {
		// to handle the shamir secret sharding algorithm limitation on not
		// being able to split with a threshold of 1, we will create an
		// additional piece, and append it as the helper to every shard in the rule
		adjustedParts := len(pubs)
		if adjustedParts < 2 {
			adjustedParts = 2
		}
		adjustedThreshold := 2

		parts, err := shamir.Split(data, adjustedParts, adjustedThreshold)
		if err != nil {
			return nil, fmt.Errorf("error splitting rule components: %s", err)
		}
		h := parts[0]

		for i, part := range parts[1:] {
			s, err := newShard(name, part, h)
			if err != nil {
				return nil, fmt.Errorf("error creating new shard object: %s", err)
			}
			enc, err := s.encrypt(pubs[i])
			if err != nil {
				return nil, fmt.Errorf("error encrypting shard: %s", err)
			}
			secret.shards = append(secret.shards, enc)
		}
	} else {
		parts, err := shamir.Split(data, len(pubs), threshold)
		if err != nil {
			return nil, fmt.Errorf("error splitting rule components: %s", err)
		}
		for i, part := range parts {
			s, err := newShard(name, part, nil)
			if err != nil {
				return nil, fmt.Errorf("error creating new shard object: %s", err)
			}
			enc, err := s.encrypt(pubs[i])
			if err != nil {
				return nil, fmt.Errorf("error encrypting shard: %s", err)
			}
			secret.shards = append(secret.shards, enc)
		}
	}
	return secret, nil
}

// Decrypt decrypts a secret with a provided set of keys
func (s *Secret) Decrypt(privs []*rsa.PrivateKey) ([]byte, error) {
	decryptedShBytes := [][]byte{}
	for _, sh := range s.shards {
		if k, ok := getKey(privs, sh.KeyID); ok {
			decrypted, err := sh.decrypt(k)
			if err != nil {
				continue // pass
			}
			decryptedShBytes = append(decryptedShBytes, decrypted.Value)
			if decrypted.HelperPiece != nil {
				decryptedShBytes = append(decryptedShBytes, decrypted.HelperPiece)
				// if we get a helper piece it means we have a secret encrypted with
				// threshold = 1, we return right away
				break
			}
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
