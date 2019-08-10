package multikey

import (
	"crypto/rsa"
	"encoding/base64"
	"errors"

	"fmt"

	"github.com/adrianosela/multikey/keys"
)

const (
	errMsgEmptyValue             = "shard can not have empty value"
	errMsgCouldNotEncrypt        = "could not encrypt shard value"
	errMsgIncorrectDecryptionKey = "the provided key does not match the shard's encryption key's fingerprint"
	errMsgCouldNotDecode         = "could not b64 decode shard value"
	errMsgCouldNotDecrypt        = "could not decrypt shard value"
)

// shard describes a piece of secret that has been split
// with Shamir's Secret Sharing Algorithm
type shard struct {
	Value []byte

	// since Shamir's secret sharing algorithm requires threshold >= 2
	// to split a secret, whenever we want one-of-n keys to be enough to
	// decrypt a shard we need to share an additional piece of the secret
	// with all the keyholders
	HelperPiece []byte
}

// encryptedShard represents a shard that has been encrypted
type encryptedShard struct {
	Value string `json:"value"`
	KeyID string `json:"key_id"`

	Helper string `json:"h"`
}

// newShard returns a populated Shard struct
func newShard(value, helperPiece []byte) (*shard, error) {
	if len(value) == 0 {
		return nil, errors.New(errMsgEmptyValue)
	}
	return &shard{
		Value:       value,
		HelperPiece: helperPiece,
	}, nil
}

// encrypt encrypts and ASCII armours a shard's value
func (s *shard) encrypt(k *rsa.PublicKey) (*encryptedShard, error) {
	if len(s.Value) == 0 {
		return nil, errors.New(errMsgEmptyValue)
	}
	armoured, err := encryptAndArmourShamirPart(s.Value, k)
	if err != nil {
		return nil, err
	}
	sh := &encryptedShard{
		Value: armoured,
		KeyID: keys.GetFingerprint(k),
	}
	if s.HelperPiece != nil && len(s.HelperPiece) > 0 {
		// ignore the error, since the validity of the key has
		// been proven, and the helper piece is non nil
		sh.Helper, _ = encryptAndArmourShamirPart(s.HelperPiece, k)
	}
	return sh, nil
}

// Decrypt decrypts an EncryptedShard
func (es *encryptedShard) decrypt(k *rsa.PrivateKey) (*shard, error) {
	fp := keys.GetFingerprint(&k.PublicKey)
	if es.KeyID != fp {
		return nil, errors.New(errMsgIncorrectDecryptionKey)
	}
	sh := &shard{}
	var err error
	if sh.Value, err = decryptAndUnarmourShamirPart(es.Value, k); err != nil {
		return nil, err
	}
	// ignore err - validity of the key has been proven already
	sh.HelperPiece, _ = decryptAndUnarmourShamirPart(es.Helper, k)
	return sh, nil
}

// decryptAndUnarmourShamirPart -
func decryptAndUnarmourShamirPart(data string, k *rsa.PrivateKey) ([]byte, error) {
	// remove ASCII armour from piece
	raw, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %s", errMsgCouldNotDecode, err)
	}
	// decrypt the raw encrypted message
	dec, err := keys.DecryptMessage(raw, k)
	if err != nil {
		return nil, fmt.Errorf("%s: %s", errMsgCouldNotDecrypt, err)
	}
	return dec, nil
}

// encryptAndArmourShamirPart -
func encryptAndArmourShamirPart(data []byte, k *rsa.PublicKey) (string, error) {
	// encrypt shard value
	enc, err := keys.EncryptMessage(data, k)
	if err != nil {
		return "", fmt.Errorf("%s: %s", errMsgCouldNotEncrypt, err)
	}
	// ASCII armour the encrypted shard
	return base64.StdEncoding.EncodeToString(enc), nil
}
