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
}

// encryptedShard represents a shard that has been encrypted
type encryptedShard struct {
	Value string `json:"value"`
	KeyID string `json:"key_id"`
}

// newShard returns a populated Shard struct
func newShard(value []byte) (*shard, error) {
	if len(value) == 0 {
		return nil, errors.New(errMsgEmptyValue)
	}
	return &shard{
		Value: value,
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
	return &encryptedShard{
		Value: armoured,
		KeyID: keys.GetFingerprint(k),
	}, nil
}

// Decrypt decrypts an EncryptedShard
func (es *encryptedShard) decrypt(k *rsa.PrivateKey) (*shard, error) {
	fp := keys.GetFingerprint(&k.PublicKey)
	if es.KeyID != fp {
		return nil, errors.New(errMsgIncorrectDecryptionKey)
	}
	val, err := decryptAndUnarmourShamirPart(es.Value, k)
	if err != nil {
		return nil, err
	}
	return &shard{Value: val}, nil
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
