package keys

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"strings"

	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
)

// GenerateRSAKeyPair generates an RSA key-pair and returns it separately
func GenerateRSAKeyPair(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	return priv, &priv.PublicKey, nil
}

// GetFingerprint returns the fingerprint of a public key
func GetFingerprint(pub *rsa.PublicKey) string {
	md5sum := md5.Sum(x509.MarshalPKCS1PublicKey(pub))
	hexarray := make([]string, len(md5sum))
	for i, c := range md5sum {
		hexarray[i] = hex.EncodeToString([]byte{c})
	}
	return strings.Join(hexarray, ":")
}

// EncodePrivKeyPEM encodes an *rsa.PrivateKey onto a PEM block
func EncodePrivKeyPEM(priv *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})
}

// EncodePubKeyPEM encodes an *rsa.PublicKey onto a PEM block
func EncodePubKeyPEM(pub *rsa.PublicKey) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(pub),
	})
}

// DecodePrivKeyPEM decodes a PEM encoded public key to an *rsa.PublicKey
func DecodePrivKeyPEM(pk []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pk)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// DecodePubKeyPEM decodes a PEM encoded public key to an *rsa.PublicKey
func DecodePubKeyPEM(pk []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pk)
	if block == nil || block.Type != "RSA PUBLIC KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing public key")
	}
	return x509.ParsePKCS1PublicKey(block.Bytes)
}

// EncryptMessage encrypts a plaintext message with a public key
func EncryptMessage(plaintxt []byte, pub *rsa.PublicKey) ([]byte, error) {
	hash := sha512.New()
	cyphertxt, err := rsa.EncryptOAEP(hash, rand.Reader, pub, plaintxt, nil)
	if err != nil {
		return nil, err
	}
	return cyphertxt, nil
}

// DecryptMessage decrypts an encrypted message with a private key
func DecryptMessage(cyphertxt []byte, priv *rsa.PrivateKey) ([]byte, error) {
	hash := sha512.New()
	plaintxt, err := rsa.DecryptOAEP(hash, rand.Reader, priv, cyphertxt, nil)
	if err != nil {
		return nil, err
	}
	return plaintxt, nil
}

// EncryptMessageWithPEMKey encrypts a plaintext message with a PEM encoded public key
func EncryptMessageWithPEMKey(plaintxt []byte, pub []byte) ([]byte, error) {
	k, err := DecodePubKeyPEM(pub)
	if err != nil {
		return nil, err
	}
	return EncryptMessage(plaintxt, k)
}

// DecryptMessageWithPEMKey decrypts an encrypted message with a PEM private key
func DecryptMessageWithPEMKey(cyphertxt []byte, priv []byte) ([]byte, error) {
	k, err := DecodePrivKeyPEM(priv)
	if err != nil {
		return nil, err
	}
	return DecryptMessage(cyphertxt, k)
}
