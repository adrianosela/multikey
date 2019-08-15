package multikey

import (
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

const (
	pemBlockType       = "MULTIKEY ENCRYPTED SECRET"
	simpleFmtSeparator = "\n"

	errMsgInvalidSimpleFmt  = "bad format"
	errMsgCouldNotDecodePEM = "could not decode pem block"
)

// secret represents an encrypted secret
type secret struct {
	shards []*encryptedShard
}

// encodePEM returns an encrypted secret in a PEM block
func (s *secret) encodePEM() (string, error) {
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  pemBlockType,
		Bytes: []byte(s.encodeSimple()),
	})
	return string(pemBytes), nil
}

// decodePEM returns an encrypted secret from a pem block
func decodePEM(s string) (*secret, error) {
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		return nil, errors.New(errMsgCouldNotDecodePEM)
	}
	sec, err := decodeSimpleSecret(string(block.Bytes))
	if err != nil {
		return nil, err
	}
	return sec, nil
}

// EncodeSimple returns a simple string representation of the encrypted secret.
// This format is KEY_ID(VALUE)
func (s *secret) encodeSimple() string {
	ret := ""
	for i, sh := range s.shards {
		ret = strings.Join([]string{ret, fmt.Sprintf("%s(%s)", sh.KeyID, sh.Value)}, "")
		if i != len(s.shards)-1 {
			ret = strings.Join([]string{ret, simpleFmtSeparator}, "")
		}
	}
	return ret
}

// decodeSimpleSecret returns a sharded representation of the encrypted secret
func decodeSimpleSecret(s string) (*secret, error) {
	parts := strings.Split(s, simpleFmtSeparator)
	sec := &secret{shards: []*encryptedShard{}}
	for _, p := range parts {
		es, err := decodeSimple(p)
		if err != nil {
			return nil, err
		}
		sec.shards = append(sec.shards, es)
	}
	return sec, nil
}

func decodeSimple(simpleEncodedShard string) (*encryptedShard, error) {
	p1 := strings.Split(simpleEncodedShard, "(")
	if len(p1) < 2 {
		return nil, errors.New(errMsgInvalidSimpleFmt)
	}
	p2 := strings.Split(p1[1], ")")
	if len(p2) < 2 {
		return nil, errors.New(errMsgInvalidSimpleFmt)
	}
	return &encryptedShard{
		KeyID: p1[0],
		Value: p2[0],
	}, nil
}
