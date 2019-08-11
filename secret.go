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
	sec, err := decodeSimple(string(block.Bytes))
	if err != nil {
		return nil, err
	}
	return sec, nil
}

// EncodeSimple returns a simple string representation of the encrypted secret.
// This format is KEY_ID(VALUE) or KEY_ID(VALUE)(HELPER) depending on whether a
// helper was needed to shard the secret
func (s *secret) encodeSimple() string {
	ret := ""
	for i, sh := range s.shards {
		if sh.Helper != "" {
			ret = strings.Join([]string{ret, fmt.Sprintf("%s(%s)(%s)", sh.KeyID, sh.Value, sh.Helper)}, "")
		} else {
			ret = strings.Join([]string{ret, fmt.Sprintf("%s(%s)", sh.KeyID, sh.Value)}, "")
		}
		if i != len(s.shards)-1 {
			ret = strings.Join([]string{ret, simpleFmtSeparator}, "")
		}
	}
	return ret
}

// decodeSimple returns a sharded representation of the encrypted secret
func decodeSimple(s string) (*secret, error) {
	parts := strings.Split(s, simpleFmtSeparator)
	if len(parts) < 1 {
		return nil, errors.New(errMsgInvalidSimpleFmt)
	}
	sec := &secret{shards: []*encryptedShard{}}
	for _, p := range parts {
		var es *encryptedShard
		var err error
		// if there is a helper shard
		if strings.Contains(p, ")(") {
			if es, err = decodeWithHelper(p); err != nil {
				return nil, err
			}
		} else { // no helper
			if es, err = decode(p); err != nil {
				return nil, err
			}
		}
		sec.shards = append(sec.shards, es)
	}
	return sec, nil
}

func decodeWithHelper(simpleEncodedShard string) (*encryptedShard, error) {
	p1 := strings.Split(simpleEncodedShard, ")(")
	if len(p1) < 2 {
		return nil, errors.New(errMsgInvalidSimpleFmt)
	}
	p2 := strings.Split(p1[0], "(")
	if len(p2) < 2 {
		return nil, errors.New(errMsgInvalidSimpleFmt)
	}
	p3 := strings.Split(p1[1], ")")
	if len(p3) < 2 {
		return nil, errors.New(errMsgInvalidSimpleFmt)
	}
	return &encryptedShard{
		KeyID:  p2[0],
		Value:  p2[1],
		Helper: p3[0],
	}, nil
}

func decode(simpleEncodedShard string) (*encryptedShard, error) {
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
