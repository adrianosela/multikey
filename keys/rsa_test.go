package keys

import (
	"crypto/rsa"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	pubA = []byte(`
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA3ODODibai/mmGOry3325h254iyCws7lrF9zu/eX6vJ+MC+8qRW20
xY8p0A6ESBmovF4kH9gYdhN9FVxvKEJg1Gw0tgblnieE9m50Su/maPg0T7NPSjiJ
SYMXsI01UbYqDZWHunekvibFHQDSFPrdUNwR4RYBdpvV6HB9IygsSX26Ua536FDW
DZ2f22wRJRmX+nGNoC189G7baVbLNvNpm+V6dDMSkDifLJRaiooJEtNMn8zHZMBu
+0CorXhb9Ui0GFrqZCAqakx8y97BTqlGuAfwuXlArJV/hA+SDDwGdtPcljFUycBW
S2fGjodJLH1nUvc6T5BhnuMz6/p6qNM7iwIDAQAB
-----END RSA PUBLIC KEY-----`)
	privA = []byte(`
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEA3ODODibai/mmGOry3325h254iyCws7lrF9zu/eX6vJ+MC+8q
RW20xY8p0A6ESBmovF4kH9gYdhN9FVxvKEJg1Gw0tgblnieE9m50Su/maPg0T7NP
SjiJSYMXsI01UbYqDZWHunekvibFHQDSFPrdUNwR4RYBdpvV6HB9IygsSX26Ua53
6FDWDZ2f22wRJRmX+nGNoC189G7baVbLNvNpm+V6dDMSkDifLJRaiooJEtNMn8zH
ZMBu+0CorXhb9Ui0GFrqZCAqakx8y97BTqlGuAfwuXlArJV/hA+SDDwGdtPcljFU
ycBWS2fGjodJLH1nUvc6T5BhnuMz6/p6qNM7iwIDAQABAoIBABXpAueqeQFrmUtd
ewwqZ44EqlZ6vqyFVxc95kMvXgj59qV0awgKEuWKBwbJedvBF9jfqcuy3vJPipfk
3G3s77gCp9PqqTpgBzN+z3BjjcKZ5G6HhfUB2LR/GYl86G4bmN5SF+2qUqA+Lk1r
OGu2Wt/bhLaEPU7rtHNjPTaQlJwRem+61/8/EbUqXJJSoztCA+mvrhgDblcRUiSm
7sW1lMY1seHIB8fNWqB3WeaFGXAS3japc9jl9HpGipoZhsU3CU9RRxBZHBmEFt47
XPx2+ASmvSiyV0xfYszURfj1sRuk/LHoMNEII43zNIkOndhgNT56Z4FLghvIhfJN
OpXD2uECgYEA/yyCTZUywrIADQtNJpcv2fTnfdCLK2zpmr8eEu1/4nEJuI8kHYlz
SMXTfYCUi9jO3ONl7nTKi5aBGkq1M9xgZvBZ2d92TAoLY1x8isl74gqQKCwHxx9g
0WZztqlLn040ZQNRlNHxv6ukMUPdKzJP/o8fez8HNiitb25tSJ6H8bsCgYEA3Zff
CJLeZv0asIRPDeuf0m51tjKSWzJlvc+g0e+7poVfCrnxPlsdStTHJknAkOi6WqXF
sLfQgNHnpfzYdy37iW5Ppivlvu1hLYFo8ChTDz24m6TQftbvU+QS5/p7IYYuwJXz
NrmXMvQVPDUAFZcFI9NVFsXBYu9GMvRFX5n4GHECgYAWOH8EWIi6EZwVhrVqNeIx
3bTG7QEhf/N7yUbKKSpowqUxEC358H08ihWXqTnGT9P7wkWfFUaKD0ogyv6qjHdM
n4ODiIUZrAo/1c72mwMRtQ/Gn8bxnRbmRUCwWF/AeKPxY++XwQyHP2Al9h3tZA05
QqdgKSXsnnAz8u7LUxrNfwKBgD54jlwwa5rFSDzzUAYwo0ID+hN/dltXfe9hFYmZ
+GEdwImZmjVmIn/yNKLKsAsqUT809OK5L4LhqljVS4Ft6Tf5bWL/hSmqancVwKvT
8nadg+n9MPpRRe90oQ/dQdFVruCEZajL8aBfx4zNtFRh2wUakyZ0YeyuYDAFRXmK
QrNBAoGAaPnksKkHOqOzVMR7vsoLdgDbKtB5IZWaARVvWxH2ea82AjF9jecaicfp
62t8ejHKbXWyhFNryB+49XvC5KBEVhq4GWIuQ8R7ZuGii5rtlkgnTna9ELLPTlLQ
JZ4BOZ+uASXL0URAyHQ9vGMdfUnsgoh0Gedw/yslIfTJpdDSgBw=
-----END RSA PRIVATE KEY-----`)
	privB = []byte(`
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAlOCNzJuKQ1itsl1Bi9RHyMi3Gsc+WUv7RD5cZ478uUA4W7Wt
eOBDIxlk4L7Ir40J+6ecAJej4qxVPlUqkErm8UCK0J8/hhvlmpQdMwjG3Ivt3Dpl
OBTfQJfbpwcvkKtkGarC1zju9qgifkydITktq6Zj+NJzbZcVhCWBYtTEDr78PQ2x
dGvmPdBFeV//NXJzzI/jALoELA4CJFhasttlHIu2R5kM2dC2DWRj7eC/zDj1qG4H
C79d1TzeiCCtrPUiLKCuPC1Cpd/b4t6Me91+QHJrcNvhS1tdwXoCdK/TpTNnkk+S
i6pPrL0pQ1+m3ZsLLYrWmqnn/IDCAJ4hpXHuLwIDAQABAoIBAH2RWIg2uEtNRFOo
bFxv04v6HtYrLt9KQsewgWenJmlpTR+tAH9vR7EW/grBX6sRnlXvbJjjTYsmJ0/H
rXq+ckMRWQPVDVMjvGjAfFBLGs9yBlE1v6GpmRN2AgHDAc9Xf7pWWLgGgSbxcQZt
wCoBfA/G65M2jbzlLXSj3ZlqM2LrUaGzT4EtyuuKRGYX+KbO7xGATBDEK5KGUZ9Q
SItRugthqob/7GsagD6Lv4Z9FAp3y6Ltipd2rYk/PwtzvMTJAiESCiu4wa3O09Qb
KdpubzWh9umc6CKnaunIg4Wxf44poNDxb0cnQ+tVZIhs14O3d4TngZbt8NFvGBXQ
SUnnKuECgYEAwH5W4Pbg2U3DzmCDvOTzXJVJQaNNB9ttt6gWqZdMizCzCb7GeMCz
2zjRyqoha8dy5Dw/DcmyLzsQ94h4P2OYKYUtQyvquU8SFV8fNWMh1iOsBY5effGR
NamQA8Zz0n2qWsVK0wBNpgIgOAQoQ7mdN3awlIF5/U1T/VXNKbFE6lMCgYEAxf50
fRGu7vUst8kWzfaTs1gt/Ap8uwBGBFKj4EsQjvtMObZKZv5ixaH2N7zOkA+cmU+c
tcQXt9/cGCbv4a2AlPEWew+nTqOpoAruPKwZja0175DskX/EuLIaIsaqGBcZFpt4
wIrB44u0+F7oGYARCowVFS6WAqinhx9NF3k9iTUCgYBVxLVPPZFIIcc6IHTyaI0q
1nWyomGDO7kyWNnoLLr1VfigQfnK+gnphvKrO4zyqga+PT3XFeSn+MiBkrQJgoXd
EjLtuBa5BMtI7H5KWmZMNM7EFwBxW35ZC7lYhUc8JbQPB9NkGsF+U3opm2iZbI3p
lZ/uO5awT5E50s48YnkTcwKBgE/MpMqby/PHoURZqfVNQm5wRehlmawNCitH24DV
AFGAe1JvZEFqmgippIEGegKaKDWqXrDr3dtgQGcDmn9M3JwrJzJmNrp9QCqe/TI6
8vmlLC3oLVDfPDxsnBgUFg4rkRMJinuf8VFyx3erWMSeVz/3AbBN3Gwp6YuOVBX3
6ZNZAoGBAJ8Q6zJuvYsfC9A+W971du/xJZXk33DPA0CUifLwq4YACk4y4OT/9cd1
u0N3O5qtmmLaW6E7M4/L9LahYqlqd7o46afR4Y2DuVTs2hawT9zS58zkllDCHQ4U
rQPf4E3IbH70rLZjCbEKLRAzgsWytUdEKCBeF26/XR5z3JZKKMur
-----END RSA PRIVATE KEY-----`)
)

func TestGenerateRSAKeyPair(t *testing.T) {
	// positive test
	priv, pub, err := GenerateRSAKeyPair(2048)
	assert.Nil(t, err)
	assert.NotNil(t, priv)
	assert.NotNil(t, pub)

	// negative test
	priv, pub, err = GenerateRSAKeyPair(1)
	assert.NotNil(t, err)
	assert.Nil(t, priv)
	assert.Nil(t, pub)
}

func TestEncodePubKeyPEM(t *testing.T) {
	_, pub, err := GenerateRSAKeyPair(2048)
	assert.Nil(t, err)
	assert.NotNil(t, pub)

	pubStr := strings.Trim(string(EncodePubKeyPEM(pub)), "\n")
	assert.True(t, strings.HasPrefix(pubStr, "-----BEGIN RSA PUBLIC KEY-----"))
	assert.True(t, strings.HasSuffix(pubStr, "-----END RSA PUBLIC KEY-----"))
}

func TestEncodePrivKeyPEM(t *testing.T) {
	priv, _, err := GenerateRSAKeyPair(2048)
	assert.Nil(t, err)
	assert.NotNil(t, priv)

	privStr := strings.Trim(string(EncodePrivKeyPEM(priv)), "\n")
	assert.True(t, strings.HasPrefix(privStr, "-----BEGIN RSA PRIVATE KEY-----"))
	assert.True(t, strings.HasSuffix(privStr, "-----END RSA PRIVATE KEY-----"))
}

func TestDecodePrivKeyPem(t *testing.T) {
	// positive test
	priv, err := DecodePrivKeyPEM(privA)
	assert.Nil(t, err)
	assert.NotNil(t, priv)
	// negative test
	priv, err = DecodePrivKeyPEM([]byte("ASDFGH"))
	assert.NotNil(t, err)
	assert.Nil(t, priv)
}

func TestDecodePubKeyPem(t *testing.T) {
	// positive test
	pub, err := DecodePubKeyPEM(pubA)
	assert.Nil(t, err)
	assert.NotNil(t, pub)
	// negative test
	pub, err = DecodePubKeyPEM([]byte("ASDFGH"))
	assert.NotNil(t, err)
	assert.Nil(t, pub)
}

func TestGetFingerPrint(t *testing.T) {
	pub, err := DecodePubKeyPEM(pubA)
	assert.Nil(t, err)
	assert.NotNil(t, pub)

	matchingPriv, err := DecodePrivKeyPEM(privA)
	assert.Nil(t, err)
	assert.NotNil(t, matchingPriv)

	anotherPriv, err := DecodePrivKeyPEM(privB)
	assert.Nil(t, err)
	assert.NotNil(t, anotherPriv)

	assert.Equal(t, GetFingerprint(pub), GetFingerprint(&matchingPriv.PublicKey))
	assert.NotEqual(t, GetFingerprint(pub), GetFingerprint(&anotherPriv.PublicKey))
}

func TestEncryptMessage(t *testing.T) {
	// positive test
	pub, err := DecodePubKeyPEM(pubA)
	assert.Nil(t, err)
	assert.NotNil(t, pub)
	encrypted, err := EncryptMessage([]byte("secretmsg"), pub)
	assert.Nil(t, err)
	assert.NotNil(t, encrypted)

	// negative test
	encrypted, err = EncryptMessage([]byte("secretmsg"), &rsa.PublicKey{})
	assert.Nil(t, encrypted)
	assert.NotNil(t, err)
}

func TestDecryptMessage(t *testing.T) {
	// preconditions
	pub, err := DecodePubKeyPEM(pubA)
	assert.Nil(t, err)
	assert.NotNil(t, pub)
	priv, err := DecodePrivKeyPEM(privA)
	assert.Nil(t, err)
	assert.NotNil(t, priv)
	privB, err := DecodePrivKeyPEM(privB)
	assert.Nil(t, err)
	assert.NotNil(t, priv)
	secret := []byte("secretmsg")
	encrypted, err := EncryptMessage(secret, pub)
	assert.Nil(t, err)
	assert.NotNil(t, encrypted)

	// positive test
	decrypted, err := DecryptMessage(encrypted, priv)
	assert.Nil(t, err)
	assert.NotNil(t, decrypted)
	assert.Equal(t, secret, decrypted)

	// negative test
	decrypted, err = DecryptMessage(encrypted, privB)
	assert.NotNil(t, err)
	assert.Nil(t, decrypted)
}

func TestEncryptMessageWithPEMKey(t *testing.T) {
	secret := []byte("secretmsg")

	// positive test
	encrypted, err := EncryptMessageWithPEMKey(secret, pubA)
	assert.Nil(t, err)
	assert.NotNil(t, encrypted)

	// negative test - bad key
	encrypted, err = EncryptMessageWithPEMKey(secret, []byte(""))
	assert.NotNil(t, err)
	assert.Nil(t, encrypted)
}

func TestDecryptMessageWithPEMKey(t *testing.T) {
	// preconditions
	secret := []byte("secretmsg")
	encrypted, err := EncryptMessageWithPEMKey(secret, pubA)
	assert.Nil(t, err)
	assert.NotNil(t, encrypted)

	// positive test
	decrypted, err := DecryptMessageWithPEMKey(encrypted, privA)
	assert.Nil(t, err)
	assert.NotNil(t, decrypted)

	// negative test - bad key
	decrypted, err = DecryptMessageWithPEMKey(encrypted, []byte(""))
	assert.NotNil(t, err)
	assert.Nil(t, decrypted)
}
