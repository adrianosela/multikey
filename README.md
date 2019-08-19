# multikey - Require n-of-N keys to decrypt

[![Go Report Card](https://goreportcard.com/badge/github.com/adrianosela/multikey)](https://goreportcard.com/report/github.com/adrianosela/multikey)
[![GitHub issues](https://img.shields.io/github/issues/adrianosela/multikey.svg)](https://github.com/adrianosela/multikey/issues)
[![Documentation](https://godoc.org/github.com//adrianosela/multikey?status.svg)](https://godoc.org/github.com/adrianosela/multikey)
[![license](https://img.shields.io/github/license/adrianosela/multikey.svg)](https://github.com/adrianosela/multikey/blob/master/LICENSE)

#### Allows for the creation of decryption rules for secrets at rest, for example:

- Decrypt if **any** of 5 keys are provided
- Decrypt if **all** of 5 keys are provided
- Decrypt if **at least 3** of 5 keys are provided

#### Example use cases:

- I want anyone on my team to be able to decrypt shared application runtime secrets with their own key locally, and have my deployments be able to decrypt the same secrets by fetching a decryption key from AWS KMS
- I want my team to be able to access a highly privileged secret in emergency situations, by having n/N team members provide their key

... many more

#### Benefits of using this:

- Allows for managing secrets with complex rules
- Allows for secrets to be encrypted at rest, which means they can live on your Github, and you don't have to pay for a database or rely on an external service

## Usage

```
import "github.com/adrianosela/multikey"
```

#### Encrypt:
```
mkEncryptedSecret, err := multikey.Encrypt(plainTxtSecret, pubKeys, requireN)
checkErr(err)
```
#### Decrypt:
```
plainTxtSecret, err := multikey.Decrypt(mkEncryptedSecret, privKeys)
checkErr(err)
```
