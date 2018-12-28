# 🍽 crypto [![GoDoc](https://godoc.org/github.com/RTradeLtd/crypto?status.svg)](https://godoc.org/github.com/RTradeLtd/crypto) [![Build Status](https://travis-ci.com/RTradeLtd/crypto.svg?branch=master)](https://travis-ci.com/RTradeLtd/crypto) [![codecov](https://codecov.io/gh/RTradeLtd/crypto/branch/master/graph/badge.svg)](https://codecov.io/gh/RTradeLtd/crypto) [![Go Report Card](https://goreportcard.com/badge/github.com/RTradeLtd/crypto)](https://goreportcard.com/report/github.com/RTradeLtd/crypto)

Package crypto provides object encryption utilities for for [Temporal](https://github.com/RTradeLtd/Temporal), an easy-to-use interface into distributed and decentralized storage technologies for personal and enterprise use cases. Designed for use on 64bit systems, usage on 32bit systems will probably be extremely slow.

It is also available as a command line application:

```sh
$> go get github.com/RTradeLtd/crypto/cmd/temporal-crypto
```

You can then use the tool by calling `temporal-crypto`:

```sh
$> temporal-crypto help
```

## Encryption Process

We offer two forms of encryption, using either AES256-CFB or AES256-GCM.

### AES256-CFB

When using AES256-CFB, we use the passphrase provided during initialization of the `EncryptManager` and run it through `PBKDF2+SHA512`key derivation function to derive a secure encryption key based on the password. The deicision to use SHA512 over SHA256 is primarily due to SHA512 being faster to compute on 64bit hardware, but also being more secure than SHA256. We use this to generate a 32byte key to utilize AES256.

For The salt, we use the secure `rand.Read` to generate a 32byte salt.

Workflow (Encryption): `NewEncryptManager -> EncryptCFB`
Workflow (Decryption): `NewEncryptManager -> DecryptCFB`
### AES256-GCM

As a more secure encryption method, we allow the usage of AES256-GCM. For this, we do not let the user decide the cipherkey, and nonce. Like when using AES256-CFB, we leverage `read.Read` to securely generate a random nonce of 24byte, and cipherkey of 32byte, allowing for usage of AES256.

As this is intended to be used by Temporal's API, naturally one may be concerned about what we do with the randomly generated cipherkey and nonce. In order to protect the users data, we take a passphrase and use that combined with our AES256-CFB encryption mechanism to encrypt the cipherkey, and nonce.

Before encrypting the cipher and nonce, we hex encode them, and format them into a string of `Nonce:\t<nonce>\nCipherKey:\t<cipherKey>`. We then take this formatted string, and encrypt it using AES256-CFB. This is then returned to the user when they place the API call.

Workflow (Encryption, safe): `NewEncryptManager -> EncryptGCM -> EncryptCipherAndNonce`
Workflow (Encryption, unsafe): `NewEncryptManager -> EncryptGCM`
Workflow (Decryption): `NewEncryptManager -> DecryptGCM`