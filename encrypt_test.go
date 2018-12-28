package crypto

import (
	"bytes"
	"encoding/hex"
	"io"
	"io/ioutil"
	"reflect"
	"strings"
	"testing"
)

func Test_EncryptManager_AES256_GCM(t *testing.T) {
	// open a sample file
	original, err := ioutil.ReadFile("README.md")
	if err != nil {
		t.Errorf("setup failed: %s", err)
		return
	}

	type fields struct {
		passphrase string
	}
	type args struct {
		r io.Reader
	}
	tests := []struct {
		name           string
		fields         fields
		args           args
		want           []byte
		wantEncryptErr bool
		wantDecryptErr bool
	}{
		{"valid passphrase 1", fields{"helloworld"}, args{bytes.NewReader(original)}, original, false, false},
		{"valid short passphrase 1", fields{"a"}, args{bytes.NewReader(original)}, original, false, false},
		{"valid passphrase 2", fields{"helloworld"}, args{bytes.NewReader(original)}, original, false, false},
		{"valid short passphrase 2", fields{"a"}, args{bytes.NewReader(original)}, original, false, false},
		{"valid passphrase 3", fields{"helloworld"}, args{bytes.NewReader(original)}, original, false, false},
		{"valid short passphrase 4", fields{"a"}, args{bytes.NewReader(original)}, original, false, false},
		{"invalid reader", fields{"helloworld"}, args{nil}, nil, true, true},
	}
	// these are used to ensure that we don't detect
	// reused nonces and ciphers across multiple runs
	// which use the same parameters. If done properly,
	// despite using multiple of the same values
	// we should not detect the same nonces and ciphers
	var (
		nonces  [][]byte
		ciphers [][]byte
	)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewEncryptManager(tt.fields.passphrase)
			// encrypt
			encryptData, err := e.Encrypt(tt.args.r, "AES256-GCM")
			if (err != nil) != tt.wantEncryptErr {
				t.Fatalf("Encrypt err = %v, wantErr %v", err, tt.wantEncryptErr)
			}
			// processing after this is only intended for non error decrypt cases
			if tt.wantDecryptErr {
				return
			}
			// decrypt the encoded cipher+nonce data
			decrypted, err := e.Decrypt(bytes.NewReader(encryptData["decryptData"]), nil)
			if (err != nil) != tt.wantDecryptErr {
				t.Fatalf("Decrypt err = %v, wantErr %v", err, tt.wantDecryptErr)
			}
			// parse output
			decryptData := strings.Split(string(decrypted), "\n")
			// grab hex encoded nonce
			hexEncodedNonce := strings.Split(decryptData[0], "\t")[1]
			// grab hex encoded cipher key
			hexEncodedCipherKey := strings.Split(decryptData[1], "\t")[1]
			// update nonces
			nonceBytes, err := hex.DecodeString(hexEncodedNonce)
			if err != nil {
				t.Fatal(err)
			}
			nonces = append(nonces, nonceBytes)
			// update ciphers
			cipherBytes, err := hex.DecodeString(hexEncodedCipherKey)
			if err != nil {
				t.Fatal(err)
			}
			ciphers = append(ciphers, cipherBytes)
			// test decrypt of data
			decrypted, err = e.Decrypt(bytes.NewReader(encryptData["encryptedData"]), &DecryptParams{
				CipherKey: hexEncodedCipherKey,
				Nonce:     hexEncodedNonce,
			})
			if err != nil {
				t.Fatal(err)
			}
			// check decrypted output
			if !reflect.DeepEqual(decrypted, tt.want) {
				t.Errorf("Encrypt = %v, want %v", decrypted, tt.want)
			}
		})
	}

	// parse through nonces and ciphers to ensure we don't have duplicates
	// this would indicate that RNG was insecure
	found := make(map[string]bool)
	for i, v := range nonces {
		if found[hex.EncodeToString(v)] {
			t.Fatal("reused nonce discovered")
		}
		if found[hex.EncodeToString(ciphers[i])] {
			t.Fatal("reused ciphers discovered")
		}
		found[hex.EncodeToString(v)] = true
		found[hex.EncodeToString(ciphers[i])] = true
	}
}
func Test_EncryptManager_AES256_CFB(t *testing.T) {
	// open a sample file
	original, err := ioutil.ReadFile("README.md")
	if err != nil {
		t.Errorf("setup failed: %s", err)
		return
	}

	type fields struct {
		passphrase string
	}
	type args struct {
		r io.Reader
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []byte
		wantErr bool
	}{
		{"valid passphrase", fields{"helloworld"}, args{bytes.NewReader(original)}, original, false},
		{"valid short passphrase", fields{"a"}, args{bytes.NewReader(original)}, original, false},
		{"invalid reader", fields{"helloworld"}, args{nil}, []byte{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewEncryptManager(tt.fields.passphrase)

			// encrypt
			encryptData, err := e.Encrypt(tt.args.r, "AES256-CFB")
			if (err != nil) != tt.wantErr {
				t.Errorf("Encrypt error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			var dataToDecrypt []byte
			// if expecting encryption error
			// we need to fake some data to decrypt
			if tt.wantErr {
				dataToDecrypt = []byte("somesillyfakedatatotesthello12345678910111213141")
			} else {
				dataToDecrypt = encryptData["encryptedData"]
			}
			// decrypt
			decrypted, err := e.Decrypt(bytes.NewReader(dataToDecrypt), nil)
			if err != nil {
				t.Fatal(err)
			}
			// check decrypted output
			if !reflect.DeepEqual(decrypted, tt.want) {
				t.Errorf("Encrypt = %v, want %v", decrypted, tt.want)
			}
		})
	}
}
