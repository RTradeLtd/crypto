package crypto

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"reflect"
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
	var (
		nonces        [][]byte
		ciphers       [][]byte
		encodedNonce  string
		encodedCipher string
	)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewEncryptManager(tt.fields.passphrase)

			// encrypt
			encrypted, nonce, cipher, err := e.EncryptGCM(tt.args.r)
			if (err != nil) != tt.wantEncryptErr {
				t.Errorf("EncryptManager.EncryptGCM() error = %v, wantErr %v", err, tt.wantEncryptErr)
			}
			if nonce != nil {
				// encode nonce
				encodedNonce = hex.EncodeToString(nonce)
				nonces = append(nonces, nonce)
			}
			if cipher != nil {
				// encode cipher
				encodedCipher = hex.EncodeToString(cipher)
				ciphers = append(ciphers, cipher)
			}

			// decrypt
			decrypted, err := e.DecryptGCM(bytes.NewReader(encrypted), encodedCipher, encodedNonce)
			if (err != nil) != tt.wantDecryptErr {
				t.Errorf("EncryptManager.DecryptGCM() = %v, want %v", err, tt.wantDecryptErr)
			}
			// check decrypted output
			if !reflect.DeepEqual(decrypted, tt.want) {
				t.Errorf("EncryptManager.EncryptGCM() = %v, want %v", decrypted, tt.want)
			}
			if tt.name == "invalid reader" {
				return
			}
			// test EncryptCipherAndNonce
			encrypted, err = e.EncryptCipherAndNonce(cipher, nonce)
			if (err != nil) != tt.wantEncryptErr {
				t.Errorf("EncryptManager.EncryptCipherAndNonce() = %v, want %v", err, tt.wantEncryptErr)
			}
			// decrypt output which was encrypted using AES256-CFB
			decrypted, err = e.DecryptCFB(bytes.NewReader(encrypted))
			if (err != nil) != tt.wantDecryptErr {
				t.Errorf("EncryptManager.DecryptCFB() = %v, want %v", err, tt.wantDecryptErr)
			}
			expectedFormattedDecryptedOutput := fmt.Sprintf("Nonce:\t%s\nCipherKey:\t%s", encodedNonce, encodedCipher)
			if !reflect.DeepEqual(string(decrypted), expectedFormattedDecryptedOutput) {
				t.Fatal("failed to properly construct GCM decryption file")
				return
			}
		})
	}
	// parse through nonces to ensure we don't have duplicates
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
		{"invalid reader", fields{"helloworld"}, args{nil}, original, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewEncryptManager(tt.fields.passphrase)

			// encrypt
			encrypted, err := e.EncryptCFB(tt.args.r)
			if (err != nil) != tt.wantErr {
				t.Errorf("EncryptManager.EncryptCFB() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}

			// decrypt
			decrypted, err := e.DecryptCFB(bytes.NewReader(encrypted))
			if err != nil {
				t.Error(err)
				return
			}
			if err != nil {
				return
			}

			// check
			if !reflect.DeepEqual(decrypted, tt.want) {
				t.Errorf("EncryptManager.Encrypt() = %v, want %v", decrypted, tt.want)
			}
		})
	}
}
