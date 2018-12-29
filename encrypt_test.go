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
			e := NewEncryptManager(tt.fields.passphrase, GCM, nil)
			// encrypt
			encryptedData, err := e.Encrypt(tt.args.r)
			if (err != nil) != tt.wantEncryptErr {
				t.Fatalf("Encrypt err = %v, wantErr %v", err, tt.wantEncryptErr)
			}
			// processing after this is only intended for non error decrypt cases
			if tt.wantDecryptErr {
				return
			}
			// update nonces
			nonceBytes, err := hex.DecodeString(e.gcmDecryptParams.Nonce)
			if err != nil {
				t.Fatal(err)
			}
			nonces = append(nonces, nonceBytes)
			// update ciphers
			cipherBytes, err := hex.DecodeString(e.gcmDecryptParams.CipherKey)
			if err != nil {
				t.Fatal(err)
			}
			ciphers = append(ciphers, cipherBytes)
			// test decrypt of data
			decrypted, err := e.Decrypt(bytes.NewReader(encryptedData))
			if (err != nil) != tt.wantDecryptErr {
				t.Fatalf("Decrypt err = %v, wantErr %v", err, tt.wantDecryptErr)
			}
			if err != nil {
				t.Fatal(err)
			}
			// check decrypted output
			if !reflect.DeepEqual(decrypted, tt.want) {
				t.Errorf("Encrypt = %v, want %v", decrypted, tt.want)
			}
			// retrieve gcm decryption data
			encryptedGCMData, err := e.RetrieveGCMDecryptionParameters()
			if (err != nil) != tt.wantEncryptErr {
				t.Fatalf("RetrieveGCMDecryptionParameters err = %v, wantErr %v", err, tt.wantEncryptErr)
			}
			// further processing is only intended for non error expected test cases
			if tt.wantEncryptErr {
				return
			}
			// create our CFB decrypter to parse the gcm data
			e = NewEncryptManager(tt.fields.passphrase, CFB, nil)
			decryptedGCMData, err := e.Decrypt(bytes.NewReader(encryptedGCMData))
			if err != nil {
				t.Fatal(err)
			}
			// parse gcm decryption data
			parsedGCMData := strings.Split(string(decryptedGCMData), "\n")
			// retrieve hex encoded nonce
			encodedNonce := strings.Split(parsedGCMData[0], "\t")[1]
			// retrieve hex encoded cipher
			encodedCipher := strings.Split(parsedGCMData[1], "\t")[1]
			// reinstantiate EncryptManager to decrypt our GCM encrypted data
			e = NewEncryptManager(tt.fields.passphrase, GCM, &GCMDecryptParams{CipherKey: encodedCipher, Nonce: encodedNonce})
			decrypted, err = e.Decrypt(bytes.NewReader(encryptedData))
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
			e := NewEncryptManager(tt.fields.passphrase, CFB, nil)

			// encrypt
			dataToDecrypt, err := e.Encrypt(tt.args.r)
			if (err != nil) != tt.wantErr {
				t.Errorf("Encrypt error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			// if expecting encryption error
			// we need to fake some data to decrypt
			if tt.wantErr {
				dataToDecrypt = []byte("somesillyfakedatatotesthello12345678910111213141")
			}
			// decrypt
			decrypted, err := e.Decrypt(bytes.NewReader(dataToDecrypt))
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
