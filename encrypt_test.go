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
			e := NewEncryptManager(tt.fields.passphrase, GCM)
			// encrypt
			encryptedData, err := e.WithGCM(nil).Encrypt(tt.args.r)
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
			e = NewEncryptManager(tt.fields.passphrase, CFB)
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
			e = NewEncryptManager(tt.fields.passphrase, GCM)
			decrypted, err = e.WithGCM(&GCMDecryptParams{CipherKey: encodedCipher, Nonce: encodedNonce}).Decrypt(bytes.NewReader(encryptedData))
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
			e := NewEncryptManager(tt.fields.passphrase, CFB)

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

func Test_EncryptManager(t *testing.T) {

	// open a sample file
	original, err := ioutil.ReadFile("sample_data")
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

	ipfsKey := "CAASqAkwggSkAgEAAoIBAQCwFnPgFZuoV+TunsOCd7gjTgodYHZzZWvhNt/8ArSF4pUHKN4hEfAEtCpk/Zk030ZgtNxApLeVe6VcOtKHw/Jc/DOtDOm9l23DpJk1ObrVfVRfpliJCjbHceSMQbq3R27FN5UoDZjfJVYiB1CLtC/KMnwOt6yBh8QcgTxI8m0Ha1DXRj42jfkKuUUkDeNiGySPRc+JuuZr6hBLlHKbbjk8Qc2uY1EpOrqXq96z/Mwe7tDiYpzpJdIlBJMSc93lPyBDtTVPJ7WP0qSC3r0IQjq9j330p0UUnDJdkAyhgNfL0cAzn/aqo7T6DWMy0E/zXHeG+IWJn1EAkrqVuHPUDmKZAgMBAAECggEAIAIk1CH5ZpN7mOihL3Eltr0z1302aumPv6Oi+YNgX0n9vwxtvGMvVxuM7Uiv9c10VJXrx5BpkrGkMGy84lL7Fm390sIbJwyEtmCQPP2eebpLgQuS4m5J4N1SJzC3iSNh/lWJNnuqQz3dN1hPCuYZHc8pf99hazZLrsbLN5NhwEwzMmYAcjoM6mcwhrjCIdnafHFCeEmHlUmTy0N1HsUJou8Z/9ciUYbcLxUBwk7UwZg9GK78eRG2hP20wkqo8NPaGkUq6i+o1aGCZtIdsJBDHFea8wwPQgXq6CE+g/PfT/1JRWYINYT0miEOy52huEUkAFqVnsbVr2SYB7cXFq0DUQKBgQDm8uQiic6XXReF/EcuTKYesUgI7Nu9nIg/YxTwgsqK32TgFQ0eUI3OhJPfrE+Eb1aTXjsf59wyN6jO3AsUwuwB4rGOJsBCjj+9a6w63UCcbHE9cbnzoX83cIHBzy7nS3aEBHLgg37Y2TbqQEJ2KbFTrjxz2JIwnehrAlAnMDxwvQKBgQDDMCZOpGCtB+fIAsQLvIOQVjT7uN8/hyzX9cXgeLxBhVqplk3K/yierAcb8pVW+h59UbIs//OG0BBd0R8+sM1UL2PbFuZMk8zLMM0cngRlxBdTg+pTGkB7UpE2MBGd5nA5cMEiMksWIChN/2q68/ZNnGFts0bAG/XFheNfMKhdDQKBgQC/+yNX7rSUsOcQEzHctAzXsMlP2g2kpk3AW44ZjK/wF1oUyIsaKx5mkWEXa3bCgYc3g/qkQCqUeB5Uryhq/soPmzG8GEx0RymHPc1zNV8zaRYNXM+WTiahoF3NDXxQ+zMu9T/FkKnOe2qh+f8FmQz2of1Q07Raw7lj0w1sNjXYBQKBgQCL2r437xPOJzHuX/z0o9ho3TwNeUONE2AQRWvJEPliwRhbFvUalIUYXA6j+ccDkSezh4vxLlvhpsdzUVnf43Lb9TDJVLki+Wvt00PEU3y3Ji/IiWamsNKvClQ9zWdyCiEzJxVbWUnvyo7WhEKHPjKnHXu5zJDPKbmKFAr8s7KPKQKBgELbmWqdiiyouzWZzEmCG/DVFU24SPjEfEeLwFiKzo8EXzS0O8KWBEmcuv3jkm0nnL9wFz6rdSRJBXRZTBl8nK5mIJhrAyroI0WfqO1YgR4lPKvLW2e3wZFhc0SPG9m/J28zzl5qCuAg0c4D89cxMb5MFRQpIwPX+353MBpheQR0"

	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []byte
		wantErr bool
	}{
		{"1", fields{ipfsKey}, args{bytes.NewReader(original)}, original, false},
		{"2", fields{ipfsKey}, args{bytes.NewReader(original)}, original, false},
		{"3", fields{ipfsKey}, args{nil}, []byte{}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewEncryptManager(tt.fields.passphrase, RSA)

			// encrypt
			dataToDecrypt, err := e.Encrypt(tt.args.r)
			if (err != nil) != tt.wantErr {
				t.Errorf("Encrypt error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// if expecting encryption error
			// we need to fake some data to decrypt
			if tt.wantErr {
				return
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
