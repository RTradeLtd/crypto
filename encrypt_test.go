package crypto

import (
	"bytes"
	"io"
	"io/ioutil"
	"reflect"
	"testing"
)

func Test_EncryptManager(t *testing.T) {
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
			encrypted, err := e.Encrypt(tt.args.r)
			if (err != nil) != tt.wantErr {
				t.Errorf("EncryptManager.Encrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}

			// decrypt
			decrypted, err := e.Decrypt(bytes.NewReader(encrypted))
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
