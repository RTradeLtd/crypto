package main

import (
	"flag"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	"github.com/RTradeLtd/cmd"
	"github.com/RTradeLtd/config"
	"github.com/RTradeLtd/crypto"
)

var (
	pwd = flag.String("passphrase", "", "passphrase to decrypt file with")
)

var commands = map[string]cmd.Cmd{
	"decrypt-cfb": {
		Blurb: "decrypt file encrypted by Temporal using AES256-CFB",
		Description: `Decrypts given files using passphrase set in the '--passphrase' flag. Decrypted 
files are saved in './<filename>.decrypted'. Multiple files can be provided as 
arguments. For example:

	temporal-crypto --passphrase=temporal decrypt file1.txt file2.txt
`,
		Action: func(cfg config.TemporalConfig, args map[string]string) {
			if *pwd == "" {
				log.Fatal("no passphrase provided - use the '--passphrase' flag")
			}

			decrypt := crypto.NewEncryptManager(*pwd)
			for i := 2; i < len(os.Args); i++ {
				f, err := os.Open(os.Args[i])
				if err != nil {
					fatal(err)
				}
				out, err := decrypt.DecryptCFB(f)
				if err != nil {
					fatal(err)
				}

				dir, err := os.Getwd()
				if err != nil {
					fatal(err)
				}

				if err = ioutil.WriteFile(
					filepath.Join(dir, filepath.Base(os.Args[i]))+".decrypted",
					out, 0644,
				); err != nil {
					fatal(err)
				}
			}
		},
	},
	"encrypt-cfb": {
		Blurb: "encrypt file using Temporal's AES256-CFB encryption format",
		Description: `Encrypts given files using passphrase set in TEMPORAL_PASSPHRASE. Encrypted 
		files are saved in ./<filename>.encrypted. Multiple files can be provided as arguments.`,
		Action: func(cfg config.TemporalConfig, args map[string]string) {
			p := os.Getenv("TEMPORAL_PASSPHRASE")
			if p == "" {
				log.Fatal("no passphrase provided in TEMPORAL_PASSPHRASE")
			}

			decrypt := crypto.NewEncryptManager(p)
			for i := 2; i < len(os.Args); i++ {
				f, err := os.Open(os.Args[i])
				if err != nil {
					fatal(err)
				}
				out, err := decrypt.EncryptCFB(f)
				if err != nil {
					fatal(err)
				}

				dir, err := os.Getwd()
				if err != nil {
					fatal(err)
				}

				if err = ioutil.WriteFile(
					filepath.Join(dir, filepath.Base(os.Args[i]))+".encrypted",
					out, 0644,
				); err != nil {
					fatal(err)
				}
			}
		},
	},
	"encrypt-gcm": {
		Blurb: "encrypt file using Temporals AES256-GCM encryption format",
		Description: `Encrypts given file using randomly generate ciphers and nonces with AES256-GCM. 
		The passphrase set in TEMPORAL_PASSPHRASE is used to encrypt the nonce and cipher, such that they may be transmitted over-the-wire in a secure fashion.
		To decrypt the encrypted nonce+cipher, please write to file and use the decrypt-cfb command`,
		Action: func(cfg config.TemporalConfig, args map[string]string) {
			p := os.Getenv("TEMPORAL_PASSPHRASE")
			if p == "" {
				log.Fatal("no passphrase provided in TEMPORAL_PASSPHRASE")
			}
			decrypt := crypto.NewEncryptManager(p)

			for i := 2; i < len(os.Args); i++ {
				f, err := os.Open(os.Args[i])
				if err != nil {
					fatal(err)
				}
				out, nonce, cipher, err := decrypt.EncryptGCM(f)
				if err != nil {
					fatal(err)
				}
				dir, err := os.Getwd()
				if err != nil {
					fatal(err)
				}
				// write encrypted file
				if err = ioutil.WriteFile(
					filepath.Join(dir, filepath.Base(os.Args[i]))+".encrypted",
					out, 0644,
				); err != nil {
					fatal(err)
				}
				// write encrypted file containing GCM decryption parameters
				out, err = decrypt.EncryptCipherAndNonce(cipher, nonce)
				if err != nil {
					fatal(err)
				}
				if err = ioutil.WriteFile(
					filepath.Join(dir, filepath.Base(os.Args[i]))+"gcm_decryption_parameters.encrypted",
					out, 0644,
				); err != nil {
					fatal(err)
				}
			}
		},
	},
}

func main() {
	app := cmd.New(commands, cmd.Config{
		Name:     "Temporal Encryption Utility",
		ExecName: "temporal-crypto",
		Desc:     "Temporal's object encryption utility",
	})

	flag.Parse()
	os.Exit(app.Run(config.TemporalConfig{}, nil, flag.Args()))
}
