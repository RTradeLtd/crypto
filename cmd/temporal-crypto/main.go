package main

import (
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	"github.com/RTradeLtd/cmd"
	"github.com/RTradeLtd/config"
	"github.com/RTradeLtd/crypto"
)

var commands = map[string]cmd.Cmd{
	"decrypt": cmd.Cmd{
		Blurb: "decrypt file encrypted by Temporal",
		Description: `Decrypts given files using passphrase set in TEMPORAL_PASSPHRASE. Decrypted 
		files are saved in ./<filename>.decrypted. Multiple files can be provided as arguments.`,
		Action: func(cfg config.TemporalConfig, args map[string]string) {
			p := os.Getenv("TEMPORAL_PASSPHRASE")
			if p == "" {
				log.Fatal("no passphrase provided in TEMPORAL_PASSPHRASE")
			}

			decrypt := crypto.NewEncryptManager(p)
			for i := 2; i < len(os.Args); i++ {
				f, err := os.Open(os.Args[i])
				if err != nil {
					log.Fatal(err)
				}
				out, err := decrypt.Decrypt(f)
				if err != nil {
					log.Fatal(err)
				}

				dir, err := os.Getwd()
				if err != nil {
					log.Fatal(err)
				}

				if err = ioutil.WriteFile(
					filepath.Join(dir, filepath.Base(os.Args[i]))+".decrypted",
					out, 0644,
				); err != nil {
					log.Fatal(err)
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
	os.Exit(app.Run(config.TemporalConfig{}, nil, os.Args[1:]))
}
