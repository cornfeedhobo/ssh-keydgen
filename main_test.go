package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/cornfeedhobo/ssh-keydgen/keygen"
	"github.com/cornfeedhobo/ssh-keydgen/slowseeder"
)

func TestKeydgen(t *testing.T) {

	cases := []*keygen.Keydgen{
		{
			Type: keygen.ED25519,
		},
		{
			Type:  keygen.ECDSA,
			Curve: 256,
		},
		{
			Type:  keygen.ECDSA,
			Curve: 384,
		},
		{
			Type:  keygen.ECDSA,
			Curve: 521,
		},
		{
			Type: keygen.RSA,
			Bits: 2048,
		},
		{
			Type: keygen.RSA,
			Bits: 4096,
		},
		{
			Type: keygen.DSA,
			Bits: 1024,
		},
		{
			Type: keygen.DSA,
			Bits: 2048,
		},
		{
			Type: keygen.DSA,
			Bits: 3072,
		},
	}

	for _, k := range cases {

		var name = k.Type
		switch k.Type {
		case keygen.RSA, keygen.DSA:
			name += fmt.Sprintf("_%d", k.Bits)
		case keygen.ECDSA:
			name += fmt.Sprintf("_%d", k.Curve)
		}

		t.Run(name, func(t *testing.T) {

			fmt.Print(name)
			start := time.Now()

			// use small parameters to keep tests short
			d, err := slowseeder.New([]byte("keygen"), 1, 1, 512, 1)
			if err != nil {
				t.Fatal(err)
			}

			_, err = k.GenerateKey(d)
			if err != nil {
				t.Fatal(err)
			}

			privBytes, err := k.MarshalPrivateKey()
			if err != nil {
				t.Fatal(err)
			}

			pubBytes, err := k.MarshalPublicKey()
			if err != nil {
				t.Fatal(err)
			}

			filename, err := filepath.Abs(name)
			if err != nil {
				t.Fatal(err)
			}

			err = writeKeyToFile(k, filename)
			if err != nil {
				t.Fatal(err)
			}

			cmd := exec.Command("ssh-keygen", "-y", "-f", filename)
			outPipe, _ := cmd.StdoutPipe()
			errPipe, _ := cmd.StderrPipe()
			err = cmd.Start()
			if err != nil {
				t.Fatal(err)
			}

			stdout, _ := ioutil.ReadAll(outPipe)
			stderr, _ := ioutil.ReadAll(errPipe)

			if !bytes.Equal(pubBytes, stdout) {
				msg := "Unable to verify generated public key with ssh-keygen"
				msg += "\n\nGenerated Private Key:\n" + string(privBytes)
				msg += "\n\nGenerated Public Key:\n" + string(pubBytes)
				msg += "\n\nStdout:\n" + string(stdout)
				msg += "\n\nStderr:\n" + string(stderr)
				t.Fatal(msg)
			}

			// don't defer in case inspection needs to be done with a failure
			os.Remove(filename)
			os.Remove(filename + ".pub")

			fmt.Printf(" PASS %s\n", time.Since(start))

		})
	}
}
