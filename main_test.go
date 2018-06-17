package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"testing"
	"time"

	"path/filepath"

	"github.com/cornfeedhobo/ssh-keydgen/deterministic"
	"github.com/cornfeedhobo/ssh-keydgen/keydgen"
)

func assertSshKeygen(k *keydgen.Keydgen) error {

	privBytes, err := k.MarshalPrivateKey()
	if err != nil {
		return err
	}

	pubBytes, err := k.MarshalPublicKey()
	if err != nil {
		return err
	}

	filename := fmt.Sprintf("keydgen_test_%s_", k.Type)
	switch k.Type {
	case keydgen.RSA, keydgen.DSA:
		filename += fmt.Sprintf("%d_", k.Bits)
	case keydgen.ECDSA:
		filename += fmt.Sprintf("%d_", k.Curve)
	}

	filename, err = filepath.Abs(filename)
	if err != nil {
		return err
	}

	if err := writeKeyToFile(k, filename); err != nil {
		return err
	}

	cmd := exec.Command("ssh-keygen", "-y", "-f", filename)
	outPipe, _ := cmd.StdoutPipe()
	errPipe, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		return err
	}

	stdout, _ := ioutil.ReadAll(outPipe)
	stderr, _ := ioutil.ReadAll(errPipe)

	if !bytes.Equal(pubBytes, stdout) {
		msg := "Unable to verify generated public key with ssh-keygen"
		msg += "\n\nGenerated Private Key:\n" + string(privBytes)
		msg += "\n\nGenerated Public Key:\n" + string(pubBytes)
		msg += "\n\nStdout:\n" + string(stdout)
		msg += "\n\nStderr:\n" + string(stderr)
		return errors.New(msg)
	}

	os.Remove(filename)
	os.Remove(filename + ".pub")

	return nil
}

func TestKeydgen(t *testing.T) {

	cases := []struct {
		name string
		fail bool
		k    *keydgen.Keydgen
	}{
		{
			name: "DSA_1024",
			k: &keydgen.Keydgen{
				Type: keydgen.DSA,
				Bits: 1024,
			},
		},
		{
			name: "DSA_2048",
			k: &keydgen.Keydgen{
				Type: keydgen.DSA,
				Bits: 2048,
			},
		},
		{
			name: "DSA_3072",
			k: &keydgen.Keydgen{
				Type: keydgen.DSA,
				Bits: 3072,
			},
		},
		// ECDSA
		{
			name: "ECDSA_256",
			k: &keydgen.Keydgen{
				Type:  keydgen.ECDSA,
				Curve: 256,
			},
		},
		{
			name: "ECDSA_384",
			k: &keydgen.Keydgen{
				Type:  keydgen.ECDSA,
				Curve: 384,
			},
		},
		{
			name: "ECDSA_521",
			k: &keydgen.Keydgen{
				Type:  keydgen.ECDSA,
				Curve: 521,
			},
		},
		// RSA
		{
			name: "RSA_2048",
			k: &keydgen.Keydgen{
				Type: keydgen.RSA,
				Bits: 2048,
			},
		},
		// ED25519
		{
			name: "ED25519",
			k: &keydgen.Keydgen{
				Type: keydgen.ED25519,
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {

			var (
				reads int
				start = time.Now()
				seed  = []byte("keydgen")
			)

			// use small parameters to keep tests short
			r, err := deterministic.New(seed, seed, 1, 1, 1024, 1)
			if err != nil {
				t.Fatal(err)
			}

			fmt.Print(c.name)
			if _, err := c.k.GenerateKey(r); err != nil && !c.fail {
				t.Fatal(err)
			} else if !c.fail {
				if err = assertSshKeygen(c.k); err != nil {
					t.Fatal(err)
				}
				reads = r.Reads()
			}
			fmt.Printf(" PASS %s with %d reads\n", time.Since(start), reads)
		})
	}
}
