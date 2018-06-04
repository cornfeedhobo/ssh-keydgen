package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/google/goexpect"
)

func TestKeydgen_GenerateKey(t *testing.T) {

	WorkFactor = 1024 * 1

	cases := []struct {
		name          string
		expectFailure bool
		keydgen       *Keydgen
	}{
		// DSA
		{
			name: "DSA_InvalidKeyLength",
			keydgen: &Keydgen{
				Type: DSA,
				Bits: 100,
				Seed: []byte("keydgen"),
			},
			expectFailure: true,
		},
		{
			name: "DSA_1024",
			keydgen: &Keydgen{
				Type: DSA,
				Bits: 1024,
				Seed: []byte("keydgen"),
			},
		},
		{
			name: "DSA_2048",
			keydgen: &Keydgen{
				Type: DSA,
				Bits: 2048,
				Seed: []byte("keydgen"),
			},
		},
		{
			name: "DSA_3072",
			keydgen: &Keydgen{
				Type: DSA,
				Bits: 3072,
				Seed: []byte("keydgen"),
			},
		},
		// ECDSA
		{
			name: "ECDSA_InvalidCurve",
			keydgen: &Keydgen{
				Type:  ECDSA,
				Curve: 128,
				Seed:  []byte("keydgen"),
			},
			expectFailure: true,
		},
		{
			name: "ECDSA_256",
			keydgen: &Keydgen{
				Type:  ECDSA,
				Curve: 256,
				Seed:  []byte("keydgen"),
			},
		},
		{
			name: "ECDSA_384",
			keydgen: &Keydgen{
				Type:  ECDSA,
				Curve: 384,
				Seed:  []byte("keydgen"),
			},
		},
		{
			name: "ECDSA_521",
			keydgen: &Keydgen{
				Type:  ECDSA,
				Curve: 521,
				Seed:  []byte("keydgen"),
			},
		},
		// RSA
		{
			name: "RSA_2048",
			keydgen: &Keydgen{
				Type: RSA,
				Bits: 2048,
				Seed: []byte("keydgen"),
			},
		},
		// ED25519
		{
			name: "ED25519",
			keydgen: &Keydgen{
				Type: ED25519,
				Seed: []byte("keydgen"),
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {

			start := time.Now()
			fmt.Print(c.name)

			if _, err := c.keydgen.GenerateKey(); err != nil && !c.expectFailure {
				t.Fatal(err)
			}

			if !c.expectFailure {

				pub, err := c.keydgen.MarshalPublicKey()
				if err != nil {
					t.Fatal(err)
				}

				filename := fmt.Sprintf("keydgen_test_%s_", c.keydgen.Type)
				if c.keydgen.Type == RSA || c.keydgen.Type == DSA {
					filename += fmt.Sprintf("%d_", c.keydgen.Bits)
				} else if c.keydgen.Type == ECDSA {
					filename += fmt.Sprintf("%d_", c.keydgen.Curve)
				}

				tmpFile, err := ioutil.TempFile("", filename)
				if err != nil {
					t.Fatal(err)
				}

				if err := writeKeyToFile(c.keydgen, tmpFile.Name()); err != nil {
					t.Fatal(err)
				}
				defer func() {
					os.Remove(tmpFile.Name())
					os.Remove(tmpFile.Name() + ".pub")
				}()

				e, _, err := expect.Spawn("ssh-keygen -y -f "+tmpFile.Name(), -1)
				if err != nil {
					t.Fatal(err)
				}
				defer e.Close()

				expr := regexp.MustCompilePOSIX(regexp.QuoteMeta(string(pub)))
				if out, _, err := e.Expect(expr, -1); err != nil {
					t.Fatal("unable to verify generated public key with ssh-keygen: " + out)
				}

			}

			fmt.Printf(" PASS %s\n", time.Since(start))

		})
	}

}
