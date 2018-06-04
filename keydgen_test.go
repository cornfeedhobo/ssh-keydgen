package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/google/goexpect"
)

type keygenCase struct {
	name          string
	expectFailure bool
	keydgen       *Keydgen
}

func init() {
	WorkFactor = 4096
}

func testKeygenImport(k *Keydgen) error {

	if _, err := k.GenerateKey(); err != nil {
		return err
	}

	pub, err := k.MarshalPublicKey()
	if err != nil {
		return err
	}

	tmpFile, err := ioutil.TempFile("", "keydgen_test")
	if err != nil {
		return err
	}

	if err := writeKeyToFile(k, tmpFile.Name()); err != nil {
		return err
	}
	defer func() {
		os.Remove(tmpFile.Name())
		os.Remove(tmpFile.Name() + ".pub")
	}()

	e, _, err := expect.Spawn("ssh-keygen -y -f "+tmpFile.Name(), -1)
	if err != nil {
		return err
	}
	defer e.Close()

	expr := regexp.MustCompilePOSIX(regexp.QuoteMeta(string(pub)))
	if _, _, eErr := e.Expect(expr, -1); eErr != nil {
		err = errors.New("unable to verify generated public key with ssh-keygen")
	}

	return err

}

func TestKeydgen_GenerateKey_DSA(t *testing.T) {

	cases := []keygenCase{
		{
			name:          "InvalidKeyLength",
			expectFailure: true,
			keydgen: &Keydgen{
				Type: DSA,
				Bits: 100,
				Seed: []byte("keydgen"),
			},
		},
		{
			name: "1024",
			keydgen: &Keydgen{
				Type: DSA,
				Bits: 1024,
				Seed: []byte("keydgen"),
			},
		},
		{
			name: "2048",
			keydgen: &Keydgen{
				Type: DSA,
				Bits: 2048,
				Seed: []byte("keydgen"),
			},
		},
		{
			name: "3072",
			keydgen: &Keydgen{
				Type: DSA,
				Bits: 3072,
				Seed: []byte("keydgen"),
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			start := time.Now()
			fmt.Print(t.Name())
			if err := testKeygenImport(c.keydgen); err != nil && !c.expectFailure {
				t.Fatal(err)
			}
			fmt.Printf(" PASS %s\n", time.Since(start))
		})
	}

}

func TestKeydgen_GenerateKey_ECDSA(t *testing.T) {

	cases := []keygenCase{
		{
			name:          "InvalidCurve",
			expectFailure: true,
			keydgen: &Keydgen{
				Type:  ECDSA,
				Curve: 128,
				Seed:  []byte("keydgen"),
			},
		},
		{
			name: "256",
			keydgen: &Keydgen{
				Type:  ECDSA,
				Curve: 256,
				Seed:  []byte("keydgen"),
			},
		},
		{
			name: "384",
			keydgen: &Keydgen{
				Type:  ECDSA,
				Curve: 384,
				Seed:  []byte("keydgen"),
			},
		},
		{
			name: "521",
			keydgen: &Keydgen{
				Type:  ECDSA,
				Curve: 521,
				Seed:  []byte("keydgen"),
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			start := time.Now()
			fmt.Print(t.Name())
			if err := testKeygenImport(c.keydgen); err != nil && !c.expectFailure {
				t.Fatal(err)
			}
			fmt.Printf(" PASS %s\n", time.Since(start))
		})
	}

}

func TestKeydgen_GenerateKey_RSA(t *testing.T) {

	cases := []keygenCase{
		{
			name: "2048",
			keydgen: &Keydgen{
				Type: RSA,
				Bits: 2048,
				Seed: []byte("keydgen"),
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			start := time.Now()
			fmt.Print(t.Name())
			if err := testKeygenImport(c.keydgen); err != nil && !c.expectFailure {
				t.Fatal(err)
			}
			fmt.Printf(" PASS %s\n", time.Since(start))
		})
	}

}

func TestKeydgen_GenerateKey_ED25519(t *testing.T) {

	cases := []keygenCase{
		{
			keydgen: &Keydgen{
				Type: ED25519,
				Seed: []byte("keydgen"),
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			start := time.Now()
			fmt.Print(t.Name())
			if err := testKeygenImport(c.keydgen); err != nil && !c.expectFailure {
				t.Fatal(err)
			}
			fmt.Printf(" PASS %s\n", time.Since(start))
		})
	}

}
