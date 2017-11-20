package main

import (
	"crypto/sha512"

	"golang.org/x/crypto/ripemd160"
	"golang.org/x/crypto/scrypt"
)

var WorkFactor int

type Deterministic struct {
	seed []byte
	salt []byte
}

func (d *Deterministic) Read(p []byte) (int, error) {

	var sha = sha512.New()
	if _, err := sha.Write(d.seed); err != nil {
		return 0, err
	}
	d.seed = sha.Sum(nil)

	var ripe = ripemd160.New()
	if _, err := ripe.Write(d.salt); err != nil {
		return 0, err
	}
	d.salt = ripe.Sum(nil)

	dk, err := scrypt.Key(d.seed, d.salt, WorkFactor, 8, 1, len(p))
	if err != nil {
		return 0, err
	}
	return copy(p, dk), nil

}
