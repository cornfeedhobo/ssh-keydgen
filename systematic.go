package main

import (
	"crypto/sha512"

	"golang.org/x/crypto/ripemd160"
	"golang.org/x/crypto/scrypt"
)

type systematic struct {
	seed []byte
	salt []byte
}

func (s *systematic) Read(p []byte) (int, error) {

	var sha = sha512.New()
	if _, err := sha.Write(s.seed); err != nil {
		return 0, err
	}
	s.seed = sha.Sum(nil)

	var ripe = ripemd160.New()
	if _, err := ripe.Write(s.salt); err != nil {
		return 0, err
	}
	s.salt = ripe.Sum(nil)

	dk, err := scrypt.Key(s.seed, s.salt, 32768, 8, 1, len(p))
	if err != nil {
		return 0, err
	}
	return copy(p, dk), nil

}
