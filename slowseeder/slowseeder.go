// Package slowseeder implements a drop-in replacement for a rand source
// intended for cryptographic key generation.
//
// It has been designed to be simple and reproducible. Generation is
// deterministic from a seed, uses multiple layered hashing functions,
// and is parameterized to easily extend the time spent during each
// iteration, making brute force and pre-computation more difficult.
//
package slowseeder

import (
	"crypto/sha512"
	"errors"
	"io"
	"sync"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/ripemd160"
)

// Reader represents a drop in replacement for a rand source
type Reader struct {
	seed, salt, key      []byte
	rounds, time, memory uint32
	threads              uint8

	mu    *sync.RWMutex
	reads int
}

// New returns a Reader generator suitable for use with cryptographic functions
func New(seed []byte, rounds, time, memory uint32, threads uint8) (io.Reader, error) {

	var err error

	if len(seed) == 0 {
		err = errors.New("Reader seed not set")
	}

	if rounds < 1 {
		err = errors.New("Reader seeder requires rounds > 0")
	}

	if time < 1 {
		err = errors.New("Reader seeder requires time > 0")
	}

	if memory < 1 {
		err = errors.New("Reader seeder requires memory > 0")
	}

	if threads < 1 {
		err = errors.New("Reader seeder requires threads > 0")
	}

	return &Reader{
		seed:    seed,
		rounds:  rounds,
		time:    time,
		memory:  memory,
		threads: threads,
		mu:      &sync.RWMutex{},
	}, err

}

// Read implements a Reader that uses SHA512 and RIPEMD160 PBKDF2 to
// iteratively hash the seed and salt, which are supplied to Argon2 to
// generate the requested "entropy"
func (r *Reader) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seed = pbkdf2.Key(r.seed, r.key, int(r.rounds), sha512.Size, sha512.New)
	r.salt = pbkdf2.Key(r.salt, r.key, int(r.reads), ripemd160.Size, ripemd160.New)
	r.key = argon2.Key(r.seed, r.salt, r.time, r.memory, r.threads, uint32(len(p)))
	return copy(p, r.key), nil
}
