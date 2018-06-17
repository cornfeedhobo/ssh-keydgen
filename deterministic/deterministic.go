package deterministic

import (
	"crypto/sha512"
	"errors"
	"sync"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/ripemd160"
)

// Deterministic represents a drop in replacement for a rand source
type Deterministic struct {
	seed    []byte
	salt    []byte
	rounds  uint32
	time    uint32
	memory  uint32
	threads uint8
	reads   int
	mu      *sync.RWMutex
}

// New returns a Deterministic generator suitable for use with cryptographic functions
func New(seed, salt []byte, rounds, time, memory uint32, threads uint8) (*Deterministic, error) {

	var d = &Deterministic{
		seed:    seed,
		salt:    salt,
		rounds:  rounds,
		time:    time,
		memory:  memory,
		threads: threads,
		mu:      &sync.RWMutex{},
	}

	return d, d.verifyState()

}

func (d *Deterministic) verifyState() (err error) {

	if len(d.seed) == 0 {
		err = errors.New("Deterministic seed not set")
	}

	if len(d.salt) == 0 {
		err = errors.New("Deterministic salt not set")
	}

	if d.rounds < 1 {
		err = errors.New("Deterministic seeder requires rounds > 0")
	}

	if d.time < 1 {
		err = errors.New("Deterministic seeder requires time > 0")
	}

	if d.memory < 1 {
		err = errors.New("Deterministic seeder requires memory > 0")
	}

	if d.threads < 1 {
		err = errors.New("Deterministic seeder requires threads > 0")
	}

	return

}

// Read implements a Reader that uses SHA512 and RIPEMD160 PBKDF2 to
// iteratively hash the seed and salt, which are supplied to Argon2ti to
// generate the requested "entropy"
func (d *Deterministic) Read(p []byte) (int, error) {

	if err := d.verifyState(); err != nil {
		panic(err)
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	d.reads++
	d.seed = pbkdf2.Key(d.seed, d.salt, int(d.rounds), sha512.Size, sha512.New)
	d.salt = pbkdf2.Key(d.salt, d.seed, int(d.rounds), ripemd160.Size, ripemd160.New)

	return copy(p, argon2.IDKey(d.seed, d.salt, d.time, d.memory, d.threads, uint32(len(p)))), nil
}

// Reads returns the number of reads that have occurred
func (d *Deterministic) Reads() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.reads
}
