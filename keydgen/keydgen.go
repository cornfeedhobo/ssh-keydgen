package keydgen

import (
	"bytes"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"io"
	"math/big"

	"github.com/mikesmitty/edkey"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/ssh"
)

// These constants represent the support key types
const (
	DSA     = "dsa"
	ECDSA   = "ecdsa"
	RSA     = "rsa"
	ED25519 = "ed25519"
)

var (
	// ErrUnsupportedKeyType is the error returned when an unsupported key type is requested
	ErrUnsupportedKeyType = errors.New("unsupported key type")

	// ErrUnsupportedKeyLength is the error returned when an invalid key length is supplied for the key type
	ErrUnsupportedKeyLength = errors.New("invalid key length")

	// ErrUnsuppontedCurve is the error returned when generating an ECDSA key and an invalid curve is requested
	ErrUnsuppontedCurve = errors.New("only P-256, P-384 and P-521 EC keys are supported")
)

// Keydgen represents a deterministic OpenSSH key generator
type Keydgen struct {
	Type  string
	Bits  uint16
	Curve uint16
	//Seed  []byte
	//Rounds  uint32
	//Time    uint32
	//Memory  uint32
	//Threads uint8

	privateKey interface{}
}

func (k *Keydgen) generateDSA(rand io.Reader) (interface{}, error) {

	var (
		size   dsa.ParameterSizes
		params = new(dsa.Parameters)
		key    = new(dsa.PrivateKey)
	)

	switch k.Bits {
	case 1024:
		size = dsa.L1024N160
	case 2048:
		size = dsa.L2048N256
	case 3072:
		size = dsa.L3072N256
	default:
		return nil, ErrUnsupportedKeyLength
	}

	if err := dsa.GenerateParameters(params, rand, size); err != nil {
		return nil, err
	}
	key.Parameters = *params

	err := dsa.GenerateKey(key, rand)

	return key, err

}

func (k *Keydgen) generateECDSA(rand io.Reader) (interface{}, error) {

	var c elliptic.Curve

	switch k.Curve {
	case 256:
		c = elliptic.P256()
	case 384:
		c = elliptic.P384()
	case 521:
		c = elliptic.P521()
	default:
		return nil, ErrUnsuppontedCurve
	}

	return ecdsa.GenerateKey(c, rand)

}

// GenerateKey generates and/or returns a private key
func (k *Keydgen) GenerateKey(rand io.Reader) (key interface{}, err error) {

	if k.privateKey != nil {
		return k.privateKey, nil
	}

	switch k.Type {
	case DSA:
		k.privateKey, err = k.generateDSA(rand)
	case ECDSA:
		k.privateKey, err = k.generateECDSA(rand)
	case RSA:
		k.privateKey, err = rsa.GenerateKey(rand, int(k.Bits))
	case ED25519:
		_, k.privateKey, err = ed25519.GenerateKey(rand)
	default:
		return nil, ErrUnsupportedKeyType
	}

	return k.privateKey, err

}

// MarshalPrivateKey returns an OpenSSH formatted private key
func (k *Keydgen) MarshalPrivateKey() ([]byte, error) {

	if k.privateKey == nil {
		panic("private key not hasn't been generated yet")
	}

	var (
		block *pem.Block
		buf   = bytes.NewBuffer(nil)
		err   error
	)

	switch k.Type {

	case DSA:
		block = &pem.Block{Type: "DSA PRIVATE KEY"}
		block.Bytes, err = asn1.Marshal(struct {
			Version       int
			P, Q, G, Y, X *big.Int
		}{
			P: k.privateKey.(*dsa.PrivateKey).P,
			Q: k.privateKey.(*dsa.PrivateKey).Q,
			G: k.privateKey.(*dsa.PrivateKey).G,
			Y: k.privateKey.(*dsa.PrivateKey).Y,
			X: k.privateKey.(*dsa.PrivateKey).X,
		})

	case ECDSA:
		block = &pem.Block{Type: "EC PRIVATE KEY"}
		block.Bytes, err = x509.MarshalECPrivateKey(k.privateKey.(*ecdsa.PrivateKey))

	case RSA:
		block = &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(k.privateKey.(*rsa.PrivateKey)),
		}

	case ED25519:
		block = &pem.Block{
			Type:  "OPENSSH PRIVATE KEY",
			Bytes: edkey.MarshalED25519PrivateKey(k.privateKey.(ed25519.PrivateKey)),
		}

	default:
		return nil, ErrUnsupportedKeyType

	}

	if err := pem.Encode(buf, block); err != nil {
		return nil, err
	}

	return buf.Bytes(), err

}

// MarshalPublicKey returns an OpenSSH formatted public key
func (k *Keydgen) MarshalPublicKey() ([]byte, error) {

	if k.privateKey == nil {
		panic("private key has not been generated yet")
	}

	var (
		pubKey ssh.PublicKey
		err    error
	)

	switch k.Type {

	case DSA:
		var pub = &k.privateKey.(*dsa.PrivateKey).PublicKey
		pubKey, err = ssh.NewPublicKey(pub)

	case ECDSA:
		var pub = &k.privateKey.(*ecdsa.PrivateKey).PublicKey
		pubKey, err = ssh.NewPublicKey(pub)

	case RSA:
		var pub = &k.privateKey.(*rsa.PrivateKey).PublicKey
		pubKey, err = ssh.NewPublicKey(pub)

	case ED25519:
		var pub = k.privateKey.(ed25519.PrivateKey).Public().(ed25519.PublicKey)
		pubKey, err = ssh.NewPublicKey(pub)

	default:
		err = ErrUnsupportedKeyType

	}

	return ssh.MarshalAuthorizedKey(pubKey), err

}
