package main

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
	"math/big"

	"github.com/mikesmitty/edkey"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/ssh"
)

type KeyType string

const (
	DSA     KeyType = "dsa"
	ECDSA   KeyType = "ecdsa"
	RSA     KeyType = "rsa"
	ED25519 KeyType = "ed25519"
)

var (
	ErrUnsupportedKeyType   = errors.New("unsupported key type")
	ErrUnsupportedKeyLength = errors.New("invalid key length")
	ErrUnsuppontedCurve     = errors.New("only P-256, P-384 and P-521 EC keys are supported")
)

type Keydgen struct {
	Seed  []byte
	Type  KeyType
	Bits  int
	Curve int

	privateKey interface{}
}

func (k *Keydgen) generateDSA(d *Deterministic, bits int) (interface{}, error) {

	var (
		size   dsa.ParameterSizes
		params = new(dsa.Parameters)
		key    = new(dsa.PrivateKey)
	)

	switch bits {
	case 1024:
		size = dsa.L1024N160
	case 2048:
		// we only offer the longer version of 2048
		size = dsa.L2048N256
	case 3072:
		size = dsa.L3072N256
	default:
		return nil, ErrUnsupportedKeyLength
	}

	if err := dsa.GenerateParameters(params, d, size); err != nil {
		return nil, err
	}
	key.Parameters = *params

	err := dsa.GenerateKey(key, d)

	return key, err

}

func (k *Keydgen) generateECDSA(d *Deterministic, curve int) (interface{}, error) {

	var c elliptic.Curve

	switch curve {
	case 256:
		c = elliptic.P256()
	case 384:
		c = elliptic.P384()
	case 521:
		c = elliptic.P521()
	default:
		return nil, ErrUnsuppontedCurve
	}

	return ecdsa.GenerateKey(c, d)

}

func (k *Keydgen) GenerateKey() (key interface{}, err error) {

	var d = &Deterministic{
		seed: k.Seed,
		salt: k.Seed,
	}

	switch k.Type {
	case DSA:
		k.privateKey, err = k.generateDSA(d, k.Bits)
	case ECDSA:
		k.privateKey, err = k.generateECDSA(d, k.Curve)
	case RSA:
		k.privateKey, err = rsa.GenerateKey(d, k.Bits)
	case ED25519:
		_, k.privateKey, err = ed25519.GenerateKey(d)
	default:
		return nil, ErrUnsupportedKeyType
	}

	return k.privateKey, err

}

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
