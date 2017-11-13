package main

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"strings"

	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/ssh/agent"
	"gopkg.in/urfave/cli.v1"
)

func keydgen(ctx *cli.Context) error {

	var keyType = strings.ToLower(ctx.String("t"))
	var keyBits = ctx.Int("b")

	if keyType != DSA && keyType != ECDSA && keyType != ED25519 && keyType != RSA {
		return cli.NewExitError("unsupported key type", errCode)
	}

	if ctx.Bool("a") && os.Getenv("SSH_AUTH_SOCK") == "" {
		return cli.NewExitError("SSH_AUTH_SOCK not set", errCode)
	}

	// get the password ...
	password, err := getPassword()
	if err != nil {
		return cli.NewExitError(err.Error(), bugCode)
	}

	fmt.Println("Generating public/private " + keyType + " key pair")

	privateKey, err := generateKey(password, keyType, keyBits, ctx.Int("c"))
	if err != nil {
		return cli.NewExitError(err.Error(), errCode)
	}

	// Adding to agent ...
	if ctx.Bool("a") {

		conn, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
		if err != nil {
			return cli.NewExitError(err.Error(), bugCode)
		}

		if keyType == "ed25519" { // because client.Add() requires a pointer for all types
			k := privateKey.(ed25519.PrivateKey)
			privateKey = &k
		}

		if err := agent.NewClient(conn).Add(agent.AddedKey{PrivateKey: privateKey}); err != nil {
			return cli.NewExitError(err.Error(), errCode)
		}

		return nil

	}

	// Marshal for printing ...
	block, err := generatePEMBlock(keyType, privateKey)
	if err != nil {
		return cli.NewExitError(err.Error(), errCode)
	}

	var w io.Writer

	if ctx.String("o") != "" {

		// output to the desired file...
		var fh *os.File
		fh, err = os.Create(ctx.String("o"))
		if err != nil {
			return cli.NewExitError(err.Error(), errCode)
		}
		defer fh.Close()
		w = fh

	} else {

		// print to Stdout...
		w = os.Stdout

	}

	if err := pem.Encode(w, block); err != nil {
		return cli.NewExitError(err.Error(), bugCode)
	}

	return nil

}

func generateKey(password []byte, keyType string, keyBits int, keyCurve int) (interface{}, error) {

	var (
		r = &systematic{
			seed: password,
			salt: password,
		}
		privKey interface{}
	)

	switch keyType {

	case DSA:
		var (
			size   dsa.ParameterSizes
			params = new(dsa.Parameters)
			key    = new(dsa.PrivateKey)
		)

		switch keyBits {
		case 1024:
			size = dsa.L1024N160
		case 2048:
			size = dsa.L2048N256
		case 3072:
			size = dsa.L3072N256
		default:
			return nil, errors.New("invalid key length")
		}

		if err := dsa.GenerateParameters(params, r, size); err != nil {
			return nil, err
		}
		key.Parameters = *params

		if err := dsa.GenerateKey(key, r); err != nil {
			return nil, err
		}
		privKey = key

	case ECDSA:
		var curve elliptic.Curve
		switch keyCurve {
		case 224:
			curve = elliptic.P224()
		case 256:
			curve = elliptic.P256()
		case 384:
			curve = elliptic.P384()
		case 521:
			curve = elliptic.P521()
		default:
			return nil, errors.New("invalid curve supplied")
		}
		key, err := ecdsa.GenerateKey(curve, r)
		if err != nil {
			return nil, err
		}
		privKey = key

	case ED25519:
		_, key, err := ed25519.GenerateKey(r)
		if err != nil {
			return nil, err
		}
		privKey = key

	case RSA:
		key, err := rsa.GenerateKey(r, keyBits)
		if err != nil {
			return nil, err
		}
		privKey = key

	}

	return privKey, nil

}

func generatePEMBlock(keyType string, privateKey interface{}) (block *pem.Block, err error) {

	switch keyType {

	case DSA:
		block = &pem.Block{Type: "DSA PRIVATE KEY"}
		block.Bytes, err = asn1.Marshal(struct {
			Version       int
			P, Q, G, Y, X *big.Int
		}{
			P: privateKey.(*dsa.PrivateKey).P,
			Q: privateKey.(*dsa.PrivateKey).Q,
			G: privateKey.(*dsa.PrivateKey).G,
			Y: privateKey.(*dsa.PrivateKey).Y,
			X: privateKey.(*dsa.PrivateKey).X,
		})

	case ECDSA:
		block = &pem.Block{Type: "EC PRIVATE KEY"}
		block.Bytes, err = x509.MarshalECPrivateKey(privateKey.(*ecdsa.PrivateKey))

	case ED25519:
		block = &pem.Block{
			Type:  "OPENSSH PRIVATE KEY",
			Bytes: privateKey.(ed25519.PrivateKey),
		}

	case RSA:
		block = &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privateKey.(*rsa.PrivateKey)),
		}

	}

	return

}
