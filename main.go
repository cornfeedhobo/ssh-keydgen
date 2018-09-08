package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/cornfeedhobo/ssh-keydgen/keygen"
	"github.com/cornfeedhobo/ssh-keydgen/slowseeder"
	"github.com/mitchellh/go-homedir"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/terminal"
	"gopkg.in/urfave/cli.v1"
)

func newError(message string) error {
	return cli.NewExitError(message, 1)
}

func newBug(message string) error {
	return cli.NewExitError(message, 13)
}

func main() {
	app := cli.NewApp()

	app.Name = "ssh-keygen"
	app.Version = "0.4.0"

	app.Author = "cornfeedhobo"
	app.Copyright = "(c) 2018 cornfeedhobo"

	app.HelpName = "ssh-keygen"
	app.Usage = "deterministic authentication key generation"
	app.UsageText = "ssh-keygen [[-t <type>] [-b <bits>] [-c <curve>] [-f <filename>] [-a <rounds>] [--at <time>] [--am <memory>] [--as <seedphrase>] [--aa]]"

	app.HideHelp = true
	app.HideVersion = true

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "t",
			Value: "rsa",
			Usage: "Specifies the `type` of key to create. The possible values are \"dsa\", \"ecdsa\", \"rsa\", or \"ed25519\".",
		},
		cli.IntFlag{
			Name:  "b",
			Value: 2048,
			Usage: "Specifies the number of `bits` in the key to create. Possible values are restricted by key type.",
		},
		cli.IntFlag{
			Name:  "c",
			Value: 256,
			Usage: "Specifies the elliptic `curve` to use. The possible values are 256, 384, or 521.",
		},
		cli.StringFlag{
			Name:  "f",
			Usage: "Specifies the `filename` of the key file.",
		},
		cli.IntFlag{
			Name:  "a",
			Value: 1000,
			Usage: "Specifies the number of hashing `rounds` applied during key generation.",
		},
		cli.UintFlag{
			Name:  "at",
			Value: 3,
			Usage: "Specifies the `time` parameter for the Argon2 function.",
		},
		cli.UintFlag{
			Name:  "am",
			Value: 1024 * 16,
			Usage: "Specifies the `memory` parameter for the Argon2 function.",
		},
		cli.UintFlag{
			Name:  "ap",
			Value: 1,
			Usage: "Specifies the `threads` or parallelism for the Argon2 function.",
		},
		cli.StringFlag{
			Name:  "as",
			Usage: "Provides the deterministic `seedphrase`.",
		},
		cli.BoolFlag{
			Name:  "aa",
			Usage: "Add the generated key to the running ssh-agent.",
		},
	}

	app.Action = appAction

	app.Run(os.Args)

}

func appAction(ctx *cli.Context) (err error) {

	ctx.Set("t", strings.ToLower(ctx.String("t")))

	if ctx.Bool("aa") && os.Getenv("SSH_AUTH_SOCK") == "" {
		return newError("SSH_AUTH_SOCK not set, unable to find running agent")
	}

	fmt.Println("Generating public/private " + ctx.String("t") + " key pair")

	var seedphrase []byte
	if seedphrase, err = getSeedphrase(ctx); err != nil {
		return
	}

	var filename string
	if filename, err = getFilename(ctx); err != nil {
		return
	}

	var keydgen = &keygen.Keydgen{
		Type:  ctx.String("t"),
		Bits:  uint16(ctx.Int("b")),
		Curve: uint16(ctx.Int("c")),
	}

	rand, err := slowseeder.New(seedphrase, uint32(ctx.Int("a")), uint32(ctx.Uint("at")), uint32(ctx.Uint("am")), uint8(ctx.Uint("ap")))
	if err != nil {
		return newError("Error with supplied parameters: " + err.Error())
	}

	privateKey, err := keydgen.GenerateKey(rand)
	if err != nil {
		return newError("Error generating key: " + err.Error())
	}

	if ctx.Bool("aa") {
		err = addKeyToAgent(privateKey)
	} else {
		err = writeKeyToFile(keydgen, filename)
	}

	return

}

func getFilename(ctx *cli.Context) (filename string, err error) {

	filename = ctx.String("f")
	if !ctx.Bool("aa") && filename == "" {
		var home string
		home, err = homedir.Dir()
		if err != nil {
			err = newBug(err.Error())
			return
		}

		fmt.Printf("Enter file in which to save the key (%s/.ssh/id_%s): ", home, ctx.String("t"))
		if _, err = fmt.Scanln(&filename); err != nil {
			return
		}
	}

	abspath, err := filepath.Abs(filename)
	if err != nil {
		err = newError(err.Error())
		return
	}

	_, privStatErr := os.Stat(abspath)
	_, pubStatErr := os.Stat(abspath + ".pub")
	if privStatErr == nil || pubStatErr == nil {

		var strbool string
		fmt.Println(filename + " already exists.")
		fmt.Print("Overwrite (y/n)? ")
		if _, err = fmt.Scanln(&strbool); err != nil {
			return
		}

		if strings.TrimSpace(strings.ToLower(strbool)) == "y" {

			err = os.Remove(abspath)
			if err != nil && !os.IsNotExist(err) {
				return
			}

			err = os.Remove(abspath + ".pub")
			if err != nil && !os.IsNotExist(err) {
				return
			}

		} else {
			err = newError("")
		}
	}

	return

}

func getSeedphrase(ctx *cli.Context) (seed []byte, err error) {

	stat, _ := os.Stdin.Stat()

	if (stat.Mode() & os.ModeCharDevice) == 0 {

		seed, err = ioutil.ReadAll(os.Stdin)

	} else {

		var (
			equal bool
			fd    = int(os.Stdin.Fd())
		)

		for !equal {

			seed = []byte(ctx.String("as"))
			for len(seed) == 0 {
				fmt.Print("Enter seedphrase (can not be empty): ")
				seed, err = terminal.ReadPassword(fd)
				fmt.Print("\n")
				if err != nil {
					break
				}
			}

			verify := []byte(ctx.String("as"))
			for len(verify) == 0 {
				fmt.Print("Verify seedphrase (can not be empty): ")
				verify, err = terminal.ReadPassword(fd)
				fmt.Print("\n")
				if err != nil {
					break
				}
			}

			equal = bytes.Equal(seed, verify)
			if !equal {
				fmt.Print("\nerror: seedphrases did not match\n\n")
			}

		}

	}

	return

}

func addKeyToAgent(privateKey interface{}) error {

	conn, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
	if err != nil {
		return err
	}

	// because agent.Client.Add() requires a pointer for all types
	if k, ok := privateKey.(ed25519.PrivateKey); ok {
		privateKey = &k
	}

	return agent.NewClient(conn).Add(agent.AddedKey{PrivateKey: privateKey})

}

func writeKeyToFile(k *keygen.Keydgen, filename string) error {

	privBytes, err := k.MarshalPrivateKey()
	if err != nil {
		return newError(err.Error())
	}

	pubBytes, err := k.MarshalPublicKey()
	if err != nil {
		return newError(err.Error())
	}

	err = ioutil.WriteFile(filename, privBytes, 0600)
	if err != nil {
		return newError(err.Error())
	}

	err = ioutil.WriteFile(filename+".pub", pubBytes, 0600)
	if err != nil {
		return newError(err.Error())
	}

	return nil

}
