package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strings"

	"github.com/mitchellh/go-homedir"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/terminal"
	"gopkg.in/urfave/cli.v1"
)

const (
	errCode = 1
	bugCode = 5
)

func main() {
	app := cli.NewApp()

	app.Name = "ssh-keydgen"
	app.Version = "0.2.0"

	app.Author = "cornfeedhobo"
	app.Copyright = "(c) 2017 cornfeedhobo"

	app.HelpName = "ssh-keydgen"
	app.Usage = "Deterministic authentication key generation"

	app.HideHelp = true
	app.HideVersion = true

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "t",
			Value: "ed25519",
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
		cli.IntFlag{
			Name:  "n",
			Value: 16384,
			Usage: "Specifies the work `factor`, or \"difficulty\", applied to the key generation function.",
		},
		cli.StringFlag{
			Name:  "f",
			Usage: "Specifies the `filename` of the key file.",
		},
		cli.BoolFlag{
			Name:  "a",
			Usage: "Add the generated key to the running ssh-agent.",
		},
	}

	app.Action = func(ctx *cli.Context) (err error) {

		if ctx.Bool("a") && os.Getenv("SSH_AUTH_SOCK") == "" {
			return cli.NewExitError("SSH_AUTH_SOCK not set", errCode)
		}

		WorkFactor = ctx.Int("n")

		var keydgen = &Keydgen{
			Type:  KeyType(strings.ToLower(ctx.String("t"))),
			Bits:  ctx.Int("b"),
			Curve: ctx.Int("c"),
		}

		fmt.Println("Generating public/private " + keydgen.Type + " key pair")

		// Get the output filename ...
		if !ctx.Bool("a") && ctx.String("f") == "" {
			filename, err := getFilename(keydgen.Type)
			if err != nil {
				return cli.NewExitError(err.Error(), bugCode)
			}
			if err := ctx.Set("f", filename); err != nil {
				return cli.NewExitError(err.Error(), bugCode)
			}
		}

		// Get the password ...
		keydgen.Seed, err = getPassword()
		if err != nil {
			return cli.NewExitError(err.Error(), bugCode)
		}

		// Generate private key ...
		privateKey, err := keydgen.GenerateKey()
		if err != nil {
			return cli.NewExitError(err.Error(), errCode)
		}

		if ctx.Bool("a") { // Add to running ssh-agent ...

			if err := addToAgent(privateKey); err != nil {
				return cli.NewExitError(err.Error(), errCode)
			}

		} else { // Write to file ...

			privBytes, err := keydgen.MarshalPrivateKey()
			if err != nil {
				return cli.NewExitError(err.Error(), errCode)
			}
			if err := ioutil.WriteFile(ctx.String("f"), privBytes, 0600); err != nil {
				return cli.NewExitError(err.Error(), errCode)
			}

			pubBytes, err := keydgen.MarshalPublicKey()
			if err != nil {
				return cli.NewExitError(err.Error(), errCode)
			}
			if err := ioutil.WriteFile(ctx.String("f")+".pub", pubBytes, 0600); err != nil {
				return cli.NewExitError(err.Error(), errCode)
			}

		}

		return nil

	}

	app.Run(os.Args)

}

func init() {
	cli.AppHelpTemplate = `NAME:
   {{.Name}}{{if .Usage}} - {{.Usage}}{{end}}

USAGE:
   {{if .UsageText}}{{.UsageText}}{{else}}{{.HelpName}}{{if .VisibleFlags}}{{range $index, $option := .VisibleFlags}}{{if $index}}{{end}} [-{{$option.GetName}}]{{end}}{{end}}{{end}}{{if .Version}}{{if not .HideVersion}}

VERSION:
   {{.Version}}{{end}}{{end}}{{if .Description}}

DESCRIPTION:
   {{.Description}}{{end}}{{if len .Authors}}

AUTHOR{{with $length := len .Authors}}{{if ne 1 $length}}S{{end}}{{end}}:
   {{range $index, $author := .Authors}}{{if $index}}
   {{end}}{{$author}}{{end}}{{end}}{{if .VisibleFlags}}

OPTIONS:
   {{range $index, $option := .VisibleFlags}}{{if $index}}
   {{end}}{{$option}}{{end}}{{end}}{{if .Copyright}}

COPYRIGHT:
   {{.Copyright}}{{end}}
`
}

func getFilename(keyType KeyType) (filename string, err error) {

	var home string
	home, err = homedir.Dir()
	if err != nil {
		return
	}

	fmt.Printf("Enter file in which to save the key (%s/.ssh/id_%s): ", home, keyType)
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		filename = scanner.Text()
		break
	}
	err = scanner.Err()

	return

}

func getPassword() (password []byte, err error) {

	// handle piped in password
	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) == 0 {
		return ioutil.ReadAll(os.Stdin)
	}

	// handle prompting
	fmt.Print("Enter passphrase: ")
	password, err = terminal.ReadPassword(int(os.Stdin.Fd()))
	fmt.Print("\n")

	return

}

func addToAgent(privateKey interface{}) error {

	conn, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
	if err != nil {
		return err
	}

	if k, ok := privateKey.(ed25519.PrivateKey); ok { // because client.Add() requires a pointer for all types
		privateKey = &k
	}

	return agent.NewClient(conn).Add(agent.AddedKey{PrivateKey: privateKey})

}
