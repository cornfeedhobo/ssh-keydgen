package main

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strings"

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

	app.Name = "ssh-keydgen"
	app.Version = "0.3.0"

	app.Author = "cornfeedhobo"
	app.Copyright = "(c) 2018 cornfeedhobo"

	app.HelpName = "ssh-keydgen"
	app.Usage = "deterministic authentication key generation"

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
		cli.StringFlag{
			Name:  "w",
			Usage: "Provides the deterministic `seed`",
		},
	}

	app.Action = func(ctx *cli.Context) (err error) {

		ctx.Set("t", strings.ToLower(ctx.String("t")))

		if ctx.Bool("a") && os.Getenv("SSH_AUTH_SOCK") == "" {
			return newError("SSH_AUTH_SOCK not set")
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

		WorkFactor = ctx.Int("n")

		var keydgen = &Keydgen{
			Seed:  seedphrase,
			Type:  KeyType(strings.ToLower(ctx.String("t"))),
			Bits:  ctx.Int("b"),
			Curve: ctx.Int("c"),
		}

		privateKey, err := keydgen.GenerateKey()
		if err != nil {
			return newError("Error generating key: " + err.Error())
		}

		if ctx.Bool("a") {
			err = addKeyToAgent(privateKey)
		} else {
			err = writeKeyToFile(keydgen, filename)
		}

		return

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

func getFilename(ctx *cli.Context) (filename string, err error) {

	filename = ctx.String("f")
	if !ctx.Bool("a") && filename == "" {
		var home string
		home, err = homedir.Dir()
		if err != nil {
			err = newBug(err.Error())
			return
		}

		fmt.Sprintf("Enter file in which to save the key (%s/.ssh/id_%s): ", home, ctx.String("t"))
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

		seed = []byte(ctx.String("w"))
		for len(seed) == 0 {
			fmt.Print("Enter seedphrase (can not be empty): ")
			seed, err = terminal.ReadPassword(int(os.Stdin.Fd()))
			fmt.Print("\n")
			if err != nil {
				break
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

	// because client.Add() requires a pointer for all types
	if k, ok := privateKey.(ed25519.PrivateKey); ok {
		privateKey = &k
	}

	return agent.NewClient(conn).Add(agent.AddedKey{PrivateKey: privateKey})

}

func writeKeyToFile(k *Keydgen, filename string) error {

	privBytes, err := k.MarshalPrivateKey()
	if err != nil {
		return newError(err.Error())
	}

	pubBytes, err := k.MarshalPublicKey()
	if err != nil {
		return newError(err.Error())
	}

	if err := ioutil.WriteFile(filename, privBytes, 0600); err != nil {
		return newError(err.Error())
	}

	if err := ioutil.WriteFile(filename+".pub", pubBytes, 0600); err != nil {
		return newError(err.Error())
	}

	return nil

}
