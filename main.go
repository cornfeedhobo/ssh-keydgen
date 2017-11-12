package main

import (
	"fmt"
	"io/ioutil"
	"os"

	"golang.org/x/crypto/ssh/terminal"
	"gopkg.in/urfave/cli.v1"
)

const (
	// exit codes
	errCode = 1
	bugCode = 5

	// key types
	DSA     = "dsa"
	ECDSA   = "ecdsa"
	ED25519 = "ed25519"
	RSA     = "rsa"
)

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

func main() {
	app := cli.NewApp()

	app.Name = "ssh-keydgen"
	app.Version = "0.1.0"

	app.Author = "cornfeedhobo"
	app.Copyright = "(c) 2017 cornfeedhobo"

	app.HelpName = "ssh-keydgen"
	app.Usage = "deterministic authentication key generation"

	app.HideHelp = true
	app.HideVersion = true

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "t",
			Value: "ed25519",
			Usage: "Specifies the `type` of key to create. The possible values are “dsa”, “ecdsa”, “ed25519”, or “rsa”.",
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
			Name:  "o",
			Usage: "Specifies the `path` to output the generated key.",
		},
		cli.BoolFlag{
			Name:  "a",
			Usage: "Add the generated key to the running ssh-agent.",
		},
	}

	app.Action = keydgen

	app.Run(os.Args)

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
