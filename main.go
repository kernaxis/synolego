// Let's Encrypt client to go!
// CLI application for generating Let's Encrypt certificates using the ACME package.
package main

import (
	"fmt"
	"os"
	"runtime"

	"github.com/go-acme/lego/v4/log"
	"github.com/kernaxis/synolego/internal/cmd"
	"github.com/urfave/cli/v2"
)

var version = "dev"

func getVersion() string {
	return version
}

func main() {

	app := cli.NewApp()
	app.Name = "synolego"
	app.HelpName = "synolego"
	app.Usage = "Let's Encrypt client written in Go, for synology"

	app.Version = getVersion()
	cli.VersionPrinter = func(c *cli.Context) {
		fmt.Printf("synolego version %s %s/%s\n", c.App.Version, runtime.GOOS, runtime.GOARCH)
	}

	var defaultPath = "/usr/local/share/synolego"

	app.Flags = cmd.CreateFlags(defaultPath)

	app.Commands = cmd.CreateCommands()

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
