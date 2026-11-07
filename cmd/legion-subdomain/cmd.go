package main

import (
	"github.com/LegionShield/legion-subdomain/v2/pkg/core"
	"github.com/LegionShield/legion-subdomain/v2/pkg/core/conf"
	"github.com/LegionShield/legion-subdomain/v2/pkg/core/gologger"
	"github.com/urfave/cli/v2"
	"os"
)

func main() {
	app := &cli.App{
		Name:    conf.AppName,
		Version: conf.Version,
		Usage:   conf.Description,
		Commands: []*cli.Command{
			enumCommand,
			verifyCommand,
			testCommand,
			deviceCommand,
		},
		Before: func(c *cli.Context) error {
			silent := false
			for _, arg := range os.Args {
				if arg == "--silent" || arg == "-s" {
					silent = true
					break
				}
			}
			if silent {
				gologger.MaxLevel = gologger.Silent
			}
			core.ShowBanner(silent)
			return nil
		},
	}
	err := app.Run(os.Args)
	if err != nil {
		gologger.Fatalf(err.Error())
	}
}
