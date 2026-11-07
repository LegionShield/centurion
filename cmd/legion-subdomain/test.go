package main

import (
	"github.com/LegionShield/legion-subdomain/v2/pkg/core/options"
	"github.com/LegionShield/legion-subdomain/v2/pkg/runner"
	"github.com/urfave/cli/v2"
)

var testCommand = &cli.Command{
	Name:  string(options.TestType),
	Usage: "Test maximum send speed of local NIC",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:    "eth",
			Aliases: []string{"e"},
			Usage:   "Specify NIC name to get its details",
		},
	},
	Action: func(c *cli.Context) error {
		ethTable := options.GetDeviceConfig(nil)
		runner.TestSpeed(ethTable)
		return nil
	},
}
