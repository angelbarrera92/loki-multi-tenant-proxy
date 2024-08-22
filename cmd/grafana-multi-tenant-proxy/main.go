package main

import (
	"os"

	proxy "github.com/giantswarm/grafana-multi-tenant-proxy/internal/app/grafana-multi-tenant-proxy"
	"github.com/urfave/cli/v2"
)

var (
	version = "dev"
)

func main() {
	app := cli.NewApp()
	app.Name = "Grafana Multi Tenant Proxy"
	app.Usage = "Makes Grafana Labs applications multi tenant"
	app.Version = version
	app.Authors = []*cli.Author{
		{Name: "Angel Barrera", Email: "angel@k8spin.cloud"},
		{Name: "Pau Rosello", Email: "pau@k8spin.cloud"},
		{Name: "Herve Nicol", Email: "herve@giantswarm.io"},
		{Name: "Quentin Bisson", Email: "quentin@giantswarm.io"},
		{Name: "Marie Roque", Email: "marie@giantswarm.io"},
	}
	app.Commands = []*cli.Command{
		{
			Name:   "run",
			Usage:  "Runs the Grafana multi tenant proxy",
			Action: proxy.Serve,
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  "config",
					Usage: "Proxy configuration file",
					Value: "config.yaml",
				},
				&cli.IntFlag{
					Name:  "port",
					Usage: "Port to expose this proxy",
					Value: 3501,
				}, &cli.StringFlag{
					Name:  "log-level",
					Usage: "Log level (DEBUG, INFO, WARN, ERROR, PANIC, FATAL)",
					Value: "INFO",
				},
			},
		},
	}

	app.Run(os.Args)
}
