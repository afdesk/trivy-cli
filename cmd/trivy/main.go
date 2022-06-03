package main

import (
	"log"

	"github.com/afdesk/trivy-cli/pkg/commands"
)

var (
	version = "dev"
)

func main() {
	app := commands.NewApp(version)
	if err := app.Execute(); err != nil {
		log.Fatal(err)
	}
}
