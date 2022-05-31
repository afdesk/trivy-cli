package main

import (
	"log"

	"github.com/afdesk/trivy-cli/pkg/commands"
)

var (
	version = "dev"
)

func main() {
	app := commands.Execute(version)
	if err := app.Execute(); err != nil {
		log.Fatal(err)
	}
}
