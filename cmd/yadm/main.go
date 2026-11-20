// Command yadm manages dotfiles across a fleet of machines. See docs/design.md.
package main

import (
	"os"

	"github.com/noahkiss/yadm/internal/cli"
)

// version is set at build time with -ldflags "-X main.version=<v>".
var version = "dev"

func main() {
	os.Exit(cli.Main(os.Args[1:], os.Stdout, os.Stderr, version))
}
