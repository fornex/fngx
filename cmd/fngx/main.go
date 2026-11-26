// SPDX-License-Identifier: GPL-3.0-or-later

// Command fngx manages nginx on cPanel/WHM servers.
package main

import (
	"os"

	"github.com/fornex/fngx/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
