// Package cli implements the command-line interface (U-11).
package cli

import (
	"fmt"
	"io"

	"github.com/fornex/fngx/internal/product"
)

// Exit codes.
const (
	ExitOK    = 0
	ExitError = 1
	ExitUsage = 2
)

type command struct {
	name    string
	summary string
	run     func(args []string, stdout, stderr io.Writer) int
}

func commands() []command {
	return []command{
		{name: "help", summary: "Show this help", run: runHelp},
		{name: "version", summary: "Print version information", run: runVersion},
	}
}

// Run executes the command line and returns the process exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return ExitUsage
	}
	name := args[0]
	switch name {
	case "-h", "--help":
		name = "help"
	case "-v", "--version":
		name = "version"
	}
	for _, c := range commands() {
		if c.name == name {
			return c.run(args[1:], stdout, stderr)
		}
	}
	fmt.Fprintf(stderr, "%s: unknown command %q\n\n", product.Name, args[0])
	usage(stderr)
	return ExitUsage
}

func usage(w io.Writer) {
	fmt.Fprintf(w, "Usage: %s <command> [arguments]\n\nCommands:\n", product.Name)
	for _, c := range commands() {
		fmt.Fprintf(w, "  %-10s %s\n", c.name, c.summary)
	}
}

func runHelp(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		fmt.Fprintf(stderr, "%s help: unexpected arguments\n", product.Name)
		return ExitUsage
	}
	usage(stdout)
	return ExitOK
}

func runVersion(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		fmt.Fprintf(stderr, "%s version: unexpected arguments\n", product.Name)
		return ExitUsage
	}
	fmt.Fprintf(stdout, "%s %s (commit %s)\n", product.Name, product.Version, product.Commit)
	return ExitOK
}
