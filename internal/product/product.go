// SPDX-License-Identifier: GPL-3.0-or-later

// Package product holds the product name and build metadata.
//
// The name is a working title and may change before the first public
// release. Every other package must take the name from here instead of
// hard-coding it.
package product

// Name is the short name: the command, directories and service names.
const Name = "fngx"

// FullName is the human-readable product name.
const FullName = "Fornex NGX"

// Build metadata. Release builds set these with -ldflags "-X ...".
var (
	Version = "dev"
	Commit  = "unknown"
)
