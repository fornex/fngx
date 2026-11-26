// Package model defines the settings model: three layers of settings
// (server, user, domain) with inheritance (A-3), the per-domain mode
// (M-3, M-4, M-5), per-setting admin permissions (U-1, U-8, A-7), and
// validation of every value that can come from a client (N-6).
//
// The package is pure: it does no I/O. Package model/store keeps the
// layers in plain text files.
//
// # Layers
//
// A setting is resolved from the most specific layer that sets it:
// domain, then user, then server, then the built-in default. A nil field
// in [Settings] means "not set on this layer, inherit". The admin can
// lock a setting on the server; a locked setting always takes the server
// value (or the built-in default) and lower layers are ignored.
//
// # Adding a setting
//
//  1. Add a pointer field with a JSON tag to [Settings].
//  2. Add a [Field] constant equal to the JSON tag and list it in [Fields].
//  3. Add its built-in default value and access, a line in [Resolve],
//     [Settings.Validate] and [Settings.Diff], and a field in [Effective].
//
// TestFieldRegistry fails if step 2 is forgotten.
//
// # Safety
//
// Values are checked against narrow character sets so they are safe to
// use as file names and inside nginx configuration. They must still never
// be passed through a shell (N-6).
package model
