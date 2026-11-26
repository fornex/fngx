// Package apply validates generated nginx configuration and makes it live
// (A-4, A-5, A-6, T-9, N-3, N-4, N-5, N-6, N-9).
//
// # Layout
//
// All state lives under Config.Root:
//
//	Root/
//	  .lock                     cross-process lock (A-6)
//	  .pending                  marker: a swap happened, reload not confirmed
//	  live -> generations/gen-000000042
//	  generations/
//	    gen-000000041/          previous set, kept for rollback
//	    gen-000000042/          live set
//	      .manifest.json        which files belong to which unit
//	      nginx.conf            Config.MainFile
//	      ...
//
// A generation is a complete, self-contained configuration tree. It is
// written once and never modified after it has been tested: unchanged files
// are hard-linked from the previous generation, changed files are written
// fresh. nginx is expected to run with "-c Root/live/nginx.conf", and the
// main file must reference the rest of the tree with paths relative to its
// own directory (for example "include vhosts/*.conf;").
//
// # Apply
//
//  1. Take the lock; finish or clean up anything a crashed run left behind.
//  2. Build the candidate in a new generation directory. Live files are not
//     touched (A-4).
//  3. Run "nginx -t -c <candidate>/nginx.conf". Because includes are relative,
//     the test sees exactly the bytes that will become live.
//  4. If the test fails and the change allows it, find the units (domains)
//     that break the test and keep their previous version, so the other units
//     still apply (N-4). The final set is always re-tested as a whole.
//  5. fsync the candidate, then switch Root/live atomically: a new symlink is
//     created next to it and renamed over it.
//  6. Reload nginx (N-5). If the reload command fails, point Root/live back to
//     the previous generation and reload again.
//  7. Remove old generations beyond Config.Keep.
//
// The nginx command-line switches used here (-t, -c, -p, -s reload) are
// described at https://nginx.org/en/docs/switches.html, and reload semantics
// at https://nginx.org/en/docs/control.html.
package apply
