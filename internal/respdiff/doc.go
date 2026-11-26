// SPDX-License-Identifier: GPL-3.0-or-later

// Package respdiff records how a server answers HTTP and HTTPS requests
// for a list of domains and compares two such records. It is the check
// behind "every domain answers the same after the migration" (I-10,
// I-11, Q-5) and is reused after mode switches and upgrades.
//
// # Snapshot
//
// [Take] requests every target over each scheme from one server address:
// it connects to that IP and sends the domain in the Host header and in
// TLS SNI, so DNS is never consulted. Redirects are not followed. For
// every response it records the status, the response headers (Set-Cookie
// values are dropped, see below), the length and SHA-256 of the decoded
// body, TLS details and timing. A [Snapshot] is stored as one JSON file.
//
// # Safety towards the probed server
//
// The server under test is usually a production server (N-1: up to
// 10,000 domains). Therefore:
//   - only GET or HEAD requests are sent, without cookies, credentials
//     or a request body, and redirects are not followed;
//   - the number of requests in flight and the request rate are bounded;
//     every request goes to the same IP, so the rate limit is a per-IP
//     limit;
//   - every request has a deadline and at most MaxBody bytes of a body
//     are read, so slow or huge responses cost bounded time and memory;
//   - proxies from the environment are ignored and nothing is sent
//     anywhere except the given IP (N-7).
//
// # Comparison and noise
//
// [Compare] matches results by target and scheme and reports each
// difference with a [Severity]. Data that changes between two identical
// requests is normalized away according to [Rules]; see
// [DefaultRulesJSON] for the defaults and the reasons behind them.
//
// Body normalization (CSRF tokens, nonces) has to run when the body is
// read, because snapshots store hashes, not bodies: storing up to
// 20,000 bodies per snapshot would cost gigabytes. Both snapshots must
// therefore be taken with the same body rules; [Compare] falls back to
// the raw hash and says so when they differ.
//
// A body that differs only because the page is dynamic cannot be told
// from a real change by one request. A snapshot taken with Repeat >= 2
// requests each target again and marks bodies that changed between the
// requests as unstable. Body changes are critical when the baseline
// proved the body stable, informational when it proved it unstable, and
// warnings otherwise; a changed page title or a more than twofold change
// in size is critical either way, and so is an answer that was stable
// before and varies after.
package respdiff
