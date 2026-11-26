// SPDX-License-Identifier: GPL-3.0-or-later

// Package render generates the nginx configuration of a server from
// templates (A-4, T-1, T-3, T-5, T-6, T-7, M-1, M-6, M-7, M-9, N-6).
//
// The input is a [Server] and a list of [Domain] values. They describe what
// the generator needs; filling them from cPanel data (A-1) is the job of the
// cPanel adapter. The output is an apply.Change for internal/apply:
//
//	nginx.conf                  main file: pid, logs, default servers,
//	                            "include vhosts/*.conf"
//	snippets/proxy.conf         request headers for Apache (M-6)
//	snippets/fastcgi.conf       FastCGI parameters for PHP-FPM (M-9)
//	apps/<template>.conf        application templates (T-2), if any
//	vhosts/<domain>.conf        one unit per domain (N-4) ...
//	domains/<domain>/*.conf     ... with its admin and client include files
//
// Every include uses a path relative to the main file, so the set tests and
// runs the same in any directory (see internal/apply).
//
// # Templates
//
// Each mode has a vhost template written for this project from the nginx
// documentation (links are in the templates). The admin can replace any of
// them with an own template in a separate directory (T-3). Templates are Go
// text/template files; the data they receive and the helper functions are
// described in docs/templates.md (T-5).
//
// # Safety
//
// Templates never see input strings: every printable field is an [Arg],
// which is checked when it is built and printed as exactly one nginx token
// (N-6). Domain and user names are checked by internal/model, paths by a
// strict character set, client rules are taken only from
// userrules.Rules.Format. Admin texts (T-6) are trusted, and each goes into
// its own include file, where nginx parses it as a separate file so that it
// cannot close the server block around it. Whether nginx accepts the result
// is checked by internal/apply with nginx -t (T-9).
package render
