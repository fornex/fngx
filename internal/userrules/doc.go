// SPDX-License-Identifier: GPL-3.0-or-later

// Package userrules validates nginx rules written by hosting clients for
// their own domains (T-7, T-8, N-6, Q-6).
//
// A client submits a small piece of nginx configuration. The package parses
// it, checks every directive against a whitelist and per-directive argument
// rules, and returns a parsed tree. Callers must include only the output of
// [Rules.Format] into a server block: it is re-serialized from the tree, so no
// raw client text reaches the configuration. The final `nginx -t` check (T-9)
// is done by the caller.
//
// Location blocks are allowed only for domains in nginx mode (T-8). The
// Validator does not know the domain's mode; callers use
// [Rules.CheckNoLocation] for domains in proxy or hybrid mode.
//
// # Syntax
//
// The accepted syntax is a strict subset of the nginx configuration syntax:
//
//   - https://nginx.org/en/docs/beginners_guide.html#conf_structure
//     (simple directives end with ';', block directives use braces,
//     '#' starts a comment that runs to the end of the line);
//   - https://nginx.org/en/docs/http/ngx_http_core_module.html#location
//     (location modifiers '=', '~', '~*', '^~');
//   - https://nginx.org/en/docs/http/ngx_http_rewrite_module.html
//     (rewrite, return);
//   - https://nginx.org/en/docs/http/ngx_http_headers_module.html
//     (add_header, expires);
//   - https://nginx.org/en/docs/http/ngx_http_access_module.html
//     (allow, deny);
//   - https://nginx.org/en/docs/syntax.html (time units);
//   - https://nginx.org/en/docs/varindex.html (variables).
//
// The documentation does not describe quoting and escaping. Where it is
// silent, this package takes the stricter reading and rejects input that
// nginx might interpret in a surprising way:
//
//   - Input must be valid UTF-8. NUL, other control characters, a carriage
//     return not followed by a line feed, and invisible formatting characters
//     (bidirectional controls, zero-width characters, byte order mark) are
//     rejected everywhere, including comments. CRLF line endings are accepted
//     and normalized to LF.
//   - Directive names are unquoted lowercase ASCII.
//   - Arguments may be bare words or quoted with '"' or "'". Outside comments
//     only ASCII and non-ASCII letters and digits are allowed; Unicode spaces
//     and punctuation lookalikes (for example a fullwidth semicolon) are
//     rejected.
//   - Inside quotes a line break or a tab is an error. The escapes \" \' and
//     \\ stand for the escaped character. The escapes \t \r and \n, which
//     nginx turns into control characters, are rejected. Any other backslash
//     is kept literally, as nginx does, so regular expressions such as \.
//     keep their meaning.
//   - In a bare word, a quote character, '#', '}' (except one closing a
//     ${name} variable) and a backslash before a space, ';', '{', '}' or '#'
//     are rejected instead of being taken literally. A closing quote must be
//     followed by whitespace, ';' or '{'.
//   - A location modifier must be a separate argument ("location = /x", not
//     "location =/x"); named locations ("@name") are not accepted.
//
// # Output
//
// [Rules.Format] prints one directive per line with four-space indentation.
// An argument is printed bare when it contains only characters that have no
// special meaning to the nginx tokenizer; otherwise it is double-quoted with
// '"' and '\' escaped. Parsing the output again yields the same tree.
package userrules
