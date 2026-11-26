# Response comparison (`respdiff`)

`fngx respdiff` checks that every domain answers the same before and after
a change of the web server: the migration from Cpnginx (I-10, I-11, Q-5),
a mode switch or an upgrade.

## Workflow

```sh
# 1. Before the change: record the baseline. By default (-repeat 2) each
#    target is requested twice to learn which pages are dynamic.
fngx respdiff snapshot -server 192.0.2.10 -targets domains.txt -out before.json

# 2. Make the change, then record again. Repeating here too finds answers
#    that alternate (for example every second request failing).
fngx respdiff snapshot -server 192.0.2.10 -targets domains.txt -out after.json

# 3. Compare. Exit code 0: no significant differences; 3: differences;
#    1: error; 2: usage error.
fngx respdiff compare -json report.json before.json after.json
```

`domains.txt` has one target per line: `example.com` or
`example.com/path?query`. Blank lines and lines starting with `#` are
skipped. Domains must be in punycode form.

Every request goes to the `-server` address with the domain in the Host
header and in TLS SNI; DNS is not used.

## Load on the server

The server is usually in production. The defaults: 8 requests in flight,
10 requests started per second, 15 s per request, 1 MiB of body read per
response, one retry after a network error, two requests per target and
scheme. 10,000 domains on HTTP and HTTPS take about 70 minutes; `-repeat 1`
halves that at the cost of weaker body checks. The rate must be between
0.01 and 1000 requests per second. Only GET (or HEAD
with `-method HEAD`) is sent, never with cookies or credentials, and
redirects are not followed.

## TLS

`-tls strict` (default) treats an invalid certificate as a failed request,
like a browser; the certificate is still recorded. `-tls record` records
the verification result and still reads the response, so sites with
self-signed or expired certificates are compared too. The comparison report
states which mode each snapshot used and how many certificates were
invalid. A certificate that was valid and becomes invalid is critical; a
replaced certificate that is still valid is informational.

## What counts as a difference

Run `fngx respdiff rules` to print the default rules with a note on each.
In short:

| Difference | Severity |
| --- | --- |
| Status, redirect target (`Location`), media type | critical |
| Request fails after but worked before | critical |
| Security header removed (HSTS, CSP, X-Frame-Options, ...) | critical |
| Body changed, baseline proved it stable | critical |
| Answers stable before, varying after (flaky backend) | critical |
| Body changed and the page title changed or the size changed more than twofold (or became empty) | critical |
| Body changed otherwise, baseline taken with `-repeat 1` | warning |
| Body changed otherwise on a page that varies between identical requests | info |
| Body of a redirect / error page changed, same status | info / at most warning |
| Caching, compression, cookies (names and attributes), CORS headers | warning |
| `Server`, `X-Powered-By`, unknown headers, TLS version | info |
| `Date`, `Age`, `Expires`, `ETag`, `Last-Modified`, request IDs, cache status | ignored |

Before hashing, text bodies are normalized: CSRF tokens in meta tags and
hidden fields, CSP nonces, nonces in inline JavaScript and the content of
HTML comments (where page caches put generation times) are replaced by
`-`. `application/javascript` and `text/javascript` count as the same
media type.

Pages that only change slowly (a "latest posts" list, a cache regenerated
between the two snapshots) cannot be told from real changes by repeating a
request a second later; expect a few such critical findings on large
servers and check them by hand.

Set-Cookie values are never stored. `-fail-on warning` makes warnings
fail the check too.

## Custom rules

A rules file (`-rules FILE`, same format as the printed defaults) is
merged over the defaults: patterns are added, a header rule replaces the
default rule for the same header names, `"no_defaults": true` starts from
nothing. Example: compare `ETag` and mask a timestamp in page footers:

```json
{
  "headers": [{"names": ["ETag", "Last-Modified"], "severity": "warning"}],
  "body_patterns": [{"name": "footer-time", "regexp": "Generated at (\\d+)"}]
}
```

Body patterns run when the snapshot is taken, because snapshots store
hashes, not bodies. Use the same rules for both snapshots; otherwise
`compare` falls back to raw hashes and says so.
