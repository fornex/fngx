# Vhost templates

This page describes how the nginx configuration of a server is generated, how
an administrator replaces the built-in vhost templates (T-3), and every
variable a template can use (T-5). The generator is the Go package
`internal/render`.

## Generated files

The generator produces one complete configuration set. The apply engine
(`internal/apply`) tests it with `nginx -t`, switches it live atomically and
reloads nginx (A-5). Every include uses a path relative to the main file.

| File | Content |
| --- | --- |
| `nginx.conf` | Main file: `pid`, logs, SSL protocols, default servers, `include vhosts/*.conf`. Built-in only. |
| `snippets/proxy.conf` | Request headers for Apache in proxy and hybrid mode, HTTP/1.1 and WebSocket upgrade. |
| `snippets/fastcgi.conf` | FastCGI parameters for PHP-FPM in nginx mode. |
| `apps/<name>.conf` | Application templates (T-2), one per template the admin configured. |
| `vhosts/<domain>.conf` | The domain's server blocks, rendered from the template of its mode. |
| `domains/<domain>/http-rewrite.conf` | Admin rewrite rules for HTTP (T-6). |
| `domains/<domain>/http-include.conf` | Admin include for HTTP (T-6). |
| `domains/<domain>/https-rewrite.conf` | Admin rewrite rules for HTTPS (T-6). |
| `domains/<domain>/https-include.conf` | Admin include for HTTPS (T-6). |
| `domains/<domain>/client.conf` | Client rules (T-7), normalized by `internal/userrules`. |

A per-domain file exists only when its text is not empty. The files of one
domain form one apply unit, so a broken domain does not block the others
(N-4). The per-domain include files live outside `vhosts/` so that the
`vhosts/*.conf` mask never matches a directory.

## Built-in templates

There is one template per mode (T-1). They were written for this project from
the nginx documentation; the templates link the pages they rely on.

- `proxy.conf.tmpl`: every request goes to Apache (M-6).
- `hybrid.conf.tmpl`: files whose extension is in the static list are served by
  nginx; other requests, and static files that do not exist, go to Apache
  (M-7). The fallback uses `try_files $uri @backend`
  ([try_files](https://nginx.org/en/docs/http/ngx_http_core_module.html#try_files)).
- `nginx.conf.tmpl`: nginx serves files and passes `.php` to the domain's
  PHP-FPM socket (M-9). If the domain selects an application template, it is
  included in place of the default `location /`.
- `common.tmpl`: helper templates the others call: `listen`, `tls`,
  `includes`, `proxy`.

All modes set `root` to the document root and `disable_symlinks if_not_owner`
([disable_symlinks](https://nginx.org/en/docs/http/ngx_http_core_module.html#disable_symlinks)):
nginx does not follow a symbolic link whose owner differs from the owner of
its target, so a client cannot make nginx serve another account's files
(Q-6). Every component of the path is checked, including the document root
itself: a client who replaces `public_html` with a link to another account's
directory gets nothing. A `from=` part is deliberately not used, because
nginx skips the check for that part. Links owned by root to directories
owned by root (for example `/home` pointing to another disk) still work.
Hard links are not covered; they rely on the kernel's `protected_hardlinks`.

In hybrid and nginx mode, requests for hidden files (`/.htaccess`,
`/.user.ini`, `/.git/...`) get 403, except `/.well-known/`, which
certificate validation needs (M-2). The check is an `if` on `$uri` at server
level, so it runs before any location is chosen and no admin or client
location can bypass it, including a `^~` prefix location, which would skip
a regex location. It does not apply after an internal rewrite of the
client's own, and proxy mode leaves hidden files to Apache, as without
nginx.

To get the text of a built-in template as a starting point, use
`render.Builtin("<name>")`; the WHM page and the CLI will expose it (U-4).

## Custom templates (T-3)

Custom templates are kept in their own directory, separate from the built-in
ones, which are compiled into the program. The directory is passed to the
generator as `render.Config.Custom`; the installer will create it (proposed:
`/etc/<product>/templates/`).

- A file named `<mode>.conf.tmpl` (`proxy`, `hybrid` or `nginx`) replaces the
  built-in template of that mode for every domain in that mode.
- Other files with the `.conf.tmpl` suffix are an error; files with other
  suffixes are ignored.
- Templates use Go [text/template](https://pkg.go.dev/text/template) syntax.
  The helper templates of `common.tmpl` are available with
  `{{template "listen" .}}` and so on.
- A syntax error stops the generator when it loads templates. An unknown
  variable fails rendering of the domains in that mode. The generated file
  is then checked with `nginx -t` before it can go live (T-9).

The main file is not replaceable: the apply engine depends on its `pid`
directive and its relative includes.

## Safety of values (N-6)

Every variable that prints text has the type `render.Arg`. An `Arg` prints as
exactly one nginx parameter: bare if it contains only letters, digits and
`/._-:@+,=%~[]`, otherwise in double quotes with `"` and `\` escaped. Values
that cannot be made inert are refused before rendering: control characters,
line breaks, non-ASCII bytes and `$` (nginx expands variables inside quotes
too and has no escape for `$`). Paths are checked more strictly still: clean,
absolute, and only letters, digits and `/._-+@,=~`. Domain and user names are
checked by `internal/model`.

Template functions:

| Function | Meaning |
| --- | --- |
| `q "text"` | Makes a literal string from the template an `Arg`; rendering fails if it contains a refused character. |
| `join .List " "` | Prints a list of `Arg` values separated by the given string. |

Admin texts (T-6) and application templates are trusted and are not checked
beyond being UTF-8 without NUL bytes. Each goes into its own file that the
server block includes. nginx parses an included file on its own, so a stray
`}` in it is a syntax error instead of closing the server block. Client rules
reach the configuration only as the output of `userrules.Rules.Format` (T-7).

## Include order and why

Inside each server block the built-in templates place the includes in this
order:

1. `nginx` mode only: the location that denies hidden files.
2. Admin rewrite file. Rewrite-module directives at server level run in the
   order they appear
   ([rewrite module](https://nginx.org/en/docs/http/ngx_http_rewrite_module.html)),
   so the admin's rules run before the client's.
3. Admin include file. `allow` and `deny` are checked in order until the first
   match ([access module](https://nginx.org/en/docs/http/ngx_http_access_module.html)),
   so an admin `deny` here wins over a client `allow all`.
4. Client rules.
5. The application template (nginx mode) and the template's own locations.

Location order matters only among regular-expression locations: they are
checked in order of appearance and the first match wins
([location](https://nginx.org/en/docs/http/ngx_http_core_module.html#location)).
Prefix and exact locations do not depend on order. So:

- a client or admin location cannot expose hidden files in hybrid and nginx
  mode (see above);
- a client regex location comes before the template's `\.php$` and static
  extension locations, so the client can refine them for own paths, for
  example add `expires` for images. Shadowing them affects only the client's
  own site (assumption 5 of the client rules);
- a client `location /` (or `location ^~ /`) would duplicate the template's
  `location /`, which nginx rejects; the generator refuses such client rules
  with a clear error instead of letting the domain's `nginx -t` fail.

Things to know when writing rules:

- `proxy_set_header`, `fastcgi_param` and `add_header` are inherited from the
  enclosing level only when the current level defines none
  ([proxy_set_header](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_set_header),
  [fastcgi_param](https://nginx.org/en/docs/http/ngx_http_fastcgi_module.html#fastcgi_param),
  [add_header](https://nginx.org/en/docs/http/ngx_http_headers_module.html#add_header)).
  A location with its own `add_header` loses the server-level headers such as
  `Alt-Svc`; a location that proxies with extra headers must include
  `snippets/proxy.conf` itself.
- The template's locations are not `internal`-protected from the domain owner:
  a client `rewrite ... last` can reach them (assumption 4 of the client
  rules).
- `.htaccess` has no effect on what nginx serves in hybrid and nginx mode
  (M-8). Directories protected by `.htaccess` (for example cPanel Directory
  Privacy) are not protected for files nginx serves itself.
- **In proxy and hybrid mode a client location serves files from disk.** The
  client whitelist has no `proxy_pass`, so a client location such as
  `location /app/ { expires 1h; }` makes nginx answer requests under `/app/`
  from the document root instead of passing them to Apache: PHP files there
  are sent as source, and `.htaccess` rules do not apply. This affects only
  the client's own site; how to handle it (refuse locations for these modes,
  or add a fallback to Apache) is an open question.
- Client rules apply to both the HTTP and the HTTPS server; a client
  `return 301 https://...` without a scheme check loops on HTTPS.

## Default servers

For every address nginx listens on (the shared addresses and each dedicated
address) the main file defines a default server
([listen](https://nginx.org/en/docs/http/ngx_http_core_module.html#listen),
[request processing](https://nginx.org/en/docs/http/request_processing.html)).

- HTTP: requests for unknown names go to Apache if there is one (so names
  that only Apache knows keep working), otherwise nginx closes the
  connection (`return 444`).
- HTTPS: the handshake is rejected (`ssl_reject_handshake on`,
  [ssl module](https://nginx.org/en/docs/http/ngx_http_ssl_module.html#ssl_reject_handshake)),
  so no domain's certificate is shown for a foreign name.
- With HTTP/3 the HTTPS default server also carries `listen ... quic
  reuseport`. `reuseport` may appear only once per address and port, and the
  QUIC documentation recommends it for several worker processes
  ([quic](https://nginx.org/en/docs/quic.html)).

## Requests to Apache (M-6)

`snippets/proxy.conf` sets `Host` to the requested name, `X-Real-IP` to the
visitor address, appends it to `X-Forwarded-For`, and sets
`X-Forwarded-Proto`, `X-Forwarded-Host` and `X-Forwarded-Port` from nginx's
own values. `Forwarded`, `X-Forwarded-Server`, `X-Forwarded-Ssl` and `Proxy`
from the visitor are removed, so a visitor cannot spoof them. Apache must be
configured to trust these headers only from nginx (mod_remoteip); that is
not part of the generator.

If Apache has no TLS port for nginx (`Apache.HTTPS` unset), requests that
came over HTTPS reach Apache as plain HTTP with `X-Forwarded-Proto: https`.
Applications that force HTTPS then redirect in a loop unless Apache sets
`HTTPS=on` from that header. With `Apache.HTTPS` set, nginx connects to
Apache over TLS with the requested name in SNI.

The main file sets `client_max_body_size` from the server setting (default
`1g`); nginx's own default of 1m would refuse uploads that Apache accepts.

## Protocols (M-1)

- HTTPS servers listen with `ssl` and enable HTTP/2 with the `http2`
  directive ([http2](https://nginx.org/en/docs/http/ngx_http_v2_module.html#http2),
  nginx 1.25.1 or later).
- With HTTP/3 on, HTTPS servers also `listen ... quic` and send
  `Alt-Svc: h3=":443"; ma=86400` (with `always`, so also on error
  responses), as in the
  [HTTP/3 module example](https://nginx.org/en/docs/http/ngx_http_v3_module.html#example).
  HTTP/3 needs nginx built with `--with-http_v3_module` and TLSv1.3.
- `ssl_protocols` is set once in the `http` block from the server setting.

## Variables of vhost templates

The root object is a `render.VhostData`. Optional values are `nil` when they
do not apply; test them with `{{with ...}}` or `{{if ...}}`.

| Variable | Type | Meaning |
| --- | --- | --- |
| `.Product` | Arg | Product name. |
| `.Domain` | Arg | Primary server name. |
| `.Names[]` | list of Arg | All server names: primary first, then aliases sorted. |
| `.User` | Arg | Owner account. |
| `.Kind` | Arg | `main`, `sub` or `addon`. |
| `.Mode` | Arg | `proxy`, `hybrid` or `nginx`. |
| `.Root` | Arg | Document root. |
| `.Servers[]` | list | The HTTP server and, with a certificate, the HTTPS server. |
| `.Servers[].Scheme` | Arg | `http` or `https`. |
| `.Servers[].TLS` | bool | This is the HTTPS server. |
| `.Servers[].Listen[]` | list of Arg | `address:port` (or `port` for all addresses) for `listen`. |
| `.Servers[].QUIC[]` | list of Arg | The same for `listen ... quic`; empty unless HTTP/3 is on. |
| `.Servers[].AltSvc` | Arg or nil | Alt-Svc header value advertising HTTP/3. |
| `.Servers[].HTTP2` | bool | HTTP/2 is on (HTTPS only). |
| `.Servers[].Cert` | Arg or nil | Certificate file (HTTPS only). |
| `.Servers[].Key` | Arg or nil | Private key file (HTTPS only). |
| `.Servers[].Backend` | Arg or nil | Apache URL for `proxy_pass` (proxy and hybrid). |
| `.Servers[].BackendTLS` | bool | The backend URL is `https://`; needs `proxy_ssl_server_name on` and `proxy_ssl_name $host`. |
| `.Servers[].AdminRewrite` | Arg or nil | Include path of the admin rewrite file for this scheme. |
| `.Servers[].AdminInclude` | Arg or nil | Include path of the admin include file for this scheme. |
| `.Servers[].ClientRules` | Arg or nil | Include path of the client rules (same file for both schemes). |
| `.Apache` | object or nil | Backend, in proxy and hybrid mode. |
| `.Apache.HTTP` | Arg | `http://address:port`. |
| `.Apache.HTTPS` | Arg or nil | `https://address:port`, if Apache has a TLS port for nginx. |
| `.Static` | object or nil | Hybrid mode with a non-empty extension list. |
| `.Static.Extensions[]` | list of Arg | Extensions nginx serves itself, sorted. |
| `.Static.Regex` | Arg | Case-insensitive regex for them, for `location ~* {{.Static.Regex}}`. |
| `.PHP` | object or nil | nginx mode. |
| `.PHP.Pass` | Arg | `fastcgi_pass` target, `unix:/path/to/socket`. |
| `.App` | Arg or nil | Include path of the selected application template (nginx mode). |

Inside `{{range .Servers}}`, `.` is the server and `$` is the root object, as
in the built-in templates (`{{$.Root}}`).

## Variables of the main file

The main file is built-in only; its data is `render.MainData`.

| Variable | Type | Meaning |
| --- | --- | --- |
| `.Product` | Arg | Product name. |
| `.User` | Arg or nil | Worker user (`user` directive). |
| `.PIDFile` | Arg | Must match the PID file the apply engine uses. |
| `.ErrorLog` | Arg | Main error log. |
| `.AccessLog` | Arg or nil | http-level access log; nil turns it off. |
| `.MimeTypes` | Arg | MIME types file installed with nginx. |
| `.Temp` | object or nil | Temporary directories, when the server sets one. |
| `.Temp.ClientBody` | Arg | `client_body_temp_path`. |
| `.Temp.Proxy` | Arg | `proxy_temp_path`. |
| `.Temp.FastCGI` | Arg | `fastcgi_temp_path`. |
| `.Temp.UWSGI` | Arg | `uwsgi_temp_path`. |
| `.Temp.SCGI` | Arg | `scgi_temp_path`. |
| `.WorkerConnections` | int | `worker_connections`. |
| `.WorkerNoFile` | int | `worker_rlimit_nofile`, twice the connections. |
| `.ClientMaxBodySize` | Arg | `client_max_body_size`. |
| `.SSLProtocols[]` | list of Arg | `ssl_protocols`. |
| `.Defaults[]` | list | One default server per address and scheme. |
| `.Defaults[].TLS` | bool | HTTPS default server. |
| `.Defaults[].Listen` | Arg | `address:port`. |
| `.Defaults[].QUIC` | Arg or nil | Same address for `listen ... quic reuseport`. |
| `.Apache` | Arg or nil | Apache URL for the HTTP default servers. |

## Testing

`go test ./internal/render` compares the output for representative inputs
with the golden files in `internal/render/testdata/golden` (Q-1). After an
intended change, regenerate them with
`go test ./internal/render -update` and review the diff. The integration
tests run the real `nginx -t` on every golden case and, on Linux, start nginx
and send it requests; see the comments in `integration_test.go` and
`live_test.go` for what they do and do not cover.
