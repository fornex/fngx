# Building nginx from source

The installer compiles nginx on the server (requirement I-2) with TLS,
HTTP/2 and HTTP/3 (M-1) and ModSecurity 3 (S-1). This document describes the
build tooling in [`build/nginx/`](../build/nginx/), the choices behind it,
and the results on each supported OS.

Labels used below: **verified** means checked against the linked primary
source or by running the build; **assumption** means not verified.

## Quick start

As root on the server:

```sh
build/nginx/build.sh                         # pinned default versions
build/nginx/build.sh --nginx-version 1.31.10 # another nginx version
build/nginx/smoke-test.sh                    # checks the installed build
```

On a workstation with Docker, build and test in a clean container:

```sh
build/nginx/run-in-container.sh almalinux:9
```

| File | Purpose |
| --- | --- |
| `build.sh` | Installs build dependencies, downloads and verifies sources, builds libmodsecurity and nginx, installs them. |
| `versions.env` | Pinned versions, SHA-256 checksums, download URLs and allowed PGP key fingerprints. |
| `keys/` | Public PGP keys of the nginx, OpenSSL and OWASP ModSecurity release signers. |
| `smoke-test.sh` | Checks run after each build (see [Smoke tests](#smoke-tests)). |
| `run-in-container.sh` | Runs `build.sh` and `smoke-test.sh` in a clean `almalinux:8/9/10` or `ubuntu:22.04/24.04` container. |
| [`.github/workflows/nginx-build.yml`](../.github/workflows/nginx-build.yml) | CI: shellcheck, then the container build for each image. Runs on changes to `build/nginx/**` and on manual dispatch (with an optional nginx version). |

`build.sh` options: `--nginx-version`, `--product`, `--jobs`, `--workdir`
(parent of a new build directory; must be root-owned and not writable by
others unless sticky),
`--keep-workdir`, `--skip-deps`, `--with-pagespeed` (fails, see
[PageSpeed](#pagespeed)). `build.sh --help` describes them.

No source code of nginx, OpenSSL, ModSecurity, OWASP CRS or PageSpeed is
stored in this repository: it is downloaded at build time.

## Components and versions

Versions pinned in `versions.env` on 26 November 2026.

| Component | Version | Why this version | Source |
| --- | --- | --- | --- |
| nginx | 1.30.8 | Latest release of the stable branch. 1.31.10 is the latest mainline and can be selected with `--nginx-version`. | [nginx.org download page](https://nginx.org/en/download.html), [GitHub releases](https://github.com/nginx/nginx/releases) |
| OpenSSL | 3.5.9 | 3.5 is the current LTS branch; nginx recommends 3.5.1 or later for QUIC (see below). | [OpenSSL downloads](https://openssl-library.org/source/), [GitHub releases](https://github.com/openssl/openssl/releases/tag/openssl-3.5.9) |
| libmodsecurity (ModSecurity v3) | 3.0.17 | Latest v3 release (29 September 2026). It fixes several published advisories (GHSA-…) listed in its release notes. | [release v3.0.17](https://github.com/owasp-modsecurity/ModSecurity/releases/tag/v3.0.17) |
| ModSecurity-nginx connector | 1.0.4 | Latest release (21 May 2025). | [release v1.0.4](https://github.com/owasp-modsecurity/ModSecurity-nginx/releases/tag/v1.0.4) |
| OWASP CRS | 4.31.0 (not downloaded by the build) | Latest release (23 November 2026). CRS is installed by a separate CLI command (S-1), which is not part of this change. | [CRS releases](https://github.com/coreruleset/coreruleset/releases) |

### TLS library for HTTP/3

Verified from the nginx documentation:

- [`ngx_http_v3_module`](https://nginx.org/en/docs/http/ngx_http_v3_module.html)
  is built with `--with-http_v3_module`, is marked *experimental*, and
  requires OpenSSL 1.1.1 or later; 0-RTT requires OpenSSL 3.5.1 or later.
  BoringSSL, LibreSSL and QuicTLS are alternatives.
- [QUIC and HTTP/3 support](https://nginx.org/en/docs/quic.html): "OpenSSL
  version 3.5.1 or higher is recommended"; with an older OpenSSL nginx uses
  an OpenSSL compatibility layer that does not support early data.
- In the nginx 1.30.8 source (`src/event/quic/ngx_event_quic.h`) the native
  OpenSSL QUIC API is selected when `OPENSSL_VERSION_NUMBER >= 0x30500010L`
  (OpenSSL 3.5.1); otherwise the compatibility layer is used.

The system OpenSSL differs per OS: Ubuntu 22.04 and 24.04 ship 3.0.x,
AlmaLinux 8 ships 1.1.1 (assumption: not checked in this work), and the
`almalinux:9` image had 3.5.9 installed (seen in the build log). To get the
same TLS stack and the native QUIC API on every OS, `build.sh` compiles
OpenSSL 3.5.9 from source and links it statically into nginx
(`--with-openssl`). Trade-off: OpenSSL security updates then require
rebuilding nginx; the system OpenSSL packages do not patch it. The OpenSSL
3.5 branch is supported until 8 April 2030
([release strategy](https://openssl-library.org/policies/releasestrat/index.html)).

BoringSSL has no releases or stable API and QuicTLS is a fork; OpenSSL 3.5
removes the need for either. LibreSSL was not evaluated.

### Who maintains ModSecurity

Verified:

- The [OWASP ModSecurity project page](https://owasp.org/www-project-modsecurity/)
  states that ModSecurity was transferred from Trustwave to OWASP.
- The repositories moved to the
  [owasp-modsecurity](https://github.com/owasp-modsecurity) GitHub
  organization; v3.0.17 was published there on 29 September 2026 and
  ModSecurity v2.9.15 on the same day, so both lines are maintained.
- Releases from 3.0.12 on are signed with the OWASP key
  `0B2BA1924065B44691202A2AD286E022149F0F6E` (`modsecurity@owasp.org`), as
  stated on the project's
  [CVE page source](https://github.com/OWASP/www-project-modsecurity/blob/main/tab_cves.md).

OWASP CRS is maintained separately by the
[Core Rule Set project](https://github.com/coreruleset/coreruleset).

## Download verification

Every tarball is checked twice before it is unpacked:

1. **SHA-256** against the value pinned in `versions.env`. For a non-default
   `--nginx-version` there is no pinned checksum; the script prints the
   computed one and relies on the signature.
2. **PGP signature** (`.asc` next to the tarball) with `gpg` in a temporary
   keyring that holds only the committed public keys for that component. The
   signature's primary key fingerprint must be one of those listed in
   `versions.env`; a valid signature by any other key fails the build.

After verification the full archive listing is checked: every entry must be
inside the expected top directory and no entry may contain a `..`
component. Downloads and redirects use HTTPS only (`--proto =https
--proto-redir =https`). Nothing is piped into a shell. The build runs in a
new `mktemp` directory (mode 0700, owned by root).

| Component | Signing key (primary fingerprint) | Where the key is published |
| --- | --- | --- |
| nginx | Release managers' keys, e.g. Sergey Kandaurov `D6786CE303D9A9022998DC6CC8464D549AF75C0A` (signed 1.30.8 and 1.31.10); all five keys from the page are allowed | [nginx.org PGP keys](https://nginx.org/en/pgp_keys.html) |
| OpenSSL | `B146647E45A7B33947AB226B2A2C87D161692D40` (signing subkey `C46ED3F2CBEFDA1FDAADA44264ED7B1DCCE71CB2`, expires 26 May 2027) | [openssl-library.org/source](https://openssl-library.org/source/), `pubkeys.asc` |
| libmodsecurity, connector | `0B2BA1924065B44691202A2AD286E022149F0F6E` | [OWASP ModSecurity CVE page](https://github.com/OWASP/www-project-modsecurity/blob/main/tab_cves.md); the key itself was fetched from keys.openpgp.org and keyserver.ubuntu.com (both identical) |

The OpenSSL page also lists retired keys; only the current primary key is
allowed. `keys/nginx.asc` contains all five keys from the nginx page, but the
key of Sergey Budnevitch (`7338973069ED3F443F4D37DFA64FD5B17ADB39A8`)
expired in 2016 and is not in the allow-list. The signing subkey expires in May 2027: signatures made before that
stay valid, but releases after it will need a refreshed `keys/openssl.asc`.

Trust roots: the committed key files were fetched over HTTPS from the pages
above on 26 November 2026. Anyone who can change this repository can change
the keys and pins, so they must be reviewed like code.

### Updating pinned versions

1. Download the new tarball and its `.asc` from the URL in `versions.env`.
2. Verify the signature with the committed keys
   (`gpg --import build/nginx/keys/<component>.asc`,
   `gpg --verify file.tar.gz.asc file.tar.gz`) and check the primary key
   fingerprint against the table above.
3. Put the version and `sha256sum` output into `versions.env`.
4. Run the CI workflow (or `run-in-container.sh` for each image).

## What gets built

### libmodsecurity

`./configure --prefix=/opt/<product>/modsecurity` with PCRE2, YAJL and
libxml2. Shared library only. Turned off to reduce dependencies and attack
surface: libcurl (`SecRemoteRules`), GeoIP/MaxMind, LMDB, Lua, ssdeep. Without
LMDB, persistent collections are kept in memory. **Assumption**: OWASP CRS
does not need any of the disabled features in its default configuration;
this is to be checked when the CRS command is implemented.

YAJL is listed as a mandatory dependency in the
[ModSecurity README](https://github.com/owasp-modsecurity/ModSecurity#dependencies)
and gives libmodsecurity its JSON request body parser.
On AlmaLinux 8 and 9 `yajl-devel` is in the CRB repository (PowerTools on EL8).
`build.sh` enables that repository for its own `dnf install` only
(`--enablerepo`), so the system's repository configuration is not changed.
**Assumption**: on CloudLinux the repository ids also contain `crb` or
`powertools`; this needs a real CloudLinux server.

#### YAJL on EL10

Verified in an `almalinux:10` container on 26 November 2026: no `yajl`
package exists in BaseOS, AppStream, CRB or EPEL 10. The Fedora and EPEL
maintainer of libmodsecurity reports that yajl is not shipped with RHEL 10,
that the upstream project has been unmaintained since 2015 with open CVEs,
and that libmodsecurity can be built without it
([ModSecurity issue #3308](https://github.com/owasp-modsecurity/ModSecurity/issues/3308),
open; the maintainers agree to replace yajl but have not done so yet).

Therefore `build.sh` builds libmodsecurity with `--without-yajl` on
AlmaLinux 10 and CloudLinux 10 and prints a warning. Consequence: on these
systems ModSecurity does not parse JSON request bodies, so rules (including
OWASP CRS) do not see values inside JSON bodies as `ARGS`. The smoke test
checks this: a JSON body with a matching value must be blocked on every
other OS, and on EL10 the absence is reported as a note.

Alternatives not taken without a decision: building yajl from an
unmaintained, unsigned upstream tarball (carries the open CVEs), or from a
downstream fork or Fedora's patched sources (another source to trust and
maintain). This is listed under [Open questions](#open-questions).

### nginx

```
--prefix=/opt/<product>/nginx
--conf-path=/etc/<product>/nginx/nginx.conf
--error-log-path, --http-log-path: /var/log/<product>/nginx/
--pid-path, --lock-path: /run/<product>/
temp paths: /var/cache/<product>/nginx/
--with-compat --with-threads --with-file-aio --with-pcre-jit
--with-http_ssl_module --with-http_v2_module --with-http_v3_module
--with-http_realip_module --with-http_stub_status_module
--with-http_gzip_static_module --with-http_gunzip_module
--with-http_sub_module --with-http_auth_request_module
--with-http_secure_link_module --with-http_slice_module
--with-http_mp4_module --with-http_flv_module
--with-openssl=<OpenSSL 3.5.9 source> --with-openssl-opt=no-tests
--add-dynamic-module=<ModSecurity-nginx source>
```

- OpenSSL is configured with `no-tests no-dso no-module no-engine
  --openssldir=/etc/<product>/ssl`. Without `--openssldir`, OpenSSL's
  compiled-in configuration path would point into the build directory under
  `/var/tmp`, which is deleted after the build and could be recreated by
  another local user. nginx built with `--with-openssl` does not read
  `openssl.cnf` unless `OPENSSL_CONF` is set (`NGX_OPENSSL_NO_CONFIG` in
  `src/event/ngx_event_openssl.c`), so this is defense in depth. The engine
  and module directories still point into the build directory (nginx's
  build fixes OpenSSL's `--prefix`), but engines, loadable modules and
  dynamic loading are not built.
- `mp4` and `flv` serve the streaming feature of U-5; `realip` and
  `stub_status` are expected to be needed by the proxy modes and status
  pages. The module list is a proposal of the developer.
- Compiler flags follow the hardening of the nginx.org packages
  (`-D_FORTIFY_SOURCE=2 -fstack-protector-strong -fstack-clash-protection`,
  full RELRO, PIE).
- `<product>` is `fngx`, a working title. `build.sh` and `smoke-test.sh`
  derive every path from one variable, `PRODUCT` (or `--product`). The CI
  lint job checks that its default matches `internal/product.Name`.
- The paths do not overlap with `ea-nginx` (`/etc/nginx`) or distribution
  packages. The layout is a proposal of the developer.

### ModSecurity can be turned off

The connector is a dynamic module
(`/opt/<product>/nginx/modules/ngx_http_modsecurity_module.so`). It is only
active when `nginx.conf` has `load_module` for it, and it inspects traffic
only where `modsecurity on;` is set; the connector's default is off. The
nginx.conf installed by the build does neither, so ModSecurity is off after
installation (S-3). The module finds `libmodsecurity.so` through an `rpath`
to `/opt/<product>/modsecurity/lib`; the system linker configuration is not
changed.

### Installation without breaking a running nginx

Everything is built and installed into a staging directory first
(`make install DESTDIR=...`). A failed download, verification or compile
leaves the installed version untouched. Only after both components have
built is the staged tree copied to the live paths: libmodsecurity first,
then nginx. Each file is copied under a temporary name and renamed over the
old one, so a running nginx keeps its open files. Existing files in
`/etc/<product>/nginx/` are never overwritten; only the `*.default`
reference copies are refreshed.

Known limits, left to the installer that will call `build.sh`:

- The copy is atomic per file, not as a whole. A failure in the middle of
  the copy (for example a full disk), or an nginx start during it, can meet
  a mix of old and new files; a module of the new version is refused by an
  old binary. A versioned install directory switched by one symlink would
  close this window.
- A running nginx keeps the old binary until it is restarted or upgraded in
  place (`USR2`); `build.sh` prints this but restarts nothing.
- Files of an older version that the new one no longer ships (for example
  `libmodsecurity.so.3.0.16`) are left in place.
- `/run/<product>` is created by `build.sh` but `/run` is a tmpfs: the
  service unit must create it at boot (`RuntimeDirectory=` or tmpfiles.d).
  The service unit is not part of this change.
- The build tools (compiler, headers) stay installed on the server.

## Smoke tests

`smoke-test.sh` runs after every build:

1. `nginx -V` lists `--with-http_ssl_module`, `--with-http_v2_module`,
   `--with-http_v3_module`, `--with-compat`, `realip`, `mp4`, `flv`,
   `--with-pcre-jit`, the ModSecurity dynamic module, and "built with
   OpenSSL 3.5.9".
2. Linking: nginx has no shared `libssl`/`libcrypto`; the compiled-in
   `OPENSSLDIR` is `/etc/<product>/ssl`; `ldd` on the module resolves
   `libmodsecurity.so` from `/opt/<product>/modsecurity/lib` with no missing
   libraries, and the module's `RUNPATH` is exactly that directory.
3. `nginx -t` passes on a minimal config that loads the ModSecurity module
   and has `listen 443 ssl` + `listen 443 quic reuseport`, `http2 on`,
   `http3 on` and a self-signed certificate.
4. nginx is started on loopback ports with a blocking ModSecurity rule
   loaded and `SecRuleEngine On` in the `http` block:
   - a server without `modsecurity on` returns 200 for the matching request
     (ModSecurity is off by default, S-3);
   - a server with `modsecurity on` returns 403 for it and 200 for a clean
     request (the module works);
   - the QUIC listener is a bound UDP socket (checked in `/proc/net/udp`);
   - `curl --http2` over TLS gets HTTP/2 and status 200.
5. The installed `nginx.conf` does not load or enable ModSecurity, and
   `nginx -t` passes on it.

6. JSON request bodies: with a rule that switches to the JSON body
   processor, a JSON body containing the matching value is blocked (406).
   On EL10, where libmodsecurity is built without YAJL, the absence is
   printed as a note instead (see [YAJL on EL10](#yajl-on-el10)).

Not tested: an actual HTTP/3 request. That needs an HTTP/3 client, and the
build installs none; whether the distributions' curl supports HTTP/3 was not
checked. `nginx -t`, starting nginx with `quic` listeners and the bound UDP
socket are tested. Also not tested: installing over an existing, running
installation.

## Results per OS

CI run [45872584039](https://github.com/fornex/fngx/actions/runs/45872584039)
on commit `e46357d`, GitHub-hosted `ubuntu-24.04` runner, x86_64,
4 CPUs, 15 GB RAM, one container per OS. All five builds passed every smoke
test. Times are from the build log: "deps" is the package installation,
"build" is download + verification + compile + install of all components.

| OS (image) | Compiler | PCRE2 / libxml2 / YAJL (system) | Deps | Build | Total job step | Result |
| --- | --- | --- | --- | --- | --- | --- |
| AlmaLinux 8.10 (`almalinux:8`) | GCC 8.5.0 | 10.32 / 2.9.7 / 2.1.0 | 29 s | 133 s | 164 s | pass |
| AlmaLinux 9.9 (`almalinux:9`) | GCC 11.5.0 | 10.40 / 2.9.13 / 2.1.0 | 24 s | 174 s | 204 s | pass |
| AlmaLinux 10.3 (`almalinux:10`) | GCC 14.4.1 | 10.44 / 2.12.5 / none | 11 s | 148 s | 160 s | pass, JSON bodies not inspected (no YAJL) |
| Ubuntu 22.04 (`ubuntu:22.04`) | GCC 11.4.0 | 10.39 / 2.9.13 / 2.1.0 | 10 s | 139 s | 151 s | pass |
| Ubuntu 24.04 (`ubuntu:24.04`) | GCC 13.3.0 | 10.42 / 2.9.14 / 2.1.0 | 12 s | 138 s | 152 s | pass |
| CloudLinux 8, 9, 10 | — | — | — | — | — | **not tested**: CloudLinux images are not freely available; must be checked on a real server |

Component versions are the same on every OS: nginx 1.30.8, OpenSSL 3.5.9
(static), libmodsecurity 3.0.17, ModSecurity-nginx 1.0.4.

`nginx -V` (AlmaLinux 9; the other OSes differ only in the "built by" line
and in the temporary build directory):

```
nginx version: nginx/1.30.8
built by gcc 11.5.0 20240719 (Red Hat 11.5.0-17) (GCC)
built with OpenSSL 3.5.9 29 Sep 2026
TLS SNI support enabled
configure arguments: --prefix=/opt/fngx/nginx --sbin-path=/opt/fngx/nginx/sbin/nginx --modules-path=/opt/fngx/nginx/modules --conf-path=/etc/fngx/nginx/nginx.conf --error-log-path=/var/log/fngx/nginx/error.log --http-log-path=/var/log/fngx/nginx/access.log --pid-path=/run/fngx/nginx.pid --lock-path=/run/fngx/nginx.lock --http-client-body-temp-path=/var/cache/fngx/nginx/client_temp --http-proxy-temp-path=/var/cache/fngx/nginx/proxy_temp --http-fastcgi-temp-path=/var/cache/fngx/nginx/fastcgi_temp --http-uwsgi-temp-path=/var/cache/fngx/nginx/uwsgi_temp --http-scgi-temp-path=/var/cache/fngx/nginx/scgi_temp --with-compat --with-threads --with-file-aio --with-pcre-jit --with-http_ssl_module --with-http_v2_module --with-http_v3_module --with-http_realip_module --with-http_stub_status_module --with-http_gzip_static_module --with-http_gunzip_module --with-http_sub_module --with-http_auth_request_module --with-http_secure_link_module --with-http_slice_module --with-http_mp4_module --with-http_flv_module --with-openssl=/var/tmp/fngx-nginx-build.heP3zq/src/openssl-3.5.9 --with-openssl-opt=no-tests --add-dynamic-module=/var/tmp/fngx-nginx-build.heP3zq/src/ModSecurity-nginx-v1.0.4 --with-cc-opt='-O2 -pipe -Wformat -Werror=format-security -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fstack-clash-protection -fPIC' --with-ld-opt='-Wl,-z,relro -Wl,-z,now -pie -Wl,-rpath,/opt/fngx/modsecurity/lib'
```

Problems found and fixed during the work:

- **AlmaLinux 10: no YAJL.** See [YAJL on EL10](#yajl-on-el10).
- **EL9 images ship `curl-minimal`**, which conflicts with the `curl`
  package; `build.sh` asks dnf for `/usr/bin/curl` instead.
- **TLS handshake failures to nginx.org** (curl exit 35) happened from a
  workstation network; curl's `--retry` does not cover them and EL8's curl
  7.61 lacks `--retry-all-errors`, so `build.sh` retries downloads itself.
- OpenSSL 3.5.9 compiled with GCC 14 (AlmaLinux 10) prints
  `-Wstringop-overflow` warnings in `engines/e_padlock.c`; the build is not
  affected. Not investigated further.

Local runs on an Apple Silicon workstation (Docker, x86_64 images under
Rosetta emulation, several builds in parallel) also passed on AlmaLinux 9
(447 s for download + build) and built on Ubuntu 22.04 (606 s); these times
are not representative of a server.

## PageSpeed

PAGESPEED_PLACEHOLDER

## Licenses of downloaded components

Verified from the license files in the release tarballs and the GitHub
repository metadata. None of these components is stored in or linked into
the Go program of this repository; they are downloaded and compiled on the
server. A lawyer reviews licensing before publication (SPEC section 16).

| Component | License |
| --- | --- |
| nginx | BSD-2-Clause ([LICENSE](https://nginx.org/LICENSE)) |
| OpenSSL 3.x | Apache-2.0 ([LICENSE.txt](https://github.com/openssl/openssl/blob/master/LICENSE.txt)) |
| libmodsecurity (ModSecurity v3) | Apache-2.0 ([LICENSE](https://github.com/owasp-modsecurity/ModSecurity/blob/v3/master/LICENSE)) |
| libinjection (bundled in the ModSecurity tarball) | BSD-3-Clause (`others/libinjection/COPYING`) |
| Mbed TLS (bundled in the ModSecurity tarball) | Apache-2.0 OR GPL-2.0-or-later (`others/mbedtls/LICENSE`) |
| ModSecurity-nginx connector | Apache-2.0 ([LICENSE](https://github.com/owasp-modsecurity/ModSecurity-nginx/blob/master/LICENSE)) |
| OWASP CRS (installed separately) | Apache-2.0 ([LICENSE](https://github.com/coreruleset/coreruleset/blob/main/LICENSE)) |
| PageSpeed by We-Amp (optional, not built) | Apache-2.0 ([LICENSE](https://github.com/We-Amp/mod_pagespeed/blob/master/LICENSE)) |

Build dependencies installed from the OS repositories (compiler, PCRE2,
zlib, libxml2, YAJL) keep their distribution licenses.

## Open questions

1. **JSON inspection on EL10.** Accept that ModSecurity does not parse JSON
   request bodies on AlmaLinux/CloudLinux 10 until ModSecurity replaces
   YAJL, or build YAJL from a patched source (which one, and who follows its
   security fixes)?
2. **CloudLinux.** The build has not run on CloudLinux 8, 9 or 10. It needs
   a real server, including the CRB/PowerTools repository ids (assumption
   above).
3. **Static OpenSSL.** OpenSSL fixes require rebuilding nginx. The plugin
   needs a way to tell the administrator when the pinned OpenSSL has a
   security release (not part of this change).
4. **Upgrade procedure.** The installer has to decide how to swap versions
   (versioned directory + symlink, restart or `USR2` binary upgrade) given
   the limits listed under "Installation without breaking a running nginx".
5. **Installed layout** (`/opt/<product>`, `/etc/<product>/nginx`, ...) and
   the module list are proposals of the developer and await confirmation.
