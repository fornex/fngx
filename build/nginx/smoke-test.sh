#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Smoke tests for an nginx built by build.sh (requirements I-2, M-1, S-1, S-3).
#
# 1. nginx -V lists the expected modules and the pinned OpenSSL.
# 2. The ModSecurity module and libmodsecurity resolve from the product prefix.
# 3. nginx -t passes on a minimal config that loads the ModSecurity module and
#    has a "listen 443 quic" server with a self-signed certificate.
# 4. nginx runs on loopback ports: HTTP/2 works over TLS; a ModSecurity rule
#    is ignored where "modsecurity on" is not set (S-3) and blocks where it is.
# 5. The installed nginx.conf neither loads nor enables ModSecurity (S-3).
#
# Usage: smoke-test.sh [--product NAME]   (run as root after build.sh)

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source-path=SCRIPTDIR source=versions.env
. "$SCRIPT_DIR/versions.env"

PRODUCT="${PRODUCT:-fngx}"
while [ $# -gt 0 ]; do
	case "$1" in
	--product) [ $# -ge 2 ] || { echo "error: $1 needs a value" >&2; exit 2; }; PRODUCT="$2"; shift 2 ;;
	--product=*) PRODUCT="${1#*=}"; shift ;;
	*) echo "error: unknown option: $1" >&2; exit 2 ;;
	esac
done
[[ "$PRODUCT" =~ ^[a-z][a-z0-9-]{0,31}$ ]] || { echo "error: invalid product name" >&2; exit 2; }

PREFIX="/opt/$PRODUCT"
NGINX="$PREFIX/nginx/sbin/nginx"
MODULE="$PREFIX/nginx/modules/ngx_http_modsecurity_module.so"
CONF="/etc/$PRODUCT/nginx/nginx.conf"

FAILED=0
# EL10 has no YAJL (see build.sh); everywhere else JSON parsing must work.
EXPECT_JSON=1
# shellcheck disable=SC1091
case "$(. /etc/os-release && echo "${ID:-}:${VERSION_ID:-}")" in
almalinux:10* | cloudlinux:10*) EXPECT_JSON=0 ;;
esac
pass() { printf 'PASS: %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*"; FAILED=1; }

TMP="$(mktemp -d)"
# nginx workers run as an unprivileged user and must read the test files.
chmod 0755 "$TMP"
NGINX_PID=""
cleanup() {
	if [ -n "$NGINX_PID" ] && kill -0 "$NGINX_PID" 2>/dev/null; then
		kill -QUIT "$NGINX_PID" 2>/dev/null || true
		sleep 1
	elif [ -f "$TMP/run.conf" ]; then
		"$NGINX" -c "$TMP/run.conf" -s quit 2>/dev/null || true
		sleep 1
	fi
	rm -rf "$TMP"
}
trap cleanup EXIT

[ -x "$NGINX" ] || { echo "FAIL: $NGINX not found" >&2; exit 1; }

# --- 1. nginx -V ------------------------------------------------------------

V="$("$NGINX" -V 2>&1)"
printf '%s\n' "$V"
for flag in --with-http_ssl_module --with-http_v2_module --with-http_v3_module \
	--with-compat --with-http_realip_module --with-http_mp4_module \
	--with-http_flv_module --with-pcre-jit; do
	if grep -q -- "$flag" <<<"$V"; then
		pass "nginx -V has $flag"
	else
		fail "nginx -V lacks $flag"
	fi
done
if grep -q -E -- '--add-dynamic-module=[^ ]*ModSecurity-nginx' <<<"$V"; then
	pass "ModSecurity connector built as a dynamic module"
else
	fail "nginx -V lacks --add-dynamic-module=...ModSecurity-nginx"
fi
# OpenSSL 3.5.1+ gives nginx the native QUIC API instead of the
# compatibility layer (https://nginx.org/en/docs/quic.html).
if grep -q "built with OpenSSL $OPENSSL_VERSION " <<<"$V"; then
	pass "built with OpenSSL $OPENSSL_VERSION"
else
	fail "not built with OpenSSL $OPENSSL_VERSION"
fi
if grep -q "running with OpenSSL" <<<"$V"; then
	fail "nginx runs with a different OpenSSL than it was built with"
fi

# --- 2. Linking and compiled-in paths ---------------------------------------

# OpenSSL is linked statically: nginx must not load a system libssl.
if ldd "$NGINX" | grep -q -E 'lib(ssl|crypto)\.so'; then
	fail "nginx links a shared libssl/libcrypto: $(ldd "$NGINX" | grep -E 'lib(ssl|crypto)')"
else
	pass "nginx does not link a shared libssl/libcrypto"
fi
# OpenSSL's compiled-in configuration directory must not point into the
# (deleted, world-writable) build directory. ENGINESDIR and MODULESDIR
# still do, but build.sh disables engines, modules and dynamic loading.
OSSL_DIRS="$(grep -a -o -E '(OPENSSLDIR|ENGINESDIR|MODULESDIR): "[^"]*"' "$NGINX" | sort -u || true)"
printf '%s\n' "$OSSL_DIRS"
if grep -q -x "OPENSSLDIR: \"/etc/$PRODUCT/ssl\"" <<<"$OSSL_DIRS"; then
	pass "OPENSSLDIR is /etc/$PRODUCT/ssl"
else
	fail "OPENSSLDIR is not /etc/$PRODUCT/ssl"
fi

if [ -f "$MODULE" ]; then
	pass "module file $MODULE exists"
	LDD="$(ldd "$MODULE" 2>&1)"
	if grep -q 'not found' <<<"$LDD"; then
		fail "unresolved libraries in $MODULE: $(grep 'not found' <<<"$LDD" | tr -s ' \t' ' ')"
	elif grep -q "libmodsecurity.so.* => $PREFIX/modsecurity/lib/" <<<"$LDD"; then
		pass "libmodsecurity resolves from $PREFIX/modsecurity/lib"
	else
		fail "libmodsecurity does not resolve from $PREFIX/modsecurity/lib"
	fi
	# The module's search path must be exactly the product prefix, with no
	# leftover path from the build directory.
	RUNPATH="$(readelf -d "$MODULE" | sed -n 's/.*(\(RUNPATH\|RPATH\)).*\[\(.*\)\]/\2/p')"
	if [ "$RUNPATH" = "$PREFIX/modsecurity/lib" ]; then
		pass "module RUNPATH is $RUNPATH"
	else
		fail "module RUNPATH is '$RUNPATH', want '$PREFIX/modsecurity/lib'"
	fi
else
	fail "module file $MODULE missing"
fi

# --- 3. nginx -t with load_module, listen 443 quic, self-signed cert --------

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=localhost" \
	-keyout "$TMP/key.pem" -out "$TMP/cert.pem" 2>/dev/null ||
	{ echo "FAIL: cannot create a self-signed certificate (openssl CLI)" >&2; exit 1; }
mkdir -p "$TMP/html"
echo ok >"$TMP/html/index.html"
chmod -R a+rX "$TMP/html"

common_http() {
	cat <<EOF
    access_log off;
    client_body_temp_path $TMP/client_temp;
    proxy_temp_path $TMP/proxy_temp;
    fastcgi_temp_path $TMP/fastcgi_temp;
    uwsgi_temp_path $TMP/uwsgi_temp;
    scgi_temp_path $TMP/scgi_temp;
EOF
}

cat >"$TMP/quic.conf" <<EOF
load_module $MODULE;
pid $TMP/quic.pid;
error_log $TMP/quic-error.log;
events {}
http {
$(common_http)
    server {
        listen 443 ssl;
        listen 443 quic reuseport;
        http2 on;
        http3 on;
        server_name localhost;
        ssl_certificate $TMP/cert.pem;
        ssl_certificate_key $TMP/key.pem;
        ssl_protocols TLSv1.2 TLSv1.3;
        add_header Alt-Svc 'h3=":443"; ma=86400';
        root $TMP/html;
    }
}
EOF
if OUT="$("$NGINX" -t -c "$TMP/quic.conf" 2>&1)"; then
	pass "nginx -t: load_module + listen 443 quic + self-signed cert"
else
	fail "nginx -t on the QUIC config: $OUT"
fi

# --- 4. Runtime: HTTP/2, ModSecurity off by default and on when enabled ----

cat >"$TMP/run.conf" <<EOF
load_module $MODULE;
pid $TMP/run.pid;
error_log $TMP/run-error.log;
daemon on;
events {}
http {
$(common_http)
    # The rule engine is on and a blocking rule is loaded for every server.
    # Only the server with "modsecurity on" must apply it. The rule answers
    # 406, a status nothing else in this config produces.
    modsecurity_rules '
        SecRuleEngine On
        SecRequestBodyAccess On
        SecRule ARGS:probe "@streq attack" "id:1000001,phase:1,deny,status:406,log"
        SecRule REQUEST_HEADERS:Content-Type "@beginsWith application/json" "id:1000002,phase:1,pass,nolog,ctl:requestBodyProcessor=JSON"
        SecRule ARGS:json.probe "@streq attack" "id:1000003,phase:2,deny,status:406,log"
    ';
    server {
        listen 127.0.0.1:18080;
        root $TMP/html;
    }
    server {
        listen 127.0.0.1:18081;
        modsecurity on;
        root $TMP/html;
    }
    server {
        listen 127.0.0.1:18443 ssl;
        listen 127.0.0.1:18443 quic reuseport;
        http2 on;
        http3 on;
        ssl_certificate $TMP/cert.pem;
        ssl_certificate_key $TMP/key.pem;
        root $TMP/html;
    }
}
EOF

http_code() { curl -s -o /dev/null -w '%{http_code}' "$@" || true; }

if OUT="$("$NGINX" -c "$TMP/run.conf" 2>&1)"; then
	for _ in 1 2 3 4 5 6 7 8 9 10; do
		[ -s "$TMP/run.pid" ] && break
		sleep 0.5
	done
	NGINX_PID="$(cat "$TMP/run.pid" 2>/dev/null || true)"

	# nginx -t does not bind sockets; check the QUIC listener really is a
	# UDP socket on port 18443 in the kernel's table (ports are hex there).
	if grep -q -i ":$(printf '%04X' 18443) " /proc/net/udp /proc/net/udp6 2>/dev/null; then
		pass "nginx listens on UDP port 18443 (QUIC)"
	else
		fail "no UDP socket on port 18443"
	fi
	code="$(http_code 'http://127.0.0.1:18080/?probe=attack')"
	if [ "$code" = 200 ]; then
		pass "ModSecurity is off without 'modsecurity on' (S-3): HTTP $code"
	else
		fail "server without 'modsecurity on' returned HTTP $code, want 200"
	fi
	code="$(http_code 'http://127.0.0.1:18081/?probe=attack')"
	if [ "$code" = 406 ]; then
		pass "ModSecurity blocks with 'modsecurity on': HTTP $code"
	else
		fail "server with 'modsecurity on' returned HTTP $code, want 406"
	fi
	if grep -q 'id "1000001"' "$TMP/run-error.log" 2>/dev/null; then
		pass "ModSecurity logged rule 1000001"
	else
		fail "ModSecurity did not log rule 1000001"
	fi
	code="$(http_code 'http://127.0.0.1:18081/?probe=fine')"
	if [ "$code" = 200 ]; then
		pass "ModSecurity passes a clean request: HTTP $code"
	else
		fail "clean request returned HTTP $code, want 200"
	fi
	# JSON request bodies are parsed only when libmodsecurity has YAJL,
	# which EL10 does not ship (build.sh builds without it there).
	code="$(http_code -X POST -H 'Content-Type: application/json' \
		--data '{"probe":"attack"}' 'http://127.0.0.1:18081/')"
	if [ "$EXPECT_JSON" = 1 ]; then
		if [ "$code" = 406 ]; then
			pass "ModSecurity inspects JSON request bodies: HTTP $code"
		else
			fail "JSON body with a matching value returned HTTP $code, want 406"
		fi
	else
		if [ "$code" = 406 ]; then
			fail "JSON body blocked although this OS has no YAJL; update smoke-test.sh"
		else
			printf 'NOTE: no YAJL on this OS: JSON request bodies are not inspected (HTTP %s)\n' "$code"
		fi
	fi
	ver="$(curl -sk --http2 -o /dev/null -w '%{http_version} %{http_code}' https://127.0.0.1:18443/ || true)"
	if [ "$ver" = "2 200" ]; then
		pass "HTTP/2 over TLS works"
	else
		fail "HTTP/2 over TLS: got HTTP version and code '$ver', want '2 200'"
	fi
	if grep -q -E '\[(emerg|alert|crit)\]' "$TMP/run-error.log" 2>/dev/null; then
		fail "errors in the runtime log: $(grep -E '\[(emerg|alert|crit)\]' "$TMP/run-error.log")"
	fi
else
	fail "nginx did not start: $OUT"
fi

# --- 5. Installed configuration leaves ModSecurity off (S-3) ----------------

if [ -f "$CONF" ]; then
	if grep -q -E '^[[:space:]]*(load_module[^;]*modsecurity|modsecurity[[:space:]]+on)' "$CONF"; then
		fail "$CONF loads or enables ModSecurity"
	else
		pass "$CONF does not load or enable ModSecurity (S-3)"
	fi
	if OUT="$("$NGINX" -t -c "$CONF" 2>&1)"; then
		pass "nginx -t on the installed $CONF"
	else
		fail "nginx -t on the installed $CONF: $OUT"
	fi
else
	fail "$CONF missing"
fi

if [ "$FAILED" = 0 ]; then
	echo "All smoke tests passed."
else
	echo "Some smoke tests FAILED."
	exit 1
fi
