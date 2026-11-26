#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Build nginx from source with TLS, HTTP/2, HTTP/3 (QUIC) and ModSecurity 3
# (requirements I-2, M-1, S-1).
#
# - OpenSSL 3.5 LTS is compiled from source and linked statically, so QUIC
#   uses the native OpenSSL QUIC API on every supported OS.
# - libmodsecurity is installed under its own prefix; the nginx connector is
#   a dynamic module that is only active when nginx.conf loads it.
# - Every download is checked against a pinned SHA-256 and a PGP signature
#   (versions.env, keys/).
# - Nothing is installed until every component has been built: a failed
#   build leaves an existing installation untouched.
#
# Run as root on the target server. See docs/build.md.

set -Eeuo pipefail
umask 022

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source-path=SCRIPTDIR source=versions.env
. "$SCRIPT_DIR/versions.env"

# The product name is a working title. Every installed path derives from it.
PRODUCT="${PRODUCT:-fngx}"

usage() {
	cat <<EOF
Usage: $(basename "$0") [options]

Options:
  --nginx-version X.Y.Z  nginx version to build (default: $NGINX_VERSION).
                         A non-default version is verified by PGP only.
  --product NAME         product name used in all paths (default: $PRODUCT)
  --jobs N               parallel make jobs (default: number of CPUs)
  --workdir DIR          build directory (default: a new directory in /var/tmp)
  --keep-workdir         do not delete the build directory on success
  --skip-deps            do not install build dependencies
  --with-pagespeed       also build the PageSpeed module (not supported, see docs)
  -h, --help             show this help

Environment: PRODUCT has the same meaning as --product.
EOF
}

log() { printf '==> %s\n' "$*" >&2; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

NGINX_SHA256_PINNED="$NGINX_SHA256"
NGINX_VERSION_DEFAULT="$NGINX_VERSION"
JOBS=""
WORKDIR=""
KEEP_WORKDIR=0
SKIP_DEPS=0
WITH_PAGESPEED=0

while [ $# -gt 0 ]; do
	case "$1" in
	--nginx-version) [ $# -ge 2 ] || die "$1 needs a value"; NGINX_VERSION="$2"; shift 2 ;;
	--nginx-version=*) NGINX_VERSION="${1#*=}"; shift ;;
	--product) [ $# -ge 2 ] || die "$1 needs a value"; PRODUCT="$2"; shift 2 ;;
	--product=*) PRODUCT="${1#*=}"; shift ;;
	--jobs) [ $# -ge 2 ] || die "$1 needs a value"; JOBS="$2"; shift 2 ;;
	--jobs=*) JOBS="${1#*=}"; shift ;;
	--workdir) [ $# -ge 2 ] || die "$1 needs a value"; WORKDIR="$2"; shift 2 ;;
	--workdir=*) WORKDIR="${1#*=}"; shift ;;
	--keep-workdir) KEEP_WORKDIR=1; shift ;;
	--skip-deps) SKIP_DEPS=1; shift ;;
	--with-pagespeed) WITH_PAGESPEED=1; shift ;;
	-h | --help) usage; exit 0 ;;
	*) usage >&2; die "unknown option: $1" ;;
	esac
done

# Validate everything that ends up in paths, URLs or command lines.
[[ "$PRODUCT" =~ ^[a-z][a-z0-9-]{0,31}$ ]] || die "invalid product name: $PRODUCT"
[[ "$NGINX_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "invalid nginx version: $NGINX_VERSION"
if [ -z "$JOBS" ]; then
	JOBS="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)"
fi
[[ "$JOBS" =~ ^[1-9][0-9]*$ ]] || die "invalid --jobs value: $JOBS"

if [ "$WITH_PAGESPEED" = 1 ]; then
	die "--with-pagespeed is not supported: no way was found to build the We-Amp
PageSpeed module against this nginx from source. See docs/build.md,
section \"PageSpeed\". Build again without --with-pagespeed."
fi

if [ "$NGINX_VERSION" = "$NGINX_VERSION_DEFAULT" ]; then
	NGINX_SHA256="$NGINX_SHA256_PINNED"
else
	NGINX_SHA256=""
fi

# Installed layout. Proposal of the developer, see docs/build.md.
PREFIX="/opt/$PRODUCT"
NGINX_PREFIX="$PREFIX/nginx"
MODSEC_PREFIX="$PREFIX/modsecurity"
CONF_DIR="/etc/$PRODUCT/nginx"
LOG_DIR="/var/log/$PRODUCT/nginx"
RUN_DIR="/run/$PRODUCT"
CACHE_DIR="/var/cache/$PRODUCT/nginx"

[ "$(id -u)" = 0 ] || die "run as root"
[ "$(uname -s)" = Linux ] || die "only Linux is supported"
if [ "$(uname -m)" != x86_64 ]; then
	log "warning: $(uname -m) is not a tested architecture (x86_64 is)"
fi

# --- OS detection -----------------------------------------------------------

OS_FAMILY=""

detect_os() {
	[ -r /etc/os-release ] || die "/etc/os-release not found"
	local id version_id
	# shellcheck disable=SC1091
	id="$(. /etc/os-release && echo "${ID:-}")"
	# shellcheck disable=SC1091
	version_id="$(. /etc/os-release && echo "${VERSION_ID:-}")"
	case "$id:$version_id" in
	almalinux:8* | almalinux:9* | almalinux:10* | cloudlinux:8* | cloudlinux:9* | cloudlinux:10*)
		OS_FAMILY=el ;;
	ubuntu:22.04 | ubuntu:24.04)
		OS_FAMILY=deb ;;
	*)
		die "unsupported OS: $id $version_id (supported: AlmaLinux and CloudLinux 8, 9, 10; Ubuntu 22.04, 24.04)" ;;
	esac
	log "OS: $id $version_id ($OS_FAMILY)"
}

# --- Build dependencies -----------------------------------------------------

install_deps_el() {
	# yajl-devel is in the CRB repository (PowerTools on EL8). It is
	# enabled for this transaction only; the system repo setup is unchanged.
	local repos=() r
	while read -r r; do
		repos+=("--enablerepo=$r")
	done < <(dnf -q repolist --all 2>/dev/null |
		awk 'NR > 1 { print $1 }' |
		grep -i -E '(^|[-_])(crb|powertools)$' || true)
	if [ "${#repos[@]}" -eq 0 ]; then
		log "warning: no CRB/PowerTools repository found; yajl-devel may be missing"
	fi
	# /usr/bin/curl is requested by path: EL9+ images ship curl-minimal,
	# which conflicts with the full curl package.
	dnf -y "${repos[@]}" install \
		gcc gcc-c++ make perl pkgconf-pkg-config \
		tar gzip gnupg2 /usr/bin/curl ca-certificates findutils diffutils openssl \
		pcre2-devel zlib-devel libxml2-devel yajl-devel
}

install_deps_deb() {
	export DEBIAN_FRONTEND=noninteractive
	apt-get update
	apt-get install -y --no-install-recommends \
		build-essential perl pkg-config \
		tar gzip gnupg curl ca-certificates openssl \
		libpcre2-dev zlib1g-dev libxml2-dev libyajl-dev
}

# --- Download and verification ----------------------------------------------

# curl's own --retry skips connection errors such as TLS handshake failures,
# and --retry-all-errors needs curl 7.71 (EL8 has 7.61), hence the loop.
fetch() {
	local url="$1" out="$2" attempt rc=0
	for attempt in 1 2 3 4 5; do
		rc=0
		curl --proto '=https' --tlsv1.2 -fsSL --connect-timeout 30 \
			--max-time 900 -o "$out" "$url" || rc=$?
		[ "$rc" = 0 ] && return 0
		log "download failed (curl exit $rc, attempt $attempt of 5): $url"
		sleep $((attempt * 5))
	done
	die "cannot download $url (curl exit $rc)"
}

# verify FILE SHA256 FINGERPRINTS KEYFILE
# SHA256 may be empty (then only the signature is checked).
verify() {
	local file="$1" sha="$2" fprs="$3" keyfile="$4"
	local name status primary fpr ok=0
	name="$(basename "$file")"

	if [ -n "$sha" ]; then
		echo "$sha  $file" | sha256sum -c --status - ||
			die "$name: SHA-256 mismatch (expected $sha, got $(sha256sum "$file" | cut -d' ' -f1))"
		log "$name: SHA-256 OK"
	else
		log "$name: no pinned SHA-256, signature check only ($(sha256sum "$file" | cut -d' ' -f1))"
	fi

	local gnupghome
	gnupghome="$(mktemp -d "$WORKDIR/gnupg.XXXXXX")"
	gpg --homedir "$gnupghome" --batch --quiet --import "$keyfile" 2>/dev/null ||
		die "cannot import $keyfile"
	status="$(gpg --homedir "$gnupghome" --batch --status-fd 1 \
		--verify "$file.asc" "$file" 2>/dev/null)" ||
		die "$name: PGP signature verification failed"
	rm -rf "$gnupghome"

	# [GNUPG:] VALIDSIG <fpr> <date> <ts> <exp> <ver> <res> <algo> <hash> <class> <primary-fpr>
	primary="$(printf '%s\n' "$status" | awk '$2 == "VALIDSIG" { print $12; exit }')"
	[ -n "$primary" ] || die "$name: no valid signature found"
	for fpr in $fprs; do
		[ "$fpr" = "$primary" ] && ok=1
	done
	[ "$ok" = 1 ] || die "$name: signed by unexpected key $primary"
	log "$name: PGP signature OK (key $primary)"
}

# get NAME URL SHA256 FINGERPRINTS KEYFILE TOPDIR
# Downloads, verifies and unpacks a tarball into $SRC/TOPDIR.
get() {
	local name="$1" url="$2" sha="$3" fprs="$4" keyfile="$5" topdir="$6"
	local file="$DL/$name"
	log "downloading $url"
	fetch "$url" "$file"
	fetch "$url.asc" "$file.asc"
	verify "$file" "$sha" "$fprs" "$keyfile"

	# Refuse archives with absolute paths, '..' or a different top directory.
	if tar -tzf "$file" | grep -v -E "^$topdir(/|$)" | grep -q .; then
		die "$name: unexpected paths in archive"
	fi
	tar -xzf "$file" -C "$SRC" --no-same-owner --no-same-permissions
	[ -d "$SRC/$topdir" ] || die "$name: $topdir not found after unpacking"
}

# --- Build steps ------------------------------------------------------------

# Hardening flags similar to the nginx.org packages.
CC_OPT="-O2 -pipe -Wformat -Werror=format-security -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fstack-clash-protection -fPIC"
LD_OPT="-Wl,-z,relro -Wl,-z,now -pie"

build_modsecurity() {
	log "building libmodsecurity $MODSECURITY_VERSION"
	cd "$SRC/modsecurity-v$MODSECURITY_VERSION"
	# Optional features (remote rules, GeoIP, LMDB, Lua, ssdeep) are off:
	# fewer dependencies, smaller attack surface. See docs/build.md.
	./configure \
		--prefix="$MODSEC_PREFIX" \
		--disable-static \
		--disable-examples \
		--disable-doxygen-doc \
		--with-pcre2 \
		--with-yajl \
		--with-libxml \
		--without-curl \
		--without-geoip \
		--without-maxmind \
		--without-lmdb \
		--without-lua \
		--without-ssdeep \
		CFLAGS="-O2 -pipe -D_FORTIFY_SOURCE=2 -fstack-protector-strong" \
		CXXFLAGS="-O2 -pipe -D_FORTIFY_SOURCE=2 -fstack-protector-strong"
	make -j"$JOBS"
	make install DESTDIR="$STAGE"
	# libtool archives reference build paths and are not needed at runtime.
	find "$STAGE$MODSEC_PREFIX/lib" -name '*.la' -delete
}

NGINX_MODULES=(
	--with-compat
	--with-threads
	--with-file-aio
	--with-pcre-jit
	--with-http_ssl_module
	--with-http_v2_module
	--with-http_v3_module
	--with-http_realip_module
	--with-http_stub_status_module
	--with-http_gzip_static_module
	--with-http_gunzip_module
	--with-http_sub_module
	--with-http_auth_request_module
	--with-http_secure_link_module
	--with-http_slice_module
	--with-http_mp4_module
	--with-http_flv_module
)

build_nginx() {
	log "building nginx $NGINX_VERSION"
	cd "$SRC/nginx-$NGINX_VERSION"
	# The connector finds libmodsecurity in the staging tree; the runtime
	# path is set with -rpath to the final prefix instead (NGX_IGNORE_RPATH).
	MODSECURITY_INC="$STAGE$MODSEC_PREFIX/include" \
		MODSECURITY_LIB="$STAGE$MODSEC_PREFIX/lib" \
		NGX_IGNORE_RPATH=YES \
		./configure \
		--prefix="$NGINX_PREFIX" \
		--sbin-path="$NGINX_PREFIX/sbin/nginx" \
		--modules-path="$NGINX_PREFIX/modules" \
		--conf-path="$CONF_DIR/nginx.conf" \
		--error-log-path="$LOG_DIR/error.log" \
		--http-log-path="$LOG_DIR/access.log" \
		--pid-path="$RUN_DIR/nginx.pid" \
		--lock-path="$RUN_DIR/nginx.lock" \
		--http-client-body-temp-path="$CACHE_DIR/client_temp" \
		--http-proxy-temp-path="$CACHE_DIR/proxy_temp" \
		--http-fastcgi-temp-path="$CACHE_DIR/fastcgi_temp" \
		--http-uwsgi-temp-path="$CACHE_DIR/uwsgi_temp" \
		--http-scgi-temp-path="$CACHE_DIR/scgi_temp" \
		"${NGINX_MODULES[@]}" \
		--with-openssl="$SRC/openssl-$OPENSSL_VERSION" \
		--with-openssl-opt="no-tests" \
		--add-dynamic-module="$SRC/ModSecurity-nginx-v$MODSECURITY_NGINX_VERSION" \
		--with-cc-opt="$CC_OPT" \
		--with-ld-opt="$LD_OPT -Wl,-rpath,$MODSEC_PREFIX/lib"
	make -j"$JOBS"
	make install DESTDIR="$STAGE"
	# make install does not create the temp directories.
	mkdir -p "$STAGE$CACHE_DIR" "$STAGE$LOG_DIR"
}

# Copy the staged tree over the live system. nginx.conf and other files
# that an administrator may have changed are not overwritten; nginx's own
# install step already keeps an existing nginx.conf the same way.
install_stage() {
	log "installing into $PREFIX and $CONF_DIR"
	local f rel
	mkdir -p "$CONF_DIR" "$LOG_DIR" "$RUN_DIR" "$CACHE_DIR"
	chmod 0750 "$LOG_DIR"
	while IFS= read -r -d '' f; do
		rel="${f#"$STAGE"}"
		if [ -e "$rel" ]; then
			continue
		fi
		mkdir -p "$(dirname "$rel")"
		cp -p "$f" "$rel"
	done < <(find "$STAGE$CONF_DIR" -type f -print0)

	# Binaries and libraries: replace files by rename so a running nginx
	# keeps its open inodes. cp to a temp name then mv is atomic per file.
	local dir
	for dir in "$NGINX_PREFIX" "$MODSEC_PREFIX"; do
		while IFS= read -r -d '' f; do
			rel="${f#"$STAGE"}"
			if [ -d "$f" ] && [ ! -L "$f" ]; then
				mkdir -p "$rel"
			else
				mkdir -p "$(dirname "$rel")"
				cp -P -p "$f" "$rel.new.$$"
				mv -f -T "$rel.new.$$" "$rel"
			fi
		done < <(find "$STAGE$dir" -mindepth 1 -print0 | sort -z)
	done
}

# --- Main -------------------------------------------------------------------

main() {
	detect_os
	local started
	started="$(date +%s)"

	if [ "$SKIP_DEPS" = 0 ]; then
		log "installing build dependencies"
		"install_deps_$OS_FAMILY"
		log "dependencies installed in $(($(date +%s) - started)) s"
		started="$(date +%s)"
	fi
	local tool
	for tool in curl gpg sha256sum tar make gcc g++ perl; do
		command -v "$tool" >/dev/null || die "missing build tool: $tool"
	done

	if [ -z "$WORKDIR" ]; then
		WORKDIR="$(mktemp -d "/var/tmp/$PRODUCT-nginx-build.XXXXXX")"
	else
		mkdir -p "$WORKDIR"
	fi
	WORKDIR="$(cd "$WORKDIR" && pwd)"
	DL="$WORKDIR/dl"
	SRC="$WORKDIR/src"
	STAGE="$WORKDIR/stage"
	rm -rf "$DL" "$SRC" "$STAGE"
	mkdir -p "$DL" "$SRC" "$STAGE"
	log "work directory: $WORKDIR"

	get "nginx-$NGINX_VERSION.tar.gz" \
		"$NGINX_URL_BASE/nginx-$NGINX_VERSION.tar.gz" \
		"$NGINX_SHA256" "$NGINX_PGP_FPRS" "$SCRIPT_DIR/keys/nginx.asc" \
		"nginx-$NGINX_VERSION"
	get "openssl-$OPENSSL_VERSION.tar.gz" \
		"$OPENSSL_URL_BASE/openssl-$OPENSSL_VERSION/openssl-$OPENSSL_VERSION.tar.gz" \
		"$OPENSSL_SHA256" "$OPENSSL_PGP_FPRS" "$SCRIPT_DIR/keys/openssl.asc" \
		"openssl-$OPENSSL_VERSION"
	get "modsecurity-v$MODSECURITY_VERSION.tar.gz" \
		"$MODSECURITY_URL_BASE/v$MODSECURITY_VERSION/modsecurity-v$MODSECURITY_VERSION.tar.gz" \
		"$MODSECURITY_SHA256" "$MODSECURITY_PGP_FPRS" "$SCRIPT_DIR/keys/modsecurity.asc" \
		"modsecurity-v$MODSECURITY_VERSION"
	get "ModSecurity-nginx-v$MODSECURITY_NGINX_VERSION.tar.gz" \
		"$MODSECURITY_NGINX_URL_BASE/v$MODSECURITY_NGINX_VERSION/ModSecurity-nginx-v$MODSECURITY_NGINX_VERSION.tar.gz" \
		"$MODSECURITY_NGINX_SHA256" "$MODSECURITY_NGINX_PGP_FPRS" "$SCRIPT_DIR/keys/modsecurity.asc" \
		"ModSecurity-nginx-v$MODSECURITY_NGINX_VERSION"

	build_modsecurity
	build_nginx
	install_stage

	"$NGINX_PREFIX/sbin/nginx" -V

	if [ "$KEEP_WORKDIR" = 0 ]; then
		rm -rf "$WORKDIR"
	else
		log "kept work directory $WORKDIR"
	fi
	log "downloaded, built and installed in $(($(date +%s) - started)) s: $NGINX_PREFIX/sbin/nginx"
}

main
