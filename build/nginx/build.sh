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
trap 'printf "error: %s failed at line %s (exit %s)\n" "${BASH_COMMAND%% *}" "$LINENO" "$?" >&2' ERR

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
  --workdir DIR          parent of the new build directory (default: /var/tmp);
                         must be owned by root and not writable by others
                         unless it has the sticky bit
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
# OpenSSL's compiled-in configuration directory. By default it would point
# into the build directory, which is deleted after the build and lives in a
# world-writable parent. nginx built with --with-openssl does not read
# openssl.cnf unless OPENSSL_CONF is set (NGX_OPENSSL_NO_CONFIG), but the
# path is fixed anyway. Engines and loadable modules are not built and
# dynamic loading is disabled (no-dso), so the module and engine paths,
# which nginx's build keeps under the build directory, are never used.
OPENSSL_DIR="/etc/$PRODUCT/ssl"

[ "$(id -u)" = 0 ] || die "run as root"
[ "$(uname -s)" = Linux ] || die "only Linux is supported"
if [ "$(uname -m)" != x86_64 ]; then
	log "warning: $(uname -m) is not a tested architecture (x86_64 is)"
fi

# --- OS detection -----------------------------------------------------------

OS_FAMILY=""
# YAJL gives libmodsecurity its JSON request body parser. RHEL 10 and
# EPEL 10 do not ship it, so on EL10 libmodsecurity is built without it.
# See docs/build.md, "YAJL on EL10".
WITH_YAJL=1

detect_os() {
	[ -r /etc/os-release ] || die "/etc/os-release not found"
	local id version_id
	# shellcheck disable=SC1091
	id="$(. /etc/os-release && echo "${ID:-}")"
	# shellcheck disable=SC1091
	version_id="$(. /etc/os-release && echo "${VERSION_ID:-}")"
	case "$id:$version_id" in
	almalinux:8* | almalinux:9* | almalinux:10* | cloudlinux:8* | cloudlinux:9* | cloudlinux:10*)
		OS_FAMILY=el
		case "$version_id" in 10*) WITH_YAJL=0 ;; esac ;;
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
	local repos=() r yajl=()
	if [ "$WITH_YAJL" = 1 ]; then
		yajl=(yajl-devel)
	fi
	while read -r r; do
		repos+=("--enablerepo=$r")
	done < <(dnf -q repolist --all 2>/dev/null |
		awk 'NR > 1 { print $1 }' |
		grep -i -E '(^|[-_])(crb|powertools)$' || true)
	if [ "${#repos[@]}" -eq 0 ] && [ "$WITH_YAJL" = 1 ]; then
		log "warning: no CRB/PowerTools repository found; yajl-devel may be missing"
	fi
	# /usr/bin/curl is requested by path: EL9+ images ship curl-minimal,
	# which conflicts with the full curl package.
	dnf -y "${repos[@]}" install \
		gcc gcc-c++ make perl pkgconf-pkg-config \
		tar gzip gnupg2 /usr/bin/curl ca-certificates findutils diffutils openssl \
		pcre2-devel zlib-devel libxml2-devel "${yajl[@]}"
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
		curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL --connect-timeout 30 \
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
	gpg --homedir "$gnupghome" --batch --quiet --import "$keyfile" 2>"$gnupghome/import.err" ||
		die "cannot import $keyfile: $(cat "$gnupghome/import.err")"
	status="$(gpg --homedir "$gnupghome" --batch --status-fd 1 \
		--verify "$file.asc" "$file" 2>"$gnupghome/verify.err")" ||
		die "$name: PGP signature verification failed: $(cat "$gnupghome/verify.err")"
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

	# Refuse archives with absolute paths, '..' components or entries
	# outside the expected top directory. The listing is read in full
	# first: a pipeline that stops early would hide a failure.
	local list entry
	list="$(tar -tzf "$file")" || die "$name: cannot list archive"
	while IFS= read -r entry; do
		case "$entry" in
		"$topdir" | "$topdir/" | "$topdir"/*) ;;
		*) die "$name: entry outside $topdir/: $entry" ;;
		esac
		case "/$entry/" in
		*/../*) die "$name: '..' in archive entry: $entry" ;;
		esac
	done <<<"$list"
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
	local yajl_opt=--with-yajl
	if [ "$WITH_YAJL" = 0 ]; then
		yajl_opt=--without-yajl
		log "warning: building libmodsecurity without YAJL: JSON request bodies are not parsed (docs/build.md)"
	fi
	# Optional features (remote rules, GeoIP, LMDB, Lua, ssdeep) are off:
	# fewer dependencies, smaller attack surface. See docs/build.md.
	./configure \
		--prefix="$MODSEC_PREFIX" \
		--disable-static \
		--disable-examples \
		--disable-doxygen-doc \
		--with-pcre2 \
		"$yajl_opt" \
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
		--with-openssl-opt="no-tests no-dso no-module no-engine --openssldir=$OPENSSL_DIR" \
		--add-dynamic-module="$SRC/ModSecurity-nginx-v$MODSECURITY_NGINX_VERSION" \
		--with-cc-opt="$CC_OPT" \
		--with-ld-opt="$LD_OPT -Wl,-rpath,$MODSEC_PREFIX/lib"
	make -j"$JOBS"
	make install DESTDIR="$STAGE"
	# make install does not create the temp directories.
	mkdir -p "$STAGE$CACHE_DIR" "$STAGE$LOG_DIR"
}

# Copy the staged tree over the live system.
#
# Configuration: files that already exist in $CONF_DIR are never
# overwritten (an administrator or the plugin may have changed them); only
# the *.default reference copies are refreshed.
#
# Binaries and libraries: each file is copied under a temporary name and
# renamed over the old one, so a running nginx keeps its open files. The
# order is libmodsecurity, then the nginx modules and binary. This is not
# atomic as a whole: a failure in the middle, or an nginx start during the
# copy, can meet a mix of old and new files (see docs/build.md). A running
# nginx keeps the old binary until it is restarted or upgraded in place.
install_stage() {
	log "installing into $PREFIX and $CONF_DIR"
	local f rel
	local d
	for d in "$STAGE$CONF_DIR" "$STAGE$NGINX_PREFIX/sbin" "$STAGE$NGINX_PREFIX/modules" "$STAGE$MODSEC_PREFIX/lib"; do
		[ -d "$d" ] || die "staging directory missing: $d"
	done
	mkdir -p "$CONF_DIR" "$LOG_DIR" "$RUN_DIR" "$CACHE_DIR" "$OPENSSL_DIR"
	chmod 0750 "$LOG_DIR"
	while IFS= read -r -d '' f; do
		rel="${f#"$STAGE"}"
		if [ -e "$rel" ] && [ "${rel%.default}" = "$rel" ]; then
			continue
		fi
		mkdir -p "$(dirname "$rel")"
		cp -p "$f" "$rel.new.$$"
		mv -f -T "$rel.new.$$" "$rel"
	done < <(find "$STAGE$CONF_DIR" -type f -print0)

	local dir
	for dir in "$MODSEC_PREFIX" "$NGINX_PREFIX"; do
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
	log "installed; a running nginx must be restarted (or upgraded with USR2) to use the new binary"
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

	# The build always runs in a new directory created by mktemp (mode 0700,
	# owned by root), so the script never deletes or reuses a directory it
	# did not create. Its parent must not let other users rename it.
	local parent="${WORKDIR:-/var/tmp}" owner mode
	[ -d "$parent" ] || die "--workdir: $parent is not a directory"
	owner="$(stat -L -c %u "$parent")"
	mode="$(stat -L -c %a "$parent")"
	[ "$owner" = 0 ] || die "--workdir: $parent is not owned by root"
	if [ $((8#$mode & 8#0022)) -ne 0 ] && [ $((8#$mode & 8#1000)) -eq 0 ]; then
		die "--workdir: $parent is writable by others and has no sticky bit"
	fi
	WORKDIR="$(mktemp -d "$parent/$PRODUCT-nginx-build.XXXXXX")"
	DL="$WORKDIR/dl"
	SRC="$WORKDIR/src"
	STAGE="$WORKDIR/stage"
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
