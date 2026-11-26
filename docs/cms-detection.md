# CMS detection

Package `internal/cms` looks at a site's document root and suggests an
application template (requirements T-2, T-10). It only suggests: it never
changes files and never assigns a template.

## Result

`Detect(docroot, uid)` (or `DetectUnder(home, "public_html/blog", uid)`,
see below) returns zero or more candidates. Each has:

- the application and, where it changes the suggestion, a variant;
- the suggested template name;
- a confidence: `high`, `medium` or `low`;
- the evidence: the marker paths that were found (never file contents);
- an optional document root hint, when the application should be served
  from a subdirectory of the current document root.

`Result.Suggestion()` returns the best candidate unless another template
has the same confidence; then the result is ambiguous and nothing is
suggested. `Result.Ignored` lists marker paths that exist but were not
used (symlinks, FIFOs, devices, unreadable or foreign-owned files).

## Rules

A rule matches when all its required markers exist with the right type
(regular file or directory, never a symlink). Confidence is `high` when
enough supporting markers exist (column "high at"), `medium` otherwise,
capped by the rule. Rules that need file contents run only when no
layout rule matched with `high` confidence.

| Application | Variant | Template | Required | Supporting (high at) | Source |
| --- | --- | --- | --- | --- | --- |
| WordPress | | `wordpress` | `wp-settings.php`, `wp-includes/` | `wp-load.php`, `wp-login.php`, `wp-admin/`, `wp-includes/version.php`, `wp-config.php`, `wp-config-sample.php` (3) | [WordPress repository](https://github.com/WordPress/WordPress); [wp-config.php](https://developer.wordpress.org/advanced-administration/wordpress/wp-config/) |
| Joomla | | `joomla` | `administrator/index.php`, `includes/defines.php` | `libraries/src/Version.php` (3.8+), `libraries/cms/version/version.php` (3.x), `configuration.php`, `index.php` (2) | [joomla-cms](https://github.com/joomla/joomla-cms), checked on 3.6.5, 3.10.12 and the default branch |
| Drupal | 8+ | `drupal` | `core/lib/Drupal.php` | `index.php`, `autoload.php`, `sites/`, `core/includes/bootstrap.inc` (2) | [drupal/drupal](https://github.com/drupal/drupal) |
| Drupal | 8+, Composer project root | `drupal`, hint `web` | `web/core/lib/Drupal.php` | `composer.json`, `web/index.php`, `vendor/` (2) | [drupal/recommended-project](https://github.com/drupal/recommended-project): `"web-root": "web/"` |
| Drupal | 7 | `drupal7` | `includes/bootstrap.inc`, `modules/system/system.module` | `misc/drupal.js`, `index.php`, `cron.php`, `sites/` (2) | [drupal/drupal branch 7.x](https://github.com/drupal/drupal/tree/7.x) |
| Laravel | project root | `laravel`, hint `public` | `artisan`, `public/index.php`, `bootstrap/app.php` | `composer.json`, `routes/`, `app/`, `vendor/` (2) | [laravel/laravel](https://github.com/laravel/laravel); [deployment](https://laravel.com/docs/deployment): the server must point at `public/` |
| Laravel | public | `laravel` | `index.php` containing `bootstrap/app.php` and `LARAVEL_START` or `Illuminate\Http\Request` (first 8 KiB) | none; max `medium` | `public/index.php` in laravel/laravel, checked on branches 5.0, 5.3, 5.4, 5.5, 5.8, 8.x, 10.x, 12.x; the path is not matched because shared-hosting installs edit it |
| OpenCart | | `opencart` | `system/startup.php`, `catalog/` | `system/engine/`, `admin/`, `config.php`, `config-dist.php`, `image/` (2) | [opencart](https://github.com/opencart/opencart), directory `upload/` on 3.0.x.x, 4.1.x.x, master |
| React | create-react-app | `react` | `index.html`, `asset-manifest.json`, `static/js/` | `manifest.json`, `robots.txt` (0) | [Production build](https://create-react-app.dev/docs/production-build/); `asset-manifest.json` is written by react-scripts' webpack config |
| React | vite | `react` | `index.html` with `id="root"` (first 16 KiB), `assets/` | none; max `medium` | [Vite build options](https://vite.dev/config/build-options): `outDir` `dist`, `assetsDir` `assets`; create-vite `template-react/index.html` |
| React | spa | `react` | `index.html` with `id="root"` | none; max `low` | cra-template and create-vite templates use `<div id="root">`; other SPAs fit the same template |

Versions are told apart only where the suggestion changes: Drupal 7 needs
a different front controller rewrite than Drupal 8+, and a Laravel or
Drupal project root used as the document root gets a hint to serve
`public/` or `web/` instead.

## Limitations

- An application in a subdirectory of the document root (for example
  WordPress in `blog/`) is not found: the package never lists
  directories. Checking a fixed list of common subdirectory names would
  multiply the cost per site; it can be added if needed.
- A document root that is itself a symlink (for example `public_html`
  pointing to `laravel/public`) is refused with an error. A caller that
  wants to follow it must resolve it within the home directory only,
  refuse targets outside it, and call `DetectUnder(home, target)`.
- Detection is a heuristic over files the client controls. A client can
  make a site look like any application; the result is a suggestion only.

## Security

Detection runs as root over client-owned trees, so it:

- takes the site owner's uid from the caller (the system user
  database), never from the tree. The document root (and, for
  `DetectUnder`, every component leading to it) must be owned by it.
  Below the document root a directory is entered and a file is read only
  if the owner owns it or the "other" permission bits let everyone search
  or read it, that is, only what the client could look at anyway. So
  sites whose files belong to the web server user are still detected,
  while a hard link to a private file of root or another user, or
  another user's private directory moved into the client's tree, is
  skipped. Assumption: no ACL or LSM rule denies the client what the
  "other" bits grant;
- wraps every error in `cms.ErrUnavailable`. The detailed message ("does
  not exist", "owner differs") is for the server log only; clients must
  see only the generic text, or a misused `Detect` would tell them
  whether paths they cannot see exist;
- accepts only clean document root paths: a trailing `/` or `/.` would
  make the kernel follow a final symlink despite `O_NOFOLLOW`;
- opens the document root with `O_NOFOLLOW` and walks below it only with
  `openat(..., O_NOFOLLOW)` from directory descriptors; markers are
  checked with `fstatat(..., AT_SYMLINK_NOFOLLOW)`. Symlinks are never
  followed, `..` is never walked, nothing outside the document root is
  read;
- `DetectUnder(base, rel)` also opens every component of `rel` without
  following symlinks; use it whenever the path below a trusted base (the
  home directory) is controlled by the client;
- probes a fixed list of paths: at most 108 operations per site with the
  current rules (83 on a tree that has every marker), hard limit 128; no
  directory listing, no recursion;
- reads only `index.php` (8 KiB) and `index.html` (16 KiB) prefixes, only
  regular files allowed by the rule above; on Linux the file is opened with
  `O_PATH` first (no open routine runs, so a FIFO or device is never
  opened for reading), checked with `fstat` against the earlier
  `fstatat` (type, owner, device, inode), then reopened through
  `/proc/self/fd` with `O_NONBLOCK|O_NOCTTY|O_NOATIME`, so access times
  do not change; never reads `wp-config.php`, `configuration.php`,
  `config.php` or `.env`;
- searches the prefix for fixed substrings only and returns no content.

Races: replacing a marker with a symlink, FIFO or another file between
the check and the open is detected. Changing the tree between two probes
can produce a result that mixes two states of the tree; it is only a
suggestion. The client can notice that a scan runs (inotify, file
leases) but learns nothing else. A system call on a hung network or FUSE
file system can block and cannot be cancelled; a goroutine given up on
keeps its descriptors. Batch callers should bound outstanding scans or
run detection in a child process they can kill.

Follow-up, not implemented: run detection in a helper process with the
site owner's identity and a hard timeout, as a second barrier.

## Cost

`BenchmarkDetect_N1` runs over 1,000 synthetic document roots (half
WordPress, the rest spread over all fixtures), warm page cache:

| Platform | Per site | 10,000 sites |
| --- | --- | --- |
| Linux x86_64 (container) | 22-45 µs (varies between runs) | 0.2-0.45 s |
| macOS (development machine) | 72 µs | 0.7 s |

A cold cache adds disk seeks for each probed directory; at most a few
dozen metadata lookups per site.

`golang.org/x/sys` (BSD-3-Clause, GPL-compatible) provides `openat` and
`fstatat`.
