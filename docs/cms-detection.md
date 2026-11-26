# CMS detection

Package `internal/cms` looks at a site's document root and suggests an
application template (requirements T-2, T-10). It only suggests: it never
changes files and never assigns a template.

## Result

`Detect(docroot)` (or `DetectUnder(home, "public_html/blog")`, see below)
returns zero or more candidates. Each has:

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
| Laravel | public | `laravel` | `index.php` containing `LARAVEL_START` and `/../bootstrap/app.php` (first 8 KiB) | none; max `medium` | `public/index.php` in laravel/laravel, checked on branches 5.8, 8.x, 10.x, 12.x |
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
  pointing to `laravel/public`) is refused with an error. The caller
  decides whether to resolve it and call `DetectUnder` on the target.
- Detection is a heuristic over files the client controls. A client can
  make a site look like any application; the result is a suggestion only.

## Security

Detection runs as root over client-owned trees, so it:

- opens the document root with `O_NOFOLLOW` and walks below it only with
  `openat(..., O_NOFOLLOW)` from directory descriptors; markers are
  checked with `fstatat(..., AT_SYMLINK_NOFOLLOW)`. Symlinks are never
  followed, `..` is never walked, nothing outside the document root is
  read;
- `DetectUnder(base, rel)` also opens every component of `rel` without
  following symlinks; use it whenever the path below a trusted base (the
  home directory) is controlled by the client;
- probes a fixed list of paths: at most 66 operations per site with the
  current rules, hard limit 96; no directory listing, no recursion;
- reads only `index.php` (8 KiB) and `index.html` (16 KiB) prefixes, only
  regular files owned by the document root owner, opened with
  `O_NONBLOCK|O_NOCTTY|O_NOFOLLOW`, after checking that the inode did not
  change between `fstatat` and `fstat`; never reads `wp-config.php`,
  `configuration.php`, `config.php` or `.env`;
- searches the prefix for fixed substrings only and returns no content.

Races: replacing a marker with a symlink, FIFO or another file between
the check and the open is detected. Changing the tree between two probes
can produce a result that mixes two states of the tree; it is only a
suggestion. A read from a hung network or FUSE file system can block;
callers that scan many sites should use worker goroutines with a
per-site deadline.

Follow-up: switch to the site owner's identity before probing as a second
barrier. Not implemented.

## Cost

`BenchmarkDetect_N1` runs over 1,000 synthetic document roots (half
WordPress, the rest spread over all fixtures), warm page cache:

| Platform | Per site | 10,000 sites |
| --- | --- | --- |
| Linux x86_64 (container) | 24 µs | 0.24 s |
| macOS (development machine) | 89 µs | 0.9 s |

A cold cache adds disk seeks for each probed directory; at most a few
dozen metadata lookups per site.

`golang.org/x/sys` (BSD-3-Clause, GPL-compatible) provides `openat` and
`fstatat`.
