# fngx

Free, open-source nginx plugin for cPanel/WHM servers.

> **Status: early development. Do not install it on production servers.**
> Nothing here is ready to use yet.

## What it does

fngx puts [nginx](https://nginx.org/) in front of your websites on a
cPanel/WHM server. Each domain can run in one of three modes:

| Mode | Static files (images, CSS, JS) | PHP and other dynamic pages | `.htaccess` |
| --- | --- | --- | --- |
| **proxy** | Apache | Apache | works |
| **hybrid** | nginx | Apache | ignored for static files |
| **nginx** | nginx | PHP-FPM | ignored |

- **proxy** changes the least: nginx passes every request to Apache, so
  your sites behave as before.
- **hybrid**: nginx serves static files itself. `.htaccess` rules
  (deny, password protection, rewrites) do not apply to those files.
- **nginx**: Apache is not used for the domain. PHP runs in PHP-FPM.
  Rewrite rules come from an application template (WordPress, Joomla,
  and others), not from `.htaccess`.

Planned features: PHP version per domain, ModSecurity 3 with the OWASP
Core Rule Set, request limits and blocking, proxy and FastCGI caching,
WHM and cPanel interfaces, a command-line tool, and automatic migration
from Cpnginx.

## Planned targets

- cPanel & WHM with EasyApache 4
- AlmaLinux, CloudLinux, or Ubuntu on x86_64

Tested versions will be listed with the first release.

## Building from source

You need [Go](https://go.dev/dl/) (the version in `go.mod`) and `make`.

```sh
make test         # run tests
make build-linux  # build bin/fngx-linux-amd64
```

## License

[GNU General Public License v3.0](LICENSE) or (at your option) any
later version. SPDX identifier: `GPL-3.0-or-later`.

This project is not affiliated with or endorsed by the nginx, cPanel,
or Cpnginx projects or their owners. Their names are used only to
describe what this software works with.
