// SPDX-License-Identifier: GPL-3.0-or-later

package cms

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The fixtures below are synthetic: empty placeholder files laid out
// like each project's own repository or build output. No project source
// code is copied; the few content strings are the minimal markers the
// rules look for.

// me is the uid the tests run as: the owner of every fixture.
var me = uint32(os.Getuid())

// fx maps a relative path to file contents; a path ending in "/" is a
// directory.
type fx map[string]string

const laravelIndex = "<?php\n\nuse Illuminate\\Http\\Request;\n\ndefine('LARAVEL_START', microtime(true));\n\n" +
	"require __DIR__.'/../vendor/autoload.php';\n\n$app = require_once __DIR__.'/../bootstrap/app.php';\n"

const spaIndex = `<!doctype html><html><head><title>x</title></head><body><div id="root"></div></body></html>`

var fixtures = map[string]fx{
	"wordpress": {
		"index.php": "", "wp-settings.php": "", "wp-load.php": "", "wp-login.php": "",
		"wp-config.php": "", "wp-admin/": "", "wp-includes/version.php": "", "wp-content/": "",
	},
	"wordpress-minimal": {"wp-settings.php": "", "wp-includes/": ""},
	"joomla4": {
		"index.php": "", "configuration.php": "", "administrator/index.php": "",
		"includes/defines.php": "", "libraries/src/Version.php": "",
	},
	"joomla3": {
		"index.php": "", "administrator/index.php": "", "includes/defines.php": "",
		"libraries/cms/version/version.php": "",
	},
	"drupal8": {
		"index.php": "", "autoload.php": "", "core/lib/Drupal.php": "",
		"core/includes/bootstrap.inc": "", "sites/default/": "",
	},
	"drupal-project-root": {
		"composer.json": "", "vendor/": "", "web/index.php": "", "web/core/lib/Drupal.php": "",
	},
	"drupal7": {
		"index.php": "", "cron.php": "", "includes/bootstrap.inc": "",
		"modules/system/system.module": "", "misc/drupal.js": "", "sites/all/": "",
	},
	"laravel-project-root": {
		"artisan": "", "composer.json": "", ".env": "", "app/": "", "routes/web.php": "",
		"bootstrap/app.php": "", "public/index.php": laravelIndex,
	},
	"laravel-public": {"index.php": laravelIndex, "robots.txt": "", "favicon.ico": ""},
	"opencart": {
		"index.php": "", "config.php": "", "system/startup.php": "", "system/engine/": "",
		"catalog/": "", "admin/": "", "image/": "",
	},
	"react-cra": {
		"index.html": spaIndex, "asset-manifest.json": "{}", "manifest.json": "",
		"static/js/main.0123abcd.js": "",
	},
	"react-vite": {"index.html": spaIndex, "assets/index-AbC123.js": ""},
	"react-spa":  {"index.html": spaIndex, "main.js": ""},
	"static":     {"index.html": "<html><body>hello</body></html>", "style.css": ""},
	"empty":      {},
	"plain-php":  {"index.php": "<?php echo 1;", "inc/db.php": ""},
}

func build(tb testing.TB, root string, f fx) {
	tb.Helper()
	for p, content := range f {
		full := filepath.Join(root, filepath.FromSlash(p))
		if strings.HasSuffix(p, "/") {
			if err := os.MkdirAll(full, 0o750); err != nil {
				tb.Fatal(err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			tb.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
			tb.Fatal(err)
		}
	}
}

func fixtureDir(tb testing.TB, name string) string {
	tb.Helper()
	f, ok := fixtures[name]
	if !ok {
		tb.Fatalf("no fixture %q", name)
	}
	root := filepath.Join(tb.TempDir(), name)
	if err := os.Mkdir(root, 0o750); err != nil {
		tb.Fatal(err)
	}
	build(tb, root, f)
	return root
}

// union builds a tree that contains every marker of every signature, the
// worst case for the number of probes.
func union() fx {
	f := fx{}
	for _, s := range signatures {
		for _, m := range append(append([]marker{}, s.required...), s.supporting...) {
			if m.kind == isDir {
				f[m.path+"/"] = ""
			} else {
				f[m.path] = ""
			}
		}
	}
	return f
}
