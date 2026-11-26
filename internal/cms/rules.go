// SPDX-License-Identifier: GPL-3.0-or-later

package cms

import (
	"bytes"

	"github.com/fornex/fngx/internal/model"
)

// App identifies a detected application.
type App string

// Applications from requirement T-2.
const (
	WordPress App = "wordpress"
	Joomla    App = "joomla"
	Drupal    App = "drupal"
	Laravel   App = "laravel"
	React     App = "react"
	OpenCart  App = "opencart"
)

// Suggested template names. ASSUMPTION: the built-in application
// templates (T-2) will use these names; package render does not define
// them yet. Drupal 7 gets its own template because its front controller
// takes the path in "?q=" while Drupal 8+ reads the request URI, so one
// rewrite rule cannot serve both.
const (
	TemplateWordPress model.TemplateName = "wordpress"
	TemplateJoomla    model.TemplateName = "joomla"
	TemplateDrupal    model.TemplateName = "drupal"
	TemplateDrupal7   model.TemplateName = "drupal7"
	TemplateLaravel   model.TemplateName = "laravel"
	TemplateReact     model.TemplateName = "react"
	TemplateOpenCart  model.TemplateName = "opencart"
)

// Read limits for the two files whose contents are checked.
const (
	indexPHPLimit  = 8 << 10  // Laravel's public/index.php is about 0.6 KiB
	indexHTMLLimit = 16 << 10 // the root element sits near the top of a built index.html
)

type markerKind uint8

const (
	isFile markerKind = iota
	isDir
)

type marker struct {
	path string // relative to the document root, '/'-separated
	kind markerKind
}

func file(p string) marker { return marker{p, isFile} }
func dir(p string) marker  { return marker{p, isDir} }

// contentCheck looks for fixed substrings in the first limit bytes of a
// file. Every group must match; within a group any needle may match.
type contentCheck struct {
	path   string
	limit  int
	groups [][]string
}

func (c *contentCheck) match(b []byte) bool {
	if b == nil {
		return false
	}
	for _, g := range c.groups {
		found := false
		for _, n := range g {
			if bytes.Contains(b, []byte(n)) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// signature describes one layout of one application.
//
// A signature matches when every required marker exists with the right
// type and, if content is set, the content check passes. Confidence is
// then High when at least highAt supporting markers exist, Medium
// otherwise, and never above max.
type signature struct {
	app        App
	variant    string
	template   model.TemplateName
	required   []marker // checked in order; the first miss stops the check
	content    *contentCheck
	supporting []marker
	highAt     int
	max        Confidence
	// docrootHint is the subdirectory that should be the document root
	// when this layout is found at the document root itself.
	docrootHint string
	note        string
}

// signatures is the rule set. Every path below comes from the project's
// own repository or documentation; docs/cms-detection.md has the table.
// Secret-bearing files (wp-config.php, configuration.php, config.php,
// .env) are only ever checked for presence, never read.
var signatures = []signature{
	{
		// https://github.com/WordPress/WordPress (root layout);
		// https://developer.wordpress.org/advanced-administration/wordpress/wp-config/
		// wp-config.php may live one level above the root, so it is
		// only supporting evidence.
		app: WordPress, template: TemplateWordPress,
		required: []marker{file("wp-settings.php"), dir("wp-includes")},
		supporting: []marker{
			file("wp-load.php"), file("wp-login.php"), dir("wp-admin"),
			file("wp-includes/version.php"), file("wp-config.php"), file("wp-config-sample.php"),
		},
		highAt: 3, max: High,
	},
	{
		// https://github.com/joomla/joomla-cms: includes/defines.php and
		// administrator/index.php exist in 3.x (tag 3.6.5, 3.10.12) and
		// 4.x/5.x; the version class moved from
		// libraries/cms/version/version.php to libraries/src/Version.php.
		app: Joomla, template: TemplateJoomla,
		required: []marker{file("administrator/index.php"), file("includes/defines.php")},
		supporting: []marker{
			file("libraries/src/Version.php"), file("libraries/cms/version/version.php"),
			file("configuration.php"), file("index.php"),
		},
		highAt: 2, max: High,
	},
	{
		// https://github.com/drupal/drupal (8.x and later): core/lib/Drupal.php.
		app: Drupal, variant: "8+", template: TemplateDrupal,
		required:   []marker{file("core/lib/Drupal.php")},
		supporting: []marker{file("index.php"), file("autoload.php"), dir("sites"), file("core/includes/bootstrap.inc")},
		highAt:     2, max: High,
	},
	{
		// https://github.com/drupal/recommended-project: composer.json sets
		// "web-root": "web/", so Drupal core lands in web/core.
		app: Drupal, variant: "8+", template: TemplateDrupal,
		required:   []marker{file("web/core/lib/Drupal.php")},
		supporting: []marker{file("composer.json"), file("web/index.php"), dir("vendor")},
		highAt:     2, max: High,
		docrootHint: "web",
		note:        "the document root is the Composer project root; it should be its web/ directory",
	},
	{
		// https://github.com/drupal/drupal branch 7.x: includes/bootstrap.inc,
		// modules/system/system.module, misc/drupal.js.
		app: Drupal, variant: "7", template: TemplateDrupal7,
		required:   []marker{file("includes/bootstrap.inc"), file("modules/system/system.module")},
		supporting: []marker{file("misc/drupal.js"), file("index.php"), file("cron.php"), dir("sites")},
		highAt:     2, max: High,
	},
	{
		// https://github.com/laravel/laravel: artisan, public/index.php,
		// bootstrap/app.php; https://laravel.com/docs/deployment: the web
		// server must point at public/.
		app: Laravel, variant: "project-root", template: TemplateLaravel,
		required:   []marker{file("artisan"), file("public/index.php"), file("bootstrap/app.php")},
		supporting: []marker{file("composer.json"), dir("routes"), dir("app"), dir("vendor")},
		highAt:     2, max: High,
		docrootHint: "public",
		note:        "the document root is the project root and exposes .env and the source; it should be public/",
	},
	{
		// Document root = public/. The parent directory is outside the
		// document root and is not examined, so the evidence is the
		// front controller itself: laravel/laravel public/index.php
		// requires bootstrap/app.php and uses Illuminate\Http\Request
		// (5.0 to 12.x; LARAVEL_START since 5.5). Only the file name is
		// matched, not "/../", because shared-hosting installs often
		// edit the path (for example "/../laravel/bootstrap/app.php").
		app: Laravel, variant: "public", template: TemplateLaravel,
		required: []marker{file("index.php")},
		content: &contentCheck{path: "index.php", limit: indexPHPLimit, groups: [][]string{
			{"bootstrap/app.php"}, {"LARAVEL_START", `Illuminate\Http\Request`},
		}},
		max: Medium,
	},
	{
		// https://github.com/opencart/opencart, directory upload/ on
		// branches 3.0.x.x, 4.1.x.x and master: system/startup.php,
		// system/engine, catalog/. admin/ may be renamed after install.
		app: OpenCart, template: TemplateOpenCart,
		required: []marker{file("system/startup.php"), dir("catalog")},
		supporting: []marker{
			dir("system/engine"), dir("admin"), file("config.php"), file("config-dist.php"), dir("image"),
		},
		highAt: 2, max: High,
	},
	{
		// Create React App build output:
		// https://create-react-app.dev/docs/production-build/ (build/static/js),
		// react-scripts webpack.config.js writes asset-manifest.json; the
		// cra-template public/index.html has <div id="root">.
		app: React, variant: "create-react-app", template: TemplateReact,
		required:   []marker{file("index.html"), file("asset-manifest.json"), dir("static/js")},
		supporting: []marker{file("manifest.json"), file("robots.txt")},
		highAt:     0, max: High,
	},
	{
		// Vite build output: https://vite.dev/config/build-options
		// (build.outDir "dist", build.assetsDir "assets"); the
		// create-vite template-react index.html has <div id="root">.
		app: React, variant: "vite", template: TemplateReact,
		required: []marker{file("index.html"), dir("assets")},
		content:  rootDiv,
		max:      Medium,
	},
	{
		// Any single-page build with a React-style mount point. The
		// React template is an SPA fallback to index.html, which fits
		// other SPA builds as well, hence Low.
		app: React, variant: "spa", template: TemplateReact,
		required: []marker{file("index.html")},
		content:  rootDiv,
		max:      Low,
	},
}

var rootDiv = &contentCheck{path: "index.html", limit: indexHTMLLimit, groups: [][]string{
	{`id="root"`, `id='root'`, `id=root`},
}}
