# cPanel & WHM integration: what the documentation says

Stage 0 discovery for the cPanel side of the plugin. Each section answers one
integration question from the official cPanel & WHM documentation and marks
how far the documentation goes. No test server was used: everything here comes
from reading pages, and anything that needs a server is listed at the end.

Requirements referenced: A-1, A-2, A-7 (architecture), M-2, M-6 (modes),
PHP-1, PHP-2 (PHP-FPM), U-1 to U-10 (interfaces), N-8 (stats), I-1, I-4,
I-6, I-7 (install and service).

## How to read this document

- Pages were read on 2026-11-26. The API reference pages show
  version `11.138.0.19` of cPanel & WHM.
- Sources: the developer documentation at <https://api.docs.cpanel.net/>
  (guides and the WHM API 1 / UAPI reference), the product documentation at
  <https://docs.cpanel.net/>, and cPanel support articles at
  <https://support.cpanel.net/>.
- Status labels:
  - **Documented**: the linked page states it directly.
  - **Partly documented**: the page covers part of the question; the gap is
    named.
  - **Not documented — check on server**: no page found that answers it.
- Short quotes are in quotation marks. Everything else is a summary.
- "Inference" marks a conclusion drawn from documented facts that no page
  states directly.

## Summary

| # | Question | Status | Main finding |
| --- | --- | --- | --- |
| 1 | Reading accounts, domains, SSL, IPs | Documented | WHM API 1 (`get_domain_info`, `listaccts`, `fetch_vhost_ssl_components`, `listips`) is the supported interface. `/var/cpanel/userdata/` exists but cPanel says not to edit it; its format is not specified. |
| 2 | Standardized Hooks | Partly documented | Events exist for account create/modify/suspend/unsuspend/remove, subdomains, parked domains, SSL and AutoSSL install, PHP version changes. No WHM-level event for addon domains or SSL removal; client actions fire `Cpanel`-category events that run as the user. |
| 3 | WHM plugin | Documented | AppConfig file in `/var/cpanel/apps/`, `register_appconfig`, CGI in `/usr/local/cpanel/whostmgr/docroot/cgi/`, ACL checks are mandatory. Backend language is free. |
| 4 | cPanel plugin and root actions | Partly documented | `install.json` + `install_plugin` for Jupiter. Root actions go through AdminBin (Perl admin module recommended). **cPanel support says common third-party plugins are not yet available in the new Meridian theme.** |
| 5 | Feature Manager | Documented | Each `install.json` link item becomes a feature; check with `verify_user_has_feature` (WHM) or `Features::has_feature` (UAPI). Unknown features read as granted. |
| 6 | Apache ports and real client IP | Partly documented | Tweak Settings `apache_port` / `apache_ssl_port`; `mod_remoteip` is always installed with EA4 Apache. How ea-nginx changes the ports is not documented step by step. |
| 7 | Service monitoring | Documented | chkservd: add a line to `/etc/chkserv.d/chkservd.conf` and a service file in `/etc/chkserv.d/`. |
| 8 | AutoSSL, service subdomains, stats behind a proxy | Partly documented | DCV paths and service subdomain names are documented; how cPanel picks up a third-party nginx's logs for bandwidth and stats is not. AWStats, Webalizer and Analog are scheduled for removal. |
| 9 | MultiPHP and PHP-FPM | Partly documented | EA4 pool layout, the YAML sources and the APIs are documented. alt-php is not covered by cPanel documentation. |
| 10 | OS and versions, conflicts | Documented | AlmaLinux 8/9/10, CloudLinux 8/9/10 (7 not recommended, cPanel 110 only), Ubuntu 24.04; 22.04 only on 134 LTS tiers. ea-nginx is documented as incompatible with LiteSpeed. No documented detection method for Engintron. |

Findings that change the plan or earlier assumptions are collected in
[Impact on the plan](#impact-on-the-plan).

## 1. Account, domain and SSL data (A-1)

**Status: Documented** for the API route; **Not documented — check on
server** for the on-disk file format.

### Supported way: WHM API 1 as root

WHM API 1 can be called from the command line as root with `whmapi1`, with
JSON output via `--output=json` ([WHM API 1 introduction][whm-intro]). On
CloudLinux the full path `/usr/local/cpanel/bin/whmapi1` is required (same
page). The same page warns against scraping interface URLs and calls that
method "**unsupported**".

| Data | Function | What it returns |
| --- | --- | --- |
| All domains with type, docroot, owner, IPs, ports, PHP version | [`get_domain_info`][whm-get-domain-info] | One object per domain: `domain`, `domain_type`, `docroot`, `parent_domain`, `user`, `user_owner`, `ipv4`, `ipv4_ssl`, `ipv6`, `ipv6_is_dedicated`, `port`, `port_ssl`, `php_version`, `modsecurity_enabled`. The page notes that service (proxy) subdomains and automatically created domains are **not** included. |
| One domain's vhost data | [`domainuserdata`][whm-domainuserdata] | `documentroot`, `serveralias` (space-separated aliases), `ip`, `port`, `owner`, `user`, `homedir`, `customlog` (Apache log targets), `userdirprotect`, and more. |
| Accounts | [`listaccts`][whm-listaccts], [`accountsummary`][whm-accountsummary] | Per account: `user`, `domain`, `ip`, `ipv6`, `owner`, `suspended`, `suspendreason`, `plan`, `theme`, `uid`, and limits. `theme` matters for section 4. |
| Suspended accounts | [`listsuspended`][whm-listsuspended] | List of suspended users. |
| Domain owner | [`getdomainowner`][whm-getdomainowner] | Owner of one domain. |
| Server IPs, dedicated flag | [`listips`][whm-listips] | Per IP: `ip`, `dedicated`, `used`, `mainaddr`, `public_ip`, `active`. |
| Installed certificates per vhost (PEM) | [`fetch_vhost_ssl_components`][whm-fetch-vhost-ssl] | Per vhost: `servername`, `certificate`, `key`, `cabundle` and their IDs. The page warns the output is large and recommends filtering. |
| Certificate metadata per vhost | [`fetch_ssl_vhosts`][whm-fetch-ssl-vhosts] | Per vhost: certificate `domains`, `not_after`, issuer, `is_self_signed`, `docroot`. |
| PHP version per vhost | [`php_get_vhost_versions`][whm-php-vhost-versions] | Per vhost: `version`, `php_fpm`, `php_fpm_pool_parms`, `phpversion_source`, `is_suspended`, `documentroot`. |

The cPanel-account-level equivalents in UAPI are
[`DomainInfo::domains_data`][uapi-domains-data],
[`DomainInfo::single_domain_data`][uapi-single-domain-data] and
[`SSL::installed_hosts`][uapi-installed-hosts]; UAPI runs as the cPanel user,
so the root-side reader should use WHM API 1 (inference).

Output format: JSON when called over HTTP (`json-api`) or with
`--output=json`; the CLI default is YAML ([WHM API 1
introduction][whm-intro]). Every response has a `metadata` object with
`result` (1 or 0) and `reason` (each function page above).

### The `/var/cpanel/userdata/` directory

- It exists and is the data cPanel uses to build Apache virtual hosts; files
  are YAML; the page says "Do not manually edit these YAML files"
  ([EA4 custom templates][ea4-custom-templates]).
- UAPI's `DomainInfo::domains_data` reads from
  `/var/cpanel/userdata/user/domain` and warns that output may not contain
  every documented field ([domains_data][uapi-domains-data]).
- Rebuild tools exist (`/usr/local/cpanel/bin/userdata_update`,
  `/scripts/updateuserdatacache`, `fix_userdata_perms`)
  ([How to rebuild userdata files][kb-rebuild-userdata]).
- No page specifies the file schema or promises it is stable.

Conclusion: reading the API is the documented interface; reading
`/var/cpanel/userdata/` directly would be faster for 10 000 domains (N-1) but
relies on an unspecified format. Whether the API is fast enough at that scale
is a server measurement.

### Certificates on disk

No page found that documents where installed certificate files live on disk
for direct reading. The [backup tarball contents][kb-backup-tarball] page
lists an `apache_tls` directory inside account backups, which is not the same
as a supported live path. The documented route is
`fetch_vhost_ssl_components` or the PEM data passed to the SSL hooks
(section 2). **Check on server**: on-disk location and whether nginx can read
it directly.

### Stability

- Release model: even major versions are production; LTS gets one release per
  year; non-LTS releases live a few months. The release table (page modified
  2026-10-02) gives approximate end-of-life dates: 110 LTS December 2026,
  134 LTS June 2027, 136 August 2026, 138 November 2026. The page adds that
  a version is not EOL until the next one reaches the RELEASE tier, and that
  110 is extended to 2028-01-01 under Extended Lifecycle Support for CentOS 7
  and CloudLinux 7 servers ([Product versions and release process][kb-release]).
  138's approximate EOL is this month, so a newer release may already exist;
  check the changelog before fixing target versions.
- Features are removed through a published deprecation plan
  ([cPanel deprecation plan][kb-deprecation]). cPanel API 2 is deprecated in
  favour of UAPI ([cPanel API 2][cpapi2]).
- No page found with a compatibility promise for individual WHM API 1
  functions. The risk is already in SPEC section 15 ("cPanel changes hooks
  and data formats"); Q-2 must run on each new cPanel version.

## 2. Standardized Hooks (A-2)

**Status: Partly documented.** Event names, data and registration are
documented; whether the WHM-category events also fire for actions started
from cPanel (client side) is not stated for every event.

### Registration and data

- Register with `/usr/local/cpanel/bin/manage_hooks add script <path>`;
  without a `describe()` method `--category` and `--event` are required
  (the examples also pass `--manual` and `--stage`), and `--blocking` only
  works when the hook has a `describe()` method
  ([manage_hooks utility][hooks-manage]). The hooks data lives in
  `/var/cpanel/hooks/data/` and must not be edited by hand
  ([Guide to Standardized Hooks][hooks-guide]).
- Scripts may be written in any language the shell can run, must be
  `root:root` with mode `755`, and should be saved in
  `/usr/local/cpanel/3rdparty/bin` ([Hook action code][hooks-action-code]).
- Input: the script must read STDIN to the end and decode it as JSON; it
  contains `context` (category and event) and `data` (the event's fields)
  (same page; the PHP example decodes `context`, `data` and `hook` keys).
- Output: the primary result is a single line on STDOUT (`1 message` or
  `0 message`) (same page).
- Scripts run as a separate process and cannot see cPanel environment
  variables; Perl modules run inside `cpsrvd` (same page).
- Blocking: only some `pre`-stage events can block. To block, the hook must
  declare `blocking` in `describe()` and fail with `BAILOUT`; a script does
  that by printing `BAILOUT` to STDOUT ([Exceptions][hooks-exceptions],
  [Hookable events][hooks-events]). For non-blocking events an exception is
  logged to `/usr/local/cpanel/logs/error_log` and the remaining hooks still
  run ([Exceptions][hooks-exceptions]).
- `--weight` orders several hooks on the same event; hooks from different
  applications coexist ([manage_hooks utility][hooks-manage],
  [Guide to Standardized Hooks][hooks-guide]).
- Whether the event waits for a `post` hook to finish, and any timeout, is
  not documented. **Check on server.** Inference: the plugin's hook should
  enqueue work and return quickly (fits A-6).

### Events relevant to the plugin

All `Whostmgr` events below run as `root`; "blocking available" refers to
the `pre` stage ([Whostmgr functions][hooks-whostmgr]).

| Need | Category / event | Stages | Data passed (main fields) |
| --- | --- | --- | --- |
| Account created | `Whostmgr` / `Accounts::Create` | pre, post | returns of WHM API 1 `createacct` |
| Account modified (domain, IP, package, etc.) | `Whostmgr` / `Accounts::Modify` | pre, post | returns of `modifyacct` |
| Package changed (feature list may change, U-10) | `Whostmgr` / `Accounts::change_package` | pre, post | `user`, `cur_pkg`, `new_pkg` |
| Site IP changed | `Whostmgr` / `Accounts::SiteIP::set` | pre, post | `user`, `oldip`, `newip` |
| Suspended | `Whostmgr` / `Accounts::suspendacct` | pre, post | `user`, `reason`, `disallowun` |
| Unsuspended | `Whostmgr` / `Accounts::unsuspendacct` | pre, post | `user` |
| Removed | `Whostmgr` / `Accounts::Remove` | pre, post | returns of `removeacct` |
| Account moved between partitions | `Whostmgr` / `Accounts::Rearrangeacct` | pre, post | none |
| Subdomain added / removed | `Whostmgr` / `Domain::addsubdomain`, `Domain::delsubdomain` | pre, post | `user`, `subdomain`, `rootdomain` |
| Alias (parked) added | `Whostmgr` / `Domain::park`, `ParkAdmin::park` | pre, post | `user`, `target_domain`, `new_domain` |
| Alias removed | `Whostmgr` / `ParkAdmin::unpark` | pre, post | `user`, `parent_domain`, `domain` |
| Certificate installed by admin | `Whostmgr` / `SSL::installssl` | pre, post | `domain`, `crt`, `key`, `cab`, `ip` |
| Certificate installed by AutoSSL | `Whostmgr` / `AutoSSL::installssl` | pre, post | `domain_set_name`, `username`, `certificate_pem`, `key_pem`, `cab_pem` |
| PHP version of a vhost changed by admin | `Whostmgr` / `Lang::PHP::set_vhost_versions` | pre, post (not blocking) | returns of `php_set_vhost_versions` |
| Server default PHP / handler changed | `Whostmgr` / `Lang::PHP::set_system_default_version`, `Lang::PHP::set_handler` | pre, post (not blocking) | returns of the matching WHM API 1 function |
| Tweak Settings changed (e.g. Apache ports) | `Whostmgr` / `TweakSettings::Main` | pre, post (not blocking) | none |
| Account transfer session | `Whostmgr` / `Transfers::Session` | pre, post | session fields |
| cPanel update | `System` / `upcp` (runs as root, cannot block) | pre, post | none ([System functions][hooks-system]) |

Gaps and caveats from the same pages:

- **Addon domains.** No `Whostmgr` event is named for addon domains. The
  separate `ConvertAddon` category covers converting an addon domain into an
  account, not creating one ([Hookable events][hooks-events]). UAPI
  creates an addon domain as a subdomain plus a domain parked on it
  ([`AddonDomain::addaddondomain`][uapi-addaddondomain],
  [`Park::park`][uapi-park]); WHM does the same with `create_subdomain` and
  `create_parked_domain_for_user` ([support: addon via whmapi1][sup-addon-whmapi]).
  Which of the subdomain and park events fire for an addon domain is
  **not documented — check on server**.
- **Client-side changes.** Actions in the cPanel interface call UAPI or
  cPanel API 2. Those fire `Cpanel`-category events named
  `API::Module::function`, with `API` being `UAPI` or `Api2` (for example
  `UAPI::SubDomain::addsubdomain`). These run **as the cPanel user**, and
  can escalate to root only for scripts registered with `escalateprivs`
  ([Cpanel functions][hooks-cpanel], [Privilege escalation][hooks-privesc]).
  UAPI `post` hooks do not run if the call fails; API 2 `post` hooks always
  run (same page).
- The `Lang::PHP` pages say a hook on the WHM event must be paired with a hook
  on the UAPI equivalent (`LangPHP::php_set_vhost_versions`) for consistent
  behaviour ([Whostmgr functions][hooks-whostmgr]).
- `Domain::addsubdomain` is described as "whenever a user creates a
  subdomain"; whether it also fires for subdomains created from cPanel or
  only from WHM is not stated. **Check on server.**
- **SSL removal.** `AutoSSL::installssl` does "**not** listen for
  uninstallation events" ([Whostmgr functions][hooks-whostmgr]); no WHM event
  for certificate deletion is listed. Client-side deletion would be
  `UAPI::SSL::delete_ssl` in the `Cpanel` category (inference from the naming
  rule). **Check on server.**
- Document root changes (`SubDomain::changedocroot`, UAPI) have no WHM event;
  only the `Cpanel`-category hook applies (inference).

Inference for the design: register `post` hooks on the `Whostmgr` events
above, plus `Cpanel`-category hooks for the UAPI and API 2 domain, SSL and
PHP functions, with a periodic full reconcile against `get_domain_info` to
catch anything no hook covers.

## 3. WHM plugin (U-1 to U-7)

**Status: Documented.**

- Registration: create an AppConfig `.conf`, run
  `/usr/local/cpanel/bin/register_appconfig <file>`; the file ends up in
  `/var/cpanel/apps/` ([AppConfig registration][whm-appconfig-reg]).
  Changes to AppConfig files take effect after `cpsrvd` restarts
  ([AppConfig configuration file][whm-appconfig-file]).
- Keys for a WHM app: `service=whostmgr`, `url` (relative to
  `/usr/local/cpanel/whostmgr/docroot/`, must start with `/`), `acls`
  (required), `entryurl` (menu link), `displayname`, `icon`, `target`,
  `searchtext` (132 and later). `user` defaults to `root` for WHM apps
  ([AppConfig configuration file][whm-appconfig-file]).
- Files: templates under `/usr/local/cpanel/whostmgr/docroot/templates/`,
  CGI under `/usr/local/cpanel/whostmgr/docroot/cgi/` (one file
  `addon_<name>.cgi` or a subdirectory), icons under
  `/usr/local/cpanel/whostmgr/docroot/addon_plugins/` (48×48 PNG
  recommended) ([Plugin files][whm-plugin-files]).
- ACLs: WHM plugins run as root by default and **must** check the
  authenticated user's ACLs ([Access control lists][whm-acls]). With no
  resellers on Fornex servers (SPEC section 15, decision 23) the plugin can
  require the `all` ACL (inference).
- Language: "Use your preferred programming language" for the backend
  ([Tutorial: create a WHM plugin][tut-whm-plugin]); installation scripts may
  be in any language ([Installation scripts][whm-install-scripts]). cPanel
  recommends Template Toolkit for the interface and notes most applications
  are written in PHP or Perl ([Plugin files][whm-plugin-files],
  [Quickstart WHM][quickstart-whm]).
- Whether a compiled binary can be the CGI directly (instead of a Perl or
  shell wrapper) is not stated. **Check on server.**
- AppConfig registration does not run installation scripts; the admin runs
  them by hand ([Installation scripts][whm-install-scripts]). This matches
  I-1 (one installer script).

## 4. cPanel plugin for clients and root actions (A-7, U-8, U-9)

**Status: Partly documented.** Jupiter install method and AdminBin are
documented. Plugin support in the new Meridian theme is documented as
**absent**.

### Install

- Interface files go in `/usr/local/cpanel/base/frontend/<theme>/` and are
  served at `https://host:2083/frontend/<theme>/...`; the guide names
  `jupiter` as the theme ([Guide to cPanel plugins][cp-plugins]).
- An `install.json` with `group` and `link` items is required and is
  installed with `/usr/local/cpanel/scripts/install_plugin`; only root can run
  it; the script does not extract the archive or place the interface files,
  the plugin's own installer must
  ([Guide to cPanel plugins][cp-plugins], [Add plugins][cp-plugins-add],
  [install_plugin script][script-install-plugin]). `--theme` defaults to
  `jupiter` ([install_plugin script][script-install-plugin]). Uninstall with
  `uninstall_plugin` ([uninstall_plugin script][script-uninstall-plugin]).
- A link item's `uri` must end in `live.pl`, `live.php`, `live.cgi`,
  `live.py` or `live.rb` ([Add plugins][cp-plugins-add]).
- cPanel interfaces may be HTML, Template Toolkit, PHP or CGI; webpack is
  discouraged because of RequireJS ([Guide to cPanel plugins][cp-plugins]).

### How the interface runs

- LiveAPI (PHP class, Perl module; Ruby, Python and others through CGI
  wrappers) runs API calls as the authenticated cPanel user and cannot call
  WHM API 1 ([Guide to the LiveAPI system][liveapi]).
- So the client UI runs without root; anything that writes nginx config
  needs a privileged path.

### Running privileged code: AdminBin

AdminBin is the mechanism the current guide describes
([Guide to API privilege escalation][adminbin]); no page found describes a
successor.

- Recommended: a Perl **admin module** subclassing `Cpanel::Admin::Base`,
  saved under `/var/cpanel/perl/Cpanel/Admin/Modules/<Namespace>/<Module>.pm`,
  exposing an `_actions()` list; callers use `Cpanel::AdminBin::Call::call`.
  The module gets helpers such as `get_caller_username()` and
  `get_cpuser_domains()` ([Admin module method][adminbin-module]).
- For other languages: the **Wrap** method, an executable plus `.conf` in
  `/usr/local/cpanel/bin/admin/<Namespace>/`, called with
  `Cpanel::Wrap::send_cpwrapd_request`; the caller's UID arrives as `ARGV[0]`
  in `full` mode ([Application files][adminbin-app],
  [Configuration files][adminbin-conf], [Call your application][adminbin-call]).
- Documented security requirements ([Guide to API privilege
  escalation][adminbin]):
  - only use it for code that must run as root;
  - "**Thoroughly** validate any input";
  - do not touch user-owned files or directories as root;
  - sanitise the environment (`@INC` for Perl);
  - files owned by root, mode `0700` ([Application files][adminbin-app]);
  - set `allowed_parents=/usr/local/cpanel/cpanel`, otherwise "anything can
    invoke the module" ([Configuration files][adminbin-conf]);
  - the application file must sanitise its own input; "The system does
    **not** sanitize them" ([Application files][adminbin-app]).
- Alternative: custom UAPI modules in `/usr/local/cpanel/Cpanel/API/`
  (Perl), which can be limited to feature lists ([Custom UAPI
  modules][uapi-custom]). They run as the user, so they still need AdminBin
  for root work (inference).

Inference for A-7: a small Perl admin module that takes the caller's
username from cPanel (never from the request), checks the domain belongs to
that user and the setting is allowed, then runs the Go CLI with fixed
arguments. This keeps N-6 (no shell interpolation) and matches the
recommended method.

### Meridian theme

- Meridian is a new goal-based cPanel theme; admins can make it the default
  in a package; accounts created on Meridian cannot switch back to Jupiter
  themselves ([Welcome to Meridian][meridian-welcome],
  [How to enable the Meridian theme][meridian-enable]).
- A support article updated 2026-11-24 says third-party plugins such as WP
  Toolkit, JetBackup, Imunify360 and Softaculous are "not yet available in
  the Meridian theme", with no release estimate
  ([support: plugins missing in Meridian][sup-meridian-plugins]).
- The plugin guide and `install_plugin` only describe Jupiter.

The article names specific plugins and does not say every `install.json`
plugin is hidden. Inference: a client on Meridian will not see the plugin's
cPanel section (U-8, U-9); confirm on the server (item 8 below). The theme
per account is visible in `listaccts` (`theme`).

## 5. Feature Manager (U-10)

**Status: Documented.**

- Each `link` item in `install.json` is registered in Feature Manager unless
  `featuremanager` is `0`; the feature name is `feature` or, by default, the
  item's `id` (letters, digits, `-`, `_`) ([Add plugins][cp-plugins-add]).
- A WHM-registered cPanel app can restrict access with AppConfig `features`
  ([AppConfig configuration file][whm-appconfig-file]).
- Checks:
  - root side: WHM API 1 [`verify_user_has_feature`][whm-verify-feature]
    (`user`, `feature`);
  - client side: UAPI [`Features::has_feature`][uapi-has-feature] or LiveAPI
    [`cpanelfeature()`][liveapi-feature].
- Caveat: `verify_user_has_feature` returns 1 for a feature that does not
  exist in a feature list ([verify_user_has_feature][whm-verify-feature]).
  The plugin must make sure its features are registered before relying on
  the check.
- The `disabled` feature list overrides all other lists
  ([Feature Manager][whm-feature-manager]).
- Feature lists can be managed by API
  ([`get_featurelist_data`][whm-get-featurelist-data],
  [`update_featurelist`][whm-update-featurelist]).

Not documented: registering a feature that has no icon (for example
"client may change cache" as a separate permission). Inference: either one
link item per permission with `featuremanager` on, or one feature for the
section and finer rights kept in the plugin's own settings (A-3, M-5).
**Check on server** whether hidden link items are possible.

## 6. Apache ports and real client IP (M-6)

**Status: Partly documented.**

### Moving Apache

- Tweak Settings → System: "Apache non-SSL IP/port" and "Apache SSL port",
  defaults `0.0.0.0:80` and `0.0.0.0:443`; the page warns a wrong value can
  make sites unreachable ([Tweak Settings — System][tweak-system]).
- The keys in `/var/cpanel/cpanel.config` are `apache_port` and
  `apache_ssl_port` ([cpanel.config file][kb-cpanel-config]). That page
  recommends interface-only changes for some dynamic keys; these two keys
  carry no such note. WHM API 1
  [`set_tweaksetting`][whm-set-tweaksetting] sets a Tweak Settings key and
  stores it in that file.
- A support article shows the Tweak Settings steps with `0.0.0.0:81` and
  `0.0.0.0:444` ([support: change the Apache port][sup-apache-port]).
- Moving back for I-6 and I-7 is the same setting with the defaults.
- Not documented: whether `set_tweaksetting` alone rebuilds `httpd.conf` and
  restarts Apache, and in which order to switch so ports 80/443 are never
  both free or both taken. **Check on server.**

### What ea-nginx does

- On install it moves Apache only if Apache uses 80/443, to "the first
  available port under 1024" (usually 81) and sets `$CPANEL_APACHE_PROXY_PORT`
  in `/etc/nginx/conf.d/ea-nginx.conf`
  ([Default configuration of NGINX with reverse proxy][eanginx-default]).
  For the SSL port that page says "usually port 443", while the standalone
  page says "usually port 444" ([NGINX Standalone][eanginx-standalone]).
  Inference: the first is a mistake in the page.
- How ea-nginx changes the setting (Tweak Settings key or another method) is
  not described.

### Real client IP

- EA4 installs `mod_remoteip` together with Apache and it cannot be removed
  ([Advanced Apache configuration][ea4-advanced-apache]).
- ea-nginx edits the proxy configuration so `REMOTE_ADDR` is correct, and
  asks admins to remove their own `RemoteIPHeader` and
  `RemoteIPInternalProxy` lines; admins with a customised
  `/var/cpanel/templates/apache2_4/ea4_main.local` must update it from
  `ea4_main.default`
  ([Default configuration of NGINX with reverse proxy][eanginx-default]).
- For a custom proxy, a support article describes: touch
  `/var/cpanel/no_apache_cloudflare`, add `RemoteIPHeader X-Forwarded-For` and
  `RemoteIPInternalProxy` to the global Pre VirtualHost include, and switch
  the Apache `LogFormat` to `%a` ([support: mod_remoteip][sup-remoteip]).
  That changes a global setting the plugin would have to restore on removal
  (I-7). Which variant fits the plugin is a design choice; **check on
  server** that domlogs then show the visitor IP.
- ea-nginx is documented as "not currently compatible" with LiteSpeed
  ([NGINX with reverse proxy][eanginx]).

## 7. Service management (I-6)

**Status: Documented.**

- chkservd checks each monitored service every five minutes and restarts it
  with the configured command; results go to `/var/log/chkservd.log`
  ([TailWatch][kb-tailwatch]).
- Custom service: add `name:1` to `/etc/chkserv.d/chkservd.conf` and create
  `/etc/chkserv.d/<name>` with a line such as
  `service[name]=x,x,x,<restart command>,<process>,<user>` (process-based) or
  a port/command/response form (connection-based)
  ([TailWatch][kb-tailwatch], [support: add a chkservd service][sup-chkservd]).
- Service Manager lists services and their Monitor checkbox
  ([Service Manager][whm-service-manager]). It lists `nginx` only when
  ea-nginx is installed (same page).
- ea-nginx must be restarted with `/usr/local/cpanel/scripts/restartsrv_nginx`
  or Service Manager, not the `nginx` binary
  ([NGINX with reverse proxy][eanginx],
  [NGINX troubleshooting][eanginx-troubleshooting]). This applies to
  ea-nginx; the plugin's own nginx can use its own systemd unit (inference).
- Not documented: whether a custom service appears in Service Manager and in
  WHM API 1 `servicestatus`. **Check on server.**

## 8. AutoSSL, service subdomains, bandwidth and stats behind a proxy (M-2, N-8)

**Status: Partly documented.**

### AutoSSL and DCV

- AutoSSL includes only names that pass DCV, adds `www.` names and service
  subdomains ([Guide to SSL][kb-guide-ssl]).
- HTTP DCV requests use these paths, which must not be redirected:
  `/.well-known/acme-challenge/`, `/.well-known/pki-validation/`,
  `/.well-known/cpanel-dcv/` ([support: AutoSSL and redirects][sup-dcv-redirect]).
  The same article excludes service subdomains (`autoconfig`, `autodiscover`,
  `cpanel`, `cpcalendars`, `cpcontacts`, `webdisk`, `webmail`, `whm`) from
  that exception.
- DCV files are served from the domain's own content (a `.htaccess` in the
  docroot can break it) ([support: DCV 404 and .htaccess][sup-dcv-htaccess]).
  So in nginx (standalone) mode the plugin must serve `/.well-known/` from
  the docroot without rewrites (inference; **check on server**).
- The experimental ea-nginx-standalone package lists AutoSSL and proxy
  subdomains as working and says it creates proxies for AutoSSL
  ([NGINX Standalone][eanginx-standalone]). How is not described.

### Service subdomains

- Service subdomains (`cpanel.`, `whm.`, `webmail.`, `webdisk.`,
  `autodiscover.`, `autoconfig.`, `cpcalendars.`, `cpcontacts.`) are created
  for every domain; "cPanel & WHM uses Apache's configuration" to serve them;
  the page says SSL vhosts use the cPanel service certificate and, a line
  later, that Domain TLS SNI is the default for their certificates; the old
  name is "proxy subdomains" ([Service and proxy subdomains][kb-service-subdomains]).
  The table there gives the backend port for each (2083, 2087, 2096, 2080 and
  others).
- Service subdomains are excluded from `get_domain_info`
  ([get_domain_info][whm-get-domain-info]).
- With nginx in front, the plugin must either proxy these hosts to Apache or
  to the cPanel ports (inference). **Check on server** that cPanel login
  through `cpanel.<domain>` works in every mode.

### Logs, bandwidth and stats

- With ea-nginx, Apache does not log proxied requests; nginx writes the
  Apache default log format to `/var/log/nginx/domains/<domain>`,
  `<domain>-ssl_log` (piped logging) and `<domain>-bytes_log`; cPanel's
  `runweblogs` does not process nginx logs
  ([Default configuration of NGINX with reverse proxy][eanginx-default]).
- With ea-nginx, cPanel's Visitors, Errors and Raw Access interfaces do not
  work ([support: Apache logs empty with ea-nginx][sup-eanginx-logs]).
- The [default configuration page][eanginx-default] says that nginx rotates
  its logs with logrotate and that "This activity will register in your user
  stats and bandwidth programs"; it does not say how nginx logs reach those
  programs. No page explains how a third-party nginx
  would feed cPanel bandwidth and stats processing. **Not documented — check
  on server**: in proxy and hybrid mode, does Apache still log to domlogs (so
  stats keep working)? In nginx mode, must nginx write domlogs in Apache's
  format and location?
- Apache domlogs are under `/etc/apache2/logs/domlogs/`
  ([cPanel log files][kb-log-files]); piped logging uses the `splitlogs`
  binary ([splitlogs][kb-splitlogs]).
- AWStats, Webalizer and Analog Stats are deprecated in cPanel & WHM 140 and
  removed in 142, replaced by GoAccess ([deprecation plan][kb-deprecation]).

## 9. MultiPHP and PHP-FPM in EA4; CloudLinux (PHP-1, PHP-2)

**Status: Partly documented.** EA4 is documented; alt-php is not covered by
cPanel documentation.

- Per-domain PHP version: MultiPHP Manager in WHM and cPanel; APIs
  [`php_get_vhost_versions`][whm-php-vhost-versions],
  [`php_set_vhost_versions`][whm-php-set-vhost-versions],
  [`php_get_installed_versions`][whm-php-installed]; UAPI
  [`LangPHP::php_set_vhost_versions`][uapi-php-set-vhost].
- EA4 PHP-FPM layout: per-version `php-fpm.conf` in
  `/opt/cpanel/ea-phpNN/root/etc/`, one pool file per domain in
  `/opt/cpanel/ea-phpNN/root/etc/php-fpm.d/<domain>.conf`, generated from
  `/var/cpanel/ApachePHPFPM/system.yaml`,
  `/var/cpanel/ApachePHPFPM/system_pool_defaults.yaml` and a per-domain YAML
  in `/var/cpanel/userdata/<user>/`; "Do not edit these configuration files
  manually" ([PHP-FPM filesystem layout][kb-fpm-layout]).
- Sockets: the domain pools page says the socket is
  `/opt/cpanel/<version>/root/usr/var/run/php-fpm/<hash>.sock`, yet its own
  Apache handler example points at a socket in the user's home directory
  ([PHP-FPM domain pools][kb-fpm-pools]). Pool directives are listed in
  [Configuration values of PHP-FPM][kb-fpm-values]. The per-domain YAML is named
  `<domain>.php-fpm.yaml` on one page and `<domain>.php_fpm.yaml` on the
  other. **Check on server** for the real names.
- Pools are rebuilt with `/scripts/php_fpm_config --rebuild`
  ([PHP-FPM domain pools][kb-fpm-pools], [php_fpm_config script][script-php-fpm-config]).
- Editing a user's pool in MultiPHP Manager stops system defaults from
  applying to that user ([PHP-FPM filesystem layout][kb-fpm-layout]).
- Inference for PHP-4 (own pool template): cPanel's generated pools cannot
  be edited directly, so either the plugin feeds its values through the
  documented YAML files, or it runs its own pools. This is a design decision
  for stage 2; Cpnginx documents its own pool template (HANDOFF 6.1).
- CloudLinux: cPanel documents CloudLinux Manager and points to CloudLinux
  for `mod_lsapi` ([CloudLinux Manager][whm-cloudlinux-manager],
  [PHP handlers][ea4-php-handlers]). alt-php and alt-php-fpm are not
  described in cPanel documentation; they belong in
  `docs/discovery/cloudlinux.md` (stage 0 item, CloudLinux docs).

## 10. Supported OS and versions; conflicts (I-4)

**Status: Documented** for OS support; **Partly documented** for conflict
detection.

### OS and cPanel versions

- AlmaLinux 8 (cPanel 110+), 9 (114+), 10 (132+)
  ([System requirements for AlmaLinux][req-alma]).
- CloudLinux 7, 8, 9, 10; cPanel 112 or later cannot be installed on
  CloudLinux 7, and the page does not recommend CloudLinux 7 because support
  will be removed soon; CloudLinux 10 needs cPanel 134 or later
  ([System requirements for CloudLinux][req-cloudlinux]).
- Ubuntu: new installations on 24.04 LTS only; an older Ubuntu "will block
  upgrades" to newer cPanel versions
  ([System requirements for Ubuntu][req-ubuntu]).
- Support table (updated 2026-09-25): AlmaLinux 8/9/10 and CloudLinux 8/9/10
  supported on 134 LTS/STABLE/RELEASE and 136 CURRENT/EDGE; Ubuntu 22.04
  supported on 134 tiers but "Not Available" on 136; Ubuntu 24 supported
  everywhere ([support: supported OS][sup-os]). The table lags the release
  page, which already lists 138.
- 64-bit only; ARM is not supported (each requirements page above).
- Release and end-of-life dates: [Product versions][kb-release].

Consequence for SPEC section 3: Ubuntu 22.04 is only reachable on 134 LTS and
blocks upgrades past it; the installer should refuse or warn on 22.04 with
cPanel newer than 134 (inference from the pages above).

### Conflicts the installer should detect

| Product | What cPanel documents | Detection method documented? |
| --- | --- | --- |
| ea-nginx | Packages `ea-nginx` (reverse proxy) and the experimental `ea-nginx-standalone`; config in `/etc/nginx/conf.d/`, script `/usr/local/cpanel/scripts/ea-nginx` ([NGINX with reverse proxy][eanginx], [ea-nginx script][eanginx-script], [support: standalone][sup-eanginx-standalone]) | Installed EA4 packages are listed by [`ea4_get_currently_installed_packages`][whm-ea4-installed]; no explicit "detect ea-nginx" page. |
| Engintron | Support article on removal: `engintron remove` ([support: uninstall Engintron][sup-engintron]) | No. **Check on server** (for example its WHM plugin or CLI). |
| LiteSpeed | Uninstall uses `/usr/local/lsws/admin/misc/cp_switch_ws.sh apache` and `/usr/local/lsws/admin/misc/uninstall.sh`; `/var/cpanel/disable_auto_lsws` stops reinstalls ([How to uninstall LiteSpeed][kb-uninstall-lsws]). ea-nginx is incompatible with LiteSpeed ([support][sup-lsws-nginx]). | Paths imply `/usr/local/lsws` (inference). |
| Other third-party nginx | cPanel support will not remove it; use the package manager ([support: third-party nginx][sup-third-party-nginx]) | No. |

Also relevant: a support article about nginx failing to start because Apache
still holds ports 80/443 ([support: ports already in use][sup-ports-in-use]).
The installer should check that 80/443 are free before starting nginx.

## Impact on the plan

1. **Meridian likely hides the plugin's cPanel section.** cPanel support says
   common third-party plugins are not yet available in Meridian; inference:
   U-8, U-9 and U-10 only work for accounts on Jupiter until cPanel adds plugin
   support to Meridian
   ([support][sup-meridian-plugins]). Decision for the customer: keep
   Jupiter as the default theme on their servers, and show a warning in WHM
   for accounts on Meridian (`listaccts` gives `theme`).
2. **Client hooks run as the user.** Changes made from cPanel fire
   `Cpanel`-category hooks that run as the cPanel user; the plugin needs
   escalated script hooks or a queue the root side reads. Addon domains have
   no WHM-level event. A periodic full reconcile is needed as a safety net
   (A-2).
3. **Stats and logs are not documented for a third-party nginx.** ea-nginx
   breaks Visitors, Errors and Raw Access; how bandwidth is counted for
   nginx logs is not public. N-8 needs a server test early in stage 1, not at
   the end. AWStats, Webalizer and Analog go away in 142 (GoAccess instead).
4. **Root path for clients is AdminBin, preferably a Perl admin module.** The
   Go core stays; the client-facing glue is a small Perl module (A-7).
5. **cPanel's own PHP-FPM pools must not be edited by hand.** PHP-4 (own pool
   template) needs a design choice in stage 2: drive cPanel's YAML or run
   separate pools.
6. **Versions.** The release table gives 136 an approximate end of life of
   August 2026;
   current targets are 134 LTS and the latest even release. Ubuntu 22.04 is
   tied to 134 LTS.

## What must be verified on the test server

| # | Item | Requirement | Why |
| --- | --- | --- | --- |
| 1 | `get_domain_info` / `listaccts` speed with 10 000 domains vs reading `/var/cpanel/userdata/` | A-1, N-1, N-2 | Speed not documented; file format not specified |
| 2 | Where installed certificates live on disk; read access for nginx | A-1, M-2 | Not documented |
| 3 | Which hooks fire for an addon domain (WHM and cPanel), for subdomains created in cPanel, for alias removal from cPanel | A-2, Q-2 | Not stated per event |
| 4 | Event names actually emitted by the Jupiter UI (`UAPI::…` vs `Api2::…`) for addon, subdomain, park, docroot change, SSL install/delete, PHP version | A-2 | Depends on which API the UI calls |
| 5 | Whether `post` hooks block the caller and any timeout | A-2, A-6 | Not documented |
| 6 | `manage_hooks list --output JSON` after install; hooks survive `upcp` | A-2, I-1 | Not documented |
| 7 | WHM CGI as a compiled binary vs a wrapper | U-1–U-7 | Not stated |
| 8 | cPanel plugin visible in Jupiter, absent in Meridian; behaviour of `install_plugin --theme` for Meridian | U-8, U-9 | Meridian support stated as missing |
| 9 | Perl admin module calling the Go CLI; `get_caller_username()` and domain ownership check | A-7, N-6 | Design check |
| 10 | Feature registration: hidden or extra permissions; `verify_user_has_feature` for a registered feature | U-10 | Not documented |
| 11 | Switching Apache ports via `set_tweaksetting` (does it rebuild and restart Apache?) and back; order of operations without downtime | M-6, I-6, I-7 | Not documented |
| 12 | `mod_remoteip` setup that keeps domlogs and `.htaccess` IP rules correct; cleanup on removal | M-6, I-7 | Two documented variants, choice needed |
| 13 | Custom chkservd service shows in Service Manager and `servicestatus` | I-6 | Not documented |
| 14 | AutoSSL DCV in each mode, including nginx mode with redirects and `.htaccess` | M-2 | Only Apache case documented |
| 15 | `cpanel.`, `webmail.`, `whm.` and other service subdomains in each mode | M-2 | Served by Apache config per docs |
| 16 | Bandwidth and stats in proxy, hybrid and nginx modes; whether nginx must write domlogs | N-8 | Not documented |
| 17 | Real names of the per-domain PHP-FPM YAML and socket paths | PHP-1, PHP-2 | Pages disagree |
| 18 | Effect of plugin-owned pools vs cPanel pools on MultiPHP Manager | PHP-4 | Design check |
| 19 | Detection of ea-nginx, Engintron, LiteSpeed on a real server | I-4 | Partly documented |
| 20 | Transfers (`Transfers::Session`) and service proxying during live transfer | A-2 | Edge case |

## HANDOFF section 6: what the documentation contradicts or updates

HANDOFF is a local working file, not in this repository; items refer to its
section 6.

| HANDOFF statement | What the pages say now |
| --- | --- |
| 6.1: in the OS table for 136, CloudLinux 10 is experimental and Ubuntu 22.04 unavailable | The table (updated 2026-09-25) marks CloudLinux 10 **supported** on 134 and 136; Ubuntu 22.04 is supported on 134 tiers and not available on 136 ([support: supported OS][sup-os]). |
| 6.1: plans are built around cPanel & WHM 136 | The release table gives 136 an approximate end of life of August 2026; 134 is the current LTS (approximately to June 2027) and 138 is the newest release listed ([Product versions][kb-release]). |
| Task brief: the current cPanel theme is Jupiter | Meridian is a new theme that can be set as default; cPanel support says common third-party plugins do not appear in it yet ([Meridian][meridian-welcome], [support][sup-meridian-plugins]). |
| 6.2: account and domain data in `/var/cpanel/userdata/` (from memory) | Confirmed to exist, but the documented interface is WHM API 1; the YAML is not to be edited and its schema is not published (section 1). |
| 6.2: client root actions through AdminBin (from memory) | Confirmed; the documented preferred form is a Perl admin module (section 4). |
| 6.1: cPanel plugin guide link built from a relative path | The link <https://api.docs.cpanel.net/guides/guide-to-cpanel-plugins> works. |

No statement in HANDOFF 6.1 about hooks, AppConfig or ea-nginx was
contradicted.

<!-- Links -->

[whm-intro]: https://api.docs.cpanel.net/whm/introduction
[whm-get-domain-info]: https://api.docs.cpanel.net/specifications/whm.openapi/domain-information/accounts-get_domain_info
[whm-domainuserdata]: https://api.docs.cpanel.net/specifications/whm.openapi/domain-information/accounts-domainuserdata
[whm-listaccts]: https://api.docs.cpanel.net/specifications/whm.openapi/account-management/accounts-listaccts
[whm-accountsummary]: https://api.docs.cpanel.net/specifications/whm.openapi/account-management/accounts-accountsummary
[whm-listsuspended]: https://api.docs.cpanel.net/specifications/whm.openapi/suspensions/accounts-listsuspended
[whm-getdomainowner]: https://api.docs.cpanel.net/specifications/whm.openapi/domain-information/accounts-getdomainowner
[whm-listips]: https://api.docs.cpanel.net/specifications/whm.openapi/ipv4-address-settings/ips-listips
[whm-fetch-vhost-ssl]: https://api.docs.cpanel.net/specifications/whm.openapi/cpanel-account-settings/ssl-fetch_vhost_ssl_components
[whm-fetch-ssl-vhosts]: https://api.docs.cpanel.net/specifications/whm.openapi/cpanel-account-settings/ssl-fetch_ssl_vhosts
[whm-php-vhost-versions]: https://api.docs.cpanel.net/specifications/whm.openapi/php/php-php_get_vhost_versions
[whm-php-set-vhost-versions]: https://api.docs.cpanel.net/specifications/whm.openapi/php/php-php_set_vhost_versions
[whm-php-installed]: https://api.docs.cpanel.net/specifications/whm.openapi/php/php-php_get_installed_versions
[whm-verify-feature]: https://api.docs.cpanel.net/specifications/whm.openapi/feature-access/accounts-verify_user_has_feature
[whm-get-featurelist-data]: https://api.docs.cpanel.net/specifications/whm.openapi/feature-lists/featurelists-get_featurelist_data
[whm-update-featurelist]: https://api.docs.cpanel.net/specifications/whm.openapi/feature-lists/featurelists-update_featurelist
[whm-set-tweaksetting]: https://api.docs.cpanel.net/specifications/whm.openapi/configurations/cpanel-set_tweaksetting
[whm-ea4-installed]: https://api.docs.cpanel.net/specifications/whm.openapi/easyapache-settings/ea4-ea4_get_currently_installed_packages
[uapi-domains-data]: https://api.docs.cpanel.net/specifications/cpanel.openapi/domain-information/domaininfo-domains_data
[uapi-single-domain-data]: https://api.docs.cpanel.net/specifications/cpanel.openapi/domain-information/domaininfo-single_domain_data
[uapi-installed-hosts]: https://api.docs.cpanel.net/specifications/cpanel.openapi/cpanel-account-ssl-management/ssl-installed_hosts
[uapi-addaddondomain]: https://api.docs.cpanel.net/specifications/cpanel.openapi/addondomain/addondomain-addaddondomain
[uapi-park]: https://api.docs.cpanel.net/specifications/cpanel.openapi/park/park-park
[uapi-has-feature]: https://api.docs.cpanel.net/specifications/cpanel.openapi/cpanel-features/features-has_feature
[uapi-php-set-vhost]: https://api.docs.cpanel.net/specifications/cpanel.openapi/php-settings/langphp-php_set_vhost_versions
[uapi-custom]: https://api.docs.cpanel.net/cpanel/custom
[cpapi2]: https://api.docs.cpanel.net/cpanel-api-2
[hooks-guide]: https://api.docs.cpanel.net/guides/guide-to-standardized-hooks
[hooks-events]: https://api.docs.cpanel.net/guides/guide-to-standardized-hooks/guide-to-standardized-hooks-hookable-events
[hooks-whostmgr]: https://api.docs.cpanel.net/guides/guide-to-standardized-hooks/guide-to-standardized-hooks-hookable-events/guide-to-standardized-hooks-whostmgr-functions
[hooks-cpanel]: https://api.docs.cpanel.net/guides/guide-to-standardized-hooks/guide-to-standardized-hooks-hookable-events/guide-to-standardized-hooks-cpanel-functions
[hooks-system]: https://api.docs.cpanel.net/guides/guide-to-standardized-hooks/guide-to-standardized-hooks-hookable-events/guide-to-standardized-hooks-system-functions
[hooks-manage]: https://api.docs.cpanel.net/guides/guide-to-standardized-hooks/guide-to-standardized-hooks-the-manage-hooks-utility
[hooks-action-code]: https://api.docs.cpanel.net/guides/guide-to-standardized-hooks/guide-to-standardized-hooks-hook-action-code
[hooks-exceptions]: https://api.docs.cpanel.net/guides/guide-to-standardized-hooks/guide-to-standardized-hooks-exceptions
[hooks-privesc]: https://api.docs.cpanel.net/guides/guide-to-standardized-hooks/guide-to-standardized-hooks-privilege-escalation
[whm-appconfig-reg]: https://api.docs.cpanel.net/guides/guide-to-whm-plugins/guide-to-whm-plugins-appconfig-registration
[whm-appconfig-file]: https://api.docs.cpanel.net/guides/guide-to-whm-plugins/guide-to-whm-plugins-appconfig-configuration-file
[whm-plugin-files]: https://api.docs.cpanel.net/guides/guide-to-whm-plugins/guide-to-whm-plugins-plugin-files
[whm-acls]: https://api.docs.cpanel.net/guides/guide-to-whm-plugins/guide-to-whm-plugins-access-control-lists
[whm-install-scripts]: https://api.docs.cpanel.net/guides/guide-to-whm-plugins/guide-to-whm-plugins-installation-scripts
[tut-whm-plugin]: https://api.docs.cpanel.net/guides/quickstart-development-guide/tutorial-create-a-whm-plugin
[quickstart-whm]: https://api.docs.cpanel.net/guides/quickstart-development-guide/quickstart-development-guide-whm
[cp-plugins]: https://api.docs.cpanel.net/guides/guide-to-cpanel-plugins
[cp-plugins-add]: https://api.docs.cpanel.net/guides/guide-to-cpanel-plugins/guide-to-cpanel-plugins-add-plugins
[liveapi]: https://api.docs.cpanel.net/guides/guide-to-the-liveapi-system
[liveapi-feature]: https://api.docs.cpanel.net/guides/guide-to-the-liveapi-system/guide-to-the-liveapi-system-liveapi-methods/guide-to-the-liveapi-system-the-cpanelfeature-method
[adminbin]: https://api.docs.cpanel.net/guides/guide-to-api-privilege-escalation
[adminbin-module]: https://api.docs.cpanel.net/guides/guide-to-api-privilege-escalation/guide-to-api-privilege-escalation-the-admin-module-method
[adminbin-app]: https://api.docs.cpanel.net/guides/guide-to-api-privilege-escalation/guide-to-api-privilege-escalation-application-files
[adminbin-conf]: https://api.docs.cpanel.net/guides/guide-to-api-privilege-escalation/guide-to-api-privilege-escalation-configuration-files
[adminbin-call]: https://api.docs.cpanel.net/guides/guide-to-api-privilege-escalation/guide-to-api-privilege-escalation-call-your-application
[script-install-plugin]: https://docs.cpanel.net/whm/scripts/the-install_plugin-script/
[script-uninstall-plugin]: https://docs.cpanel.net/whm/scripts/the-uninstall_plugin-script/
[script-php-fpm-config]: https://docs.cpanel.net/whm/scripts/the-php_fpm_config-script/
[meridian-welcome]: https://docs.cpanel.net/cpanel/meridian/getting-started/welcome-to-meridian/
[meridian-enable]: https://docs.cpanel.net/knowledge-base/cpanel-product/how-to-enable-the-meridian-theme/
[whm-feature-manager]: https://docs.cpanel.net/whm/packages/feature-manager/
[tweak-system]: https://docs.cpanel.net/whm/server-configuration/tweak-settings/system/
[kb-cpanel-config]: https://docs.cpanel.net/knowledge-base/cpanel-product/the-cpanel-config-file/
[eanginx]: https://docs.cpanel.net/knowledge-base/nginx/nginx-with-reverse-proxy/
[eanginx-default]: https://docs.cpanel.net/knowledge-base/nginx/the-default-configuration-of-nginx-with-reverse-proxy/
[eanginx-standalone]: https://docs.cpanel.net/knowledge-base/experimental-software/nginx-standalone/
[eanginx-script]: https://docs.cpanel.net/knowledge-base/nginx/the-ea-nginx-script/
[eanginx-troubleshooting]: https://docs.cpanel.net/knowledge-base/nginx/nginx-troubleshooting/
[ea4-advanced-apache]: https://docs.cpanel.net/ea4/apache/advanced-apache-configuration/
[ea4-custom-templates]: https://docs.cpanel.net/ea4/apache/custom-templates/
[ea4-php-handlers]: https://docs.cpanel.net/ea4/php/php-handlers/
[kb-rebuild-userdata]: https://docs.cpanel.net/knowledge-base/accounts/how-to-rebuild-userdata-files/
[kb-backup-tarball]: https://docs.cpanel.net/knowledge-base/backup/backup-tarball-contents/
[kb-release]: https://docs.cpanel.net/knowledge-base/cpanel-product/product-versions-and-the-release-process/
[kb-deprecation]: https://docs.cpanel.net/knowledge-base/cpanel-product/cpanel-deprecation-plan/
[kb-tailwatch]: https://docs.cpanel.net/knowledge-base/cpanel-product/tailwatch/
[whm-service-manager]: https://docs.cpanel.net/whm/service-configuration/service-manager/
[kb-guide-ssl]: https://docs.cpanel.net/knowledge-base/security/guide-to-ssl/
[kb-service-subdomains]: https://docs.cpanel.net/knowledge-base/general-systems-administration/service-and-proxy-subdomains/
[kb-log-files]: https://docs.cpanel.net/knowledge-base/cpanel-product/the-cpanel-log-files/
[kb-splitlogs]: https://docs.cpanel.net/knowledge-base/web-services/the-splitlogs-binary/
[kb-fpm-layout]: https://docs.cpanel.net/knowledge-base/php-fpm/php-fpm-code-and-filesystem-layout-for-easyapache-4/
[kb-fpm-pools]: https://docs.cpanel.net/knowledge-base/php-fpm/php-fpm-domain-pools/
[kb-fpm-values]: https://docs.cpanel.net/knowledge-base/php-fpm/configuration-values-of-php-fpm/
[whm-cloudlinux-manager]: https://docs.cpanel.net/whm/server-configuration/cloudlinux-manager/
[req-alma]: https://docs.cpanel.net/installation-guide/system-requirements-almalinux/
[req-cloudlinux]: https://docs.cpanel.net/installation-guide/system-requirements-cloudlinux/
[req-ubuntu]: https://docs.cpanel.net/installation-guide/system-requirements-ubuntu/
[kb-uninstall-lsws]: https://docs.cpanel.net/knowledge-base/third-party/how-to-uninstall-litespeed-web-server/
[sup-meridian-plugins]: https://support.cpanel.net/hc/en-us/articles/43509218242583-Why-are-third-party-plugins-missing-after-updating-to-Meridian
[sup-addon-whmapi]: https://support.cpanel.net/hc/en-us/articles/4533782268823-How-to-create-an-Addon-Domain-via-whmapi1
[sup-apache-port]: https://support.cpanel.net/hc/en-us/articles/360051036913-How-to-change-the-Apache-port-in-WHM
[sup-remoteip]: https://support.cpanel.net/hc/en-us/articles/360051107513-How-to-restore-visitors-IP-with-mod-remoteip
[sup-chkservd]: https://support.cpanel.net/hc/en-us/articles/1500000535122-How-to-add-a-new-service-for-chkservd-to-monitor
[sup-dcv-redirect]: https://support.cpanel.net/hc/en-us/articles/360052772894-How-to-prevent-AutoSSL-from-following-redirects-in-Apache-includes
[sup-dcv-htaccess]: https://support.cpanel.net/hc/en-us/articles/38778339941271--AutoSSL-Local-HTTP-DCV-error-404-not-found-htaccess-directives
[sup-eanginx-logs]: https://support.cpanel.net/hc/en-us/articles/4407570056215-Apache-Access-Logs-empty-after-installing-EA-NGINX
[sup-eanginx-standalone]: https://support.cpanel.net/hc/en-us/articles/360060333794-Why-is-ea-nginx-no-longer-running-in-standalone-mode
[sup-os]: https://support.cpanel.net/hc/en-us/articles/1500001216582-What-operating-systems-are-supported-by-cPanel
[sup-engintron]: https://support.cpanel.net/hc/en-us/articles/360060317354-How-to-uninstall-Engintron
[sup-lsws-nginx]: https://support.cpanel.net/hc/en-us/articles/4409752517527-Is-LiteSpeed-compatible-with-cPanel-NGINX
[sup-third-party-nginx]: https://support.cpanel.net/hc/en-us/articles/7748710026263-How-to-uninstall-third-party-NGINX
[sup-ports-in-use]: https://support.cpanel.net/hc/en-us/articles/4413711369111-Nginx-failed-to-start-ports-80-443-are-already-in-use-by-Apache
