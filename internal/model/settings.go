// SPDX-License-Identifier: GPL-3.0-or-later

package model

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Mode is the per-domain nginx mode (section 5 of the requirements).
type Mode string

// Modes.
const (
	// ModeProxy: nginx passes every request to Apache.
	ModeProxy Mode = "proxy"
	// ModeHybrid: nginx serves static files, Apache the rest.
	ModeHybrid Mode = "hybrid"
	// ModeNginx: nginx with PHP-FPM, no Apache (standalone).
	ModeNginx Mode = "nginx"
)

// ParseMode validates a mode name from untrusted input (N-6).
func ParseMode(s string) (Mode, error) {
	m := Mode(s)
	if err := m.Validate(); err != nil {
		return "", err
	}
	return m, nil
}

// Validate reports whether m is one of the three modes.
func (m Mode) Validate() error {
	switch m {
	case ModeProxy, ModeHybrid, ModeNginx:
		return nil
	}
	return invalid("mode", string(m), "must be proxy, hybrid or nginx")
}

// Access says who may change a setting below the server layer
// (U-1, U-8, A-7).
type Access string

// Access levels, from most to least restrictive.
const (
	// AccessLocked: the server value applies to every domain; user and
	// domain values are ignored. "What the admin disabled the client
	// cannot enable" (U-1).
	AccessLocked Access = "locked"
	// AccessAdmin: the admin may set the value per user and per domain;
	// the client may not change it.
	AccessAdmin Access = "admin"
	// AccessClient: the client may also change it for own domains.
	AccessClient Access = "client"
)

// Validate reports whether a is a known access level.
func (a Access) Validate() error {
	switch a {
	case AccessLocked, AccessAdmin, AccessClient:
		return nil
	}
	return invalid("access", string(a), "must be locked, admin or client")
}

// Layer identifies where an effective value came from.
type Layer int

// Layers, from least to most specific.
const (
	LayerBuiltin Layer = iota
	LayerServer
	LayerUser
	LayerDomain
)

func (l Layer) String() string {
	switch l {
	case LayerBuiltin:
		return "builtin"
	case LayerServer:
		return "server"
	case LayerUser:
		return "user"
	case LayerDomain:
		return "domain"
	}
	return fmt.Sprintf("Layer(%d)", int(l))
}

// Field names a setting. The value equals the JSON key in settings files.
type Field string

// Fields.
const (
	FieldMode        Field = "mode"         // M-3
	FieldPHPVersion  Field = "php_version"  // PHP-1
	FieldAppTemplate Field = "app_template" // T-4
	FieldCache       Field = "cache"        // C-2, C-5
)

// Fields returns every setting in a stable order.
func Fields() []Field {
	return []Field{FieldMode, FieldPHPVersion, FieldAppTemplate, FieldCache}
}

// Validate reports whether f is a known field.
func (f Field) Validate() error {
	for _, k := range Fields() {
		if f == k {
			return nil
		}
	}
	return invalid("field", string(f), "unknown setting")
}

// Built-in defaults, used when no layer sets a value.
const (
	// BuiltinMode: new domains get standalone nginx (M-4).
	BuiltinMode = ModeNginx
	// BuiltinPHPVersion is empty: the generator uses the account's
	// default PHP as reported by cPanel.
	BuiltinPHPVersion PHPVersion = ""
	// BuiltinAppTemplate: no application template.
	BuiltinAppTemplate = TemplateNone
	// BuiltinCache: cache is off after installation (C-3).
	BuiltinCache = false
)

// builtinAccess is the access level when the server file does not set
// one. Cache is locked off until the admin enables it on the server
// (C-2, C-3); the rest is open to the client as in U-8.
func builtinAccess(f Field) Access {
	if f == FieldCache {
		return AccessLocked
	}
	return AccessClient
}

// Settings is one layer of settings. A nil field is not set on this
// layer and is inherited from the layer above.
type Settings struct {
	Mode        *Mode         `json:"mode,omitempty"`
	PHPVersion  *PHPVersion   `json:"php_version,omitempty"`
	AppTemplate *TemplateName `json:"app_template,omitempty"`
	Cache       *bool         `json:"cache,omitempty"`
}

// Validate checks every value that is set.
func (s Settings) Validate() error {
	var errs []error
	if s.Mode != nil {
		errs = append(errs, s.Mode.Validate())
	}
	if s.PHPVersion != nil {
		errs = append(errs, s.PHPVersion.Validate())
	}
	if s.AppTemplate != nil {
		errs = append(errs, s.AppTemplate.Validate())
	}
	return errors.Join(errs...)
}

// IsEmpty reports whether no field is set.
func (s Settings) IsEmpty() bool { return len(Settings{}.Diff(s)) == 0 }

func eqPtr[T comparable](a, b *T) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

// Diff returns the fields whose value (or set/unset state) differs
// between s and o.
func (s Settings) Diff(o Settings) []Field {
	var out []Field
	if !eqPtr(s.Mode, o.Mode) {
		out = append(out, FieldMode)
	}
	if !eqPtr(s.PHPVersion, o.PHPVersion) {
		out = append(out, FieldPHPVersion)
	}
	if !eqPtr(s.AppTemplate, o.AppTemplate) {
		out = append(out, FieldAppTemplate)
	}
	if !eqPtr(s.Cache, o.Cache) {
		out = append(out, FieldCache)
	}
	return out
}

// Server is the server layer: defaults for every domain and the access
// level of each setting.
type Server struct {
	Defaults Settings `json:"defaults,omitzero"`
	// Access overrides the built-in access level per field.
	Access map[Field]Access `json:"access,omitempty"`
}

// Validate checks the defaults and the access table.
func (s Server) Validate() error {
	errs := []error{s.Defaults.Validate()}
	for f, a := range s.Access {
		errs = append(errs, f.Validate(), a.Validate())
	}
	return errors.Join(errs...)
}

// AccessFor returns the effective access level of f.
func (s Server) AccessFor(f Field) Access {
	if a, ok := s.Access[f]; ok {
		return a
	}
	return builtinAccess(f)
}

// Resolved is an effective value and the layer it came from.
type Resolved[T any] struct {
	Value T
	From  Layer
}

// Effective is the fully resolved settings of one domain.
type Effective struct {
	Mode        Resolved[Mode]
	PHPVersion  Resolved[PHPVersion] // empty Value: account default PHP
	AppTemplate Resolved[TemplateName]
	Cache       Resolved[bool]
}

func pick[T any](a Access, builtin T, srv, usr, dom *T) Resolved[T] {
	if a != AccessLocked {
		if dom != nil {
			return Resolved[T]{*dom, LayerDomain}
		}
		if usr != nil {
			return Resolved[T]{*usr, LayerUser}
		}
	}
	if srv != nil {
		return Resolved[T]{*srv, LayerServer}
	}
	return Resolved[T]{builtin, LayerBuiltin}
}

// Resolve computes the effective settings of a domain owned by a user:
// domain overrides user overrides server overrides built-in (A-3), except
// for locked settings, which always come from the server or built-in
// defaults (U-1). Inputs are assumed valid (see Validate).
func Resolve(srv Server, user, domain Settings) Effective {
	d := srv.Defaults
	return Effective{
		Mode:        pick(srv.AccessFor(FieldMode), BuiltinMode, d.Mode, user.Mode, domain.Mode),
		PHPVersion:  pick(srv.AccessFor(FieldPHPVersion), BuiltinPHPVersion, d.PHPVersion, user.PHPVersion, domain.PHPVersion),
		AppTemplate: pick(srv.AccessFor(FieldAppTemplate), BuiltinAppTemplate, d.AppTemplate, user.AppTemplate, domain.AppTemplate),
		Cache:       pick(srv.AccessFor(FieldCache), BuiltinCache, d.Cache, user.Cache, domain.Cache),
	}
}

// NewDomainSettings returns the domain layer for a domain created after
// installation (M-4). The mode is written into the domain layer instead
// of being inherited, so a later change of the default mode applies only
// to domains created after it and never switches existing sites.
func NewDomainSettings(srv Server, user Settings) Settings {
	m := Resolve(srv, user, Settings{}).Mode.Value
	return Settings{Mode: &m}
}

// ExistingSiteSettings returns the domain layer for a site that already
// worked before the first installation on a server without Cpnginx: it
// gets proxy mode (M-5, I-5) unless the layer already sets a mode.
// Other fields are kept.
func ExistingSiteSettings(cur Settings) Settings {
	if cur.Mode == nil {
		m := ModeProxy
		cur.Mode = &m
	}
	return cur
}

// ErrNotPermitted is wrapped by errors for changes the client may not
// make (U-1, A-7).
var ErrNotPermitted = errors.New("not permitted")

// CheckClientChange checks a change of a domain layer requested by the
// client from cPanel (U-8). Every changed field must have client access,
// and the new layer must be valid. Changes made by the admin do not go
// through this check.
func CheckClientChange(srv Server, before, after Settings) error {
	if err := after.Validate(); err != nil {
		return err
	}
	var denied []string
	for _, f := range before.Diff(after) {
		if srv.AccessFor(f) != AccessClient {
			denied = append(denied, string(f))
		}
	}
	if len(denied) > 0 {
		sort.Strings(denied)
		return fmt.Errorf("%w: client may not change %s", ErrNotPermitted, strings.Join(denied, ", "))
	}
	return nil
}
