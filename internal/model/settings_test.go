package model

import (
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func ptr[T any](v T) *T { return &v }

// TestFieldRegistry guards the steps in the package documentation: every
// Settings field has a JSON key, a Field constant and a place in Diff.
func TestFieldRegistry(t *testing.T) {
	typ := reflect.TypeFor[Settings]()
	var tags []Field
	for i := 0; i < typ.NumField(); i++ {
		sf := typ.Field(i)
		if sf.Type.Kind() != reflect.Pointer {
			t.Errorf("field %s must be a pointer so unset is distinguishable", sf.Name)
		}
		name, _, _ := strings.Cut(sf.Tag.Get("json"), ",")
		tags = append(tags, Field(name))
	}
	if !slices.Equal(tags, Fields()) {
		t.Fatalf("Settings JSON keys %v != Fields() %v", tags, Fields())
	}
	if n := reflect.TypeFor[Effective]().NumField(); n != len(Fields()) {
		t.Fatalf("Effective has %d fields, want %d", n, len(Fields()))
	}
	full := Settings{Mode: ptr(ModeProxy), PHPVersion: ptr(PHPVersion("x")), AppTemplate: ptr(TemplateNone), Cache: ptr(false)}
	if d := (Settings{}).Diff(full); !slices.Equal(d, Fields()) {
		t.Fatalf("Diff does not cover every field: %v", d)
	}
	for _, f := range Fields() {
		if err := f.Validate(); err != nil {
			t.Error(err)
		}
		if err := builtinAccess(f).Validate(); err != nil {
			t.Error(err)
		}
	}
}

func TestModeAndAccessValidate(t *testing.T) {
	for _, m := range []string{"proxy", "hybrid", "nginx"} {
		if _, err := ParseMode(m); err != nil {
			t.Errorf("ParseMode(%q): %v", m, err)
		}
	}
	for _, m := range []string{"", "Proxy", "standalone", "apache", "nginx "} {
		if _, err := ParseMode(m); !errors.Is(err, ErrInvalid) {
			t.Errorf("ParseMode(%q) = %v, want ErrInvalid", m, err)
		}
	}
	for _, a := range []Access{"", "Locked", "user", "root"} {
		if err := a.Validate(); err == nil {
			t.Errorf("Access(%q) accepted", a)
		}
	}
	if err := Field("firewall").Validate(); err == nil {
		t.Error("unknown field accepted")
	}
}

func TestLayerString(t *testing.T) {
	for l, want := range map[Layer]string{LayerBuiltin: "builtin", LayerServer: "server", LayerUser: "user", LayerDomain: "domain", 9: "Layer(9)"} {
		if got := l.String(); got != want {
			t.Errorf("%d: got %q want %q", int(l), got, want)
		}
	}
}

func TestSettingsValidate(t *testing.T) {
	tests := []struct {
		name string
		s    Settings
		ok   bool
	}{
		{"empty", Settings{}, true},
		{"full", Settings{Mode: ptr(ModeHybrid), PHPVersion: ptr(PHPVersion("ea-php83")), AppTemplate: ptr(TemplateName("wordpress")), Cache: ptr(true)}, true},
		{"bad mode", Settings{Mode: ptr(Mode("x"))}, false},
		{"empty php", Settings{PHPVersion: ptr(PHPVersion(""))}, false},
		{"bad template", Settings{AppTemplate: ptr(TemplateName("../x"))}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.s.Validate(); (err == nil) != tt.ok {
				t.Fatalf("Validate() = %v, want ok=%v", err, tt.ok)
			}
		})
	}
}

func TestServerValidate(t *testing.T) {
	tests := []struct {
		name string
		s    Server
		ok   bool
	}{
		{"zero", Server{}, true},
		{"access", Server{Access: map[Field]Access{FieldCache: AccessClient, FieldMode: AccessLocked}}, true},
		{"unknown field", Server{Access: map[Field]Access{"firewall": AccessClient}}, false},
		{"bad access", Server{Access: map[Field]Access{FieldMode: "everyone"}}, false},
		{"bad default", Server{Defaults: Settings{Mode: ptr(Mode("apache"))}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.s.Validate(); (err == nil) != tt.ok {
				t.Fatalf("Validate() = %v, want ok=%v", err, tt.ok)
			}
		})
	}
}

func TestResolve_A3(t *testing.T) {
	php := func(s string) *PHPVersion { return ptr(PHPVersion(s)) }
	tests := []struct {
		name         string
		srv          Server
		user, domain Settings
		want         Effective
	}{
		{
			name: "built-in defaults (M-4, C-3)",
			want: Effective{
				Mode:        Resolved[Mode]{ModeNginx, LayerBuiltin},
				PHPVersion:  Resolved[PHPVersion]{"", LayerBuiltin},
				AppTemplate: Resolved[TemplateName]{TemplateNone, LayerBuiltin},
				Cache:       Resolved[bool]{false, LayerBuiltin},
			},
		},
		{
			name:   "domain overrides user overrides server",
			srv:    Server{Defaults: Settings{Mode: ptr(ModeHybrid), PHPVersion: php("ea-php81"), AppTemplate: ptr(TemplateName("wordpress"))}},
			user:   Settings{PHPVersion: php("ea-php82"), AppTemplate: ptr(TemplateName("joomla"))},
			domain: Settings{AppTemplate: ptr(TemplateNone)},
			want: Effective{
				Mode:        Resolved[Mode]{ModeHybrid, LayerServer},
				PHPVersion:  Resolved[PHPVersion]{"ea-php82", LayerUser},
				AppTemplate: Resolved[TemplateName]{TemplateNone, LayerDomain},
				Cache:       Resolved[bool]{false, LayerBuiltin},
			},
		},
		{
			name:   "cache locked by default ignores lower layers (U-1, C-2)",
			user:   Settings{Cache: ptr(true)},
			domain: Settings{Cache: ptr(true)},
			want: Effective{
				Mode:        Resolved[Mode]{ModeNginx, LayerBuiltin},
				AppTemplate: Resolved[TemplateName]{TemplateNone, LayerBuiltin},
				Cache:       Resolved[bool]{false, LayerBuiltin},
			},
		},
		{
			name:   "cache enabled on server, domain turns it on (C-2, C-5)",
			srv:    Server{Access: map[Field]Access{FieldCache: AccessClient}},
			domain: Settings{Cache: ptr(true)},
			want: Effective{
				Mode:        Resolved[Mode]{ModeNginx, LayerBuiltin},
				AppTemplate: Resolved[TemplateName]{TemplateNone, LayerBuiltin},
				Cache:       Resolved[bool]{true, LayerDomain},
			},
		},
		{
			name:   "explicit false on domain beats true on user",
			srv:    Server{Access: map[Field]Access{FieldCache: AccessAdmin}},
			user:   Settings{Cache: ptr(true)},
			domain: Settings{Cache: ptr(false)},
			want: Effective{
				Mode:        Resolved[Mode]{ModeNginx, LayerBuiltin},
				AppTemplate: Resolved[TemplateName]{TemplateNone, LayerBuiltin},
				Cache:       Resolved[bool]{false, LayerDomain},
			},
		},
		{
			name:   "locked mode uses the server value",
			srv:    Server{Defaults: Settings{Mode: ptr(ModeProxy)}, Access: map[Field]Access{FieldMode: AccessLocked}},
			user:   Settings{Mode: ptr(ModeHybrid)},
			domain: Settings{Mode: ptr(ModeNginx)},
			want: Effective{
				Mode:        Resolved[Mode]{ModeProxy, LayerServer},
				AppTemplate: Resolved[TemplateName]{TemplateNone, LayerBuiltin},
				Cache:       Resolved[bool]{false, LayerBuiltin},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Resolve(tt.srv, tt.user, tt.domain); got != tt.want {
				t.Fatalf("got  %+v\nwant %+v", got, tt.want)
			}
		})
	}
}

func TestNewDomainSettings_M4(t *testing.T) {
	if got := NewDomainSettings(Server{}, Settings{}); got.Mode == nil || *got.Mode != ModeNginx {
		t.Fatalf("new domain default must be nginx, got %+v", got)
	}
	srv := Server{Defaults: Settings{Mode: ptr(ModeHybrid), Cache: ptr(true)}}
	got := NewDomainSettings(srv, Settings{})
	if *got.Mode != ModeHybrid {
		t.Fatalf("admin-changed default not used: %v", *got.Mode)
	}
	if got.Cache != nil || got.PHPVersion != nil || got.AppTemplate != nil {
		t.Fatalf("only mode may be stamped: %+v", got)
	}
	// The stamped mode survives a later change of the server default.
	srv.Defaults.Mode = ptr(ModeProxy)
	if m := Resolve(srv, Settings{}, got).Mode; m.Value != ModeHybrid || m.From != LayerDomain {
		t.Fatalf("existing domain switched mode: %+v", m)
	}
	if got := NewDomainSettings(Server{}, Settings{Mode: ptr(ModeProxy)}); *got.Mode != ModeProxy {
		t.Fatalf("user default not used: %v", *got.Mode)
	}
}

func TestExistingSiteSettings_M5(t *testing.T) {
	got := ExistingSiteSettings(Settings{})
	if got.Mode == nil || *got.Mode != ModeProxy {
		t.Fatalf("existing site must get proxy, got %+v", got)
	}
	keep := Settings{Mode: ptr(ModeHybrid), PHPVersion: ptr(PHPVersion("ea-php83"))}
	if got := ExistingSiteSettings(keep); len(got.Diff(keep)) != 0 {
		t.Fatalf("explicit settings changed: %+v", got)
	}
	in := Settings{Cache: ptr(true)}
	got = ExistingSiteSettings(in)
	if in.Mode != nil {
		t.Fatal("input was modified")
	}
	if *got.Mode != ModeProxy || !*got.Cache {
		t.Fatalf("got %+v", got)
	}
}

func TestCheckClientChange_U8(t *testing.T) {
	open := Server{Access: map[Field]Access{FieldCache: AccessClient}}
	closed := Server{Access: map[Field]Access{FieldMode: AccessAdmin, FieldPHPVersion: AccessLocked}}
	base := Settings{Mode: ptr(ModeNginx)}
	tests := []struct {
		name          string
		srv           Server
		before, after Settings
		wantErr       error
	}{
		{"no change", Server{}, base, base, nil},
		{"mode allowed by default", Server{}, base, Settings{Mode: ptr(ModeProxy)}, nil},
		{"cache locked by default", Server{}, base, Settings{Mode: ptr(ModeNginx), Cache: ptr(true)}, ErrNotPermitted},
		{"cache opened by admin (C-2)", open, base, Settings{Mode: ptr(ModeNginx), Cache: ptr(true)}, nil},
		{"admin-only mode", closed, base, Settings{Mode: ptr(ModeProxy)}, ErrNotPermitted},
		{"unsetting counts as change", closed, base, Settings{}, ErrNotPermitted},
		{"locked php", closed, base, Settings{Mode: ptr(ModeNginx), PHPVersion: ptr(PHPVersion("ea-php83"))}, ErrNotPermitted},
		{"invalid value", Server{}, base, Settings{Mode: ptr(Mode("apache"))}, ErrInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckClientChange(tt.srv, tt.before, tt.after)
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("got %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestIsEmpty(t *testing.T) {
	if !(Settings{}).IsEmpty() || (Settings{Cache: ptr(false)}).IsEmpty() {
		t.Fatal("IsEmpty wrong")
	}
}

func BenchmarkResolve(b *testing.B) {
	srv := Server{Defaults: Settings{PHPVersion: ptr(PHPVersion("ea-php83"))}, Access: map[Field]Access{FieldCache: AccessClient}}
	user := Settings{AppTemplate: ptr(TemplateName("wordpress"))}
	dom := Settings{Mode: ptr(ModeProxy), Cache: ptr(true)}
	for b.Loop() {
		_ = Resolve(srv, user, dom)
	}
}
