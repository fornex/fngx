// SPDX-License-Identifier: GPL-3.0-or-later

package model

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestParseSettings_A3(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want Settings
		ok   bool
	}{
		{"empty layer", `{"version":1}`, Settings{}, true},
		{"full layer", `{"version":1,"mode":"hybrid","php_version":"ea-php83","app_template":"wordpress","cache":false}`,
			Settings{Mode: ptr(ModeHybrid), PHPVersion: ptr(PHPVersion("ea-php83")), AppTemplate: ptr(TemplateName("wordpress")), Cache: ptr(false)}, true},
		{"whitespace", "\n {\n \"version\" : 1 ,\n \"mode\":\"proxy\"\n}\n\n", Settings{Mode: ptr(ModeProxy)}, true},

		{"empty file", ``, Settings{}, false},
		{"truncated", `{"version":1,"mode":"pro`, Settings{}, false},
		{"missing version", `{"mode":"proxy"}`, Settings{}, false},
		{"future version", `{"version":2}`, Settings{}, false},
		{"version as string", `{"version":"1"}`, Settings{}, false},
		{"version float", `{"version":1.5}`, Settings{}, false},
		{"unknown key", `{"version":1,"firewall":true}`, Settings{}, false},
		{"case-folded key", `{"version":1,"Mode":"proxy"}`, Settings{}, false},
		{"unicode-folded key", `{"version":1,"mode":"proxy","caſe":true}`, Settings{}, false},
		{"duplicate key", `{"version":1,"mode":"nginx","mode":"proxy"}`, Settings{}, false},
		{"null", `{"version":1,"mode":null}`, Settings{}, false},
		{"trailing object", `{"version":1}{"version":1}`, Settings{}, false},
		{"trailing garbage", `{"version":1} x`, Settings{}, false},
		{"top-level array", `[{"version":1}]`, Settings{}, false},
		{"top-level string", `"x"`, Settings{}, false},
		{"bad mode", `{"version":1,"mode":"apache"}`, Settings{}, false},
		{"empty php", `{"version":1,"php_version":""}`, Settings{}, false},
		{"traversal template", `{"version":1,"app_template":"../../etc/passwd"}`, Settings{}, false},
		{"cache as string", `{"version":1,"cache":"yes"}`, Settings{}, false},
		{"mode as number", `{"version":1,"mode":1}`, Settings{}, false},
		{"nested unknown", `{"version":1,"x":{"y":[1,2]}}`, Settings{}, false},
		{"empty key", `{"version":1,"":1}`, Settings{}, false},
		{"bom", "\xef\xbb\xbf{\"version\":1}", Settings{}, false},
		{"binary garbage", "\x00\x01\x02\xff", Settings{}, false},
		{"trailing comma", `{"version":1,}`, Settings{}, false},
		{"comment", `{"version":1 /* x */}`, Settings{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseSettings([]byte(tt.in))
			if !tt.ok {
				if err == nil {
					t.Fatalf("accepted: %+v", got)
				}
				if !errors.Is(err, ErrInvalid) {
					t.Fatalf("error does not wrap ErrInvalid: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if d := got.Diff(tt.want); len(d) != 0 {
				t.Fatalf("fields differ: %v", d)
			}
		})
	}
}

func TestParseLimits(t *testing.T) {
	big := `{"version":1,"x":"` + strings.Repeat("a", MaxFileSize) + `"}`
	if _, err := ParseSettings([]byte(big)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("oversized file: %v", err)
	}
	deep := `{"version":1,"x":` + strings.Repeat(`{"a":`, maxDepth+1) + `1` + strings.Repeat(`}`, maxDepth+1) + `}`
	if _, err := ParseSettings([]byte(deep)); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "nesting") {
		t.Fatalf("deep nesting: %v", err)
	}
	deepArr := `{"version":1,"x":` + strings.Repeat(`[`, maxDepth+1) + strings.Repeat(`]`, maxDepth+1) + `}`
	if _, err := ParseSettings([]byte(deepArr)); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "nesting") {
		t.Fatalf("deep array nesting: %v", err)
	}
	longKey := `{"version":1,"` + strings.Repeat("k", maxKeyLen+1) + `":1}`
	if _, err := ParseSettings([]byte(longKey)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("long key: %v", err)
	}
}

func TestParseServer_U1(t *testing.T) {
	tests := []struct {
		name string
		in   string
		ok   bool
	}{
		{"minimal", `{"version":1}`, true},
		{"empty objects", `{"version":1,"defaults":{},"access":{}}`, true},
		{"full", `{"version":1,"defaults":{"mode":"proxy","cache":true},"access":{"cache":"client","mode":"admin"}}`, true},
		{"unknown access field", `{"version":1,"access":{"firewall":"client"}}`, false},
		{"bad access level", `{"version":1,"access":{"mode":"all"}}`, false},
		{"null access", `{"version":1,"access":{"mode":null}}`, false},
		{"duplicate nested", `{"version":1,"access":{"mode":"admin","mode":"client"}}`, false},
		{"unknown default", `{"version":1,"defaults":{"foo":1}}`, false},
		{"defaults wrong case", `{"version":1,"Defaults":{"mode":"proxy"}}`, false},
		{"settings at top level", `{"version":1,"mode":"proxy"}`, false},
		{"defaults not object", `{"version":1,"defaults":"nginx"}`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseServer([]byte(tt.in))
			if (err == nil) != tt.ok {
				t.Fatalf("ParseServer error = %v, want ok=%v", err, tt.ok)
			}
			if err != nil && !errors.Is(err, ErrInvalid) {
				t.Fatalf("error does not wrap ErrInvalid: %v", err)
			}
		})
	}
}

func TestRoundTrip(t *testing.T) {
	s := Settings{Mode: ptr(ModeProxy), PHPVersion: ptr(PHPVersion("alt-php74")), Cache: ptr(false)}
	data, err := MarshalSettings(s)
	if err != nil {
		t.Fatal(err)
	}
	want := "{\n  \"version\": 1,\n  \"mode\": \"proxy\",\n  \"php_version\": \"alt-php74\",\n  \"cache\": false\n}\n"
	if string(data) != want {
		t.Fatalf("unexpected encoding:\n%s", data)
	}
	got, err := ParseSettings(data)
	if err != nil {
		t.Fatal(err)
	}
	if d := got.Diff(s); len(d) != 0 {
		t.Fatalf("round trip changed %v", d)
	}

	srv := Server{Defaults: Settings{Mode: ptr(ModeHybrid)}, Access: map[Field]Access{FieldCache: AccessClient, FieldMode: AccessAdmin}}
	data, err = MarshalServer(srv)
	if err != nil {
		t.Fatal(err)
	}
	gotSrv, err := ParseServer(data)
	if err != nil {
		t.Fatalf("%v\n%s", err, data)
	}
	if len(gotSrv.Defaults.Diff(srv.Defaults)) != 0 || len(gotSrv.Access) != 2 || gotSrv.Access[FieldMode] != AccessAdmin {
		t.Fatalf("server round trip: %+v", gotSrv)
	}
	if data, err := MarshalServer(Server{}); err != nil || string(data) != "{\n  \"version\": 1\n}\n" {
		t.Fatalf("zero server: %q %v", data, err)
	}
}

func TestMarshalRejectsInvalid(t *testing.T) {
	if _, err := MarshalSettings(Settings{Mode: ptr(Mode("x"))}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("settings: %v", err)
	}
	if _, err := MarshalServer(Server{Access: map[Field]Access{"x": AccessClient}}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("server: %v", err)
	}
}

func fuzzSeeds(f *testing.F) {
	for _, s := range []string{
		`{"version":1}`,
		`{"version":1,"mode":"hybrid","php_version":"ea-php83","app_template":"wordpress","cache":true}`,
		`{"version":1,"defaults":{"mode":"proxy"},"access":{"cache":"client"}}`,
		`{"version":1,"mode":"nginx","mode":"proxy"}`,
		`{"version":1,"Mode":"proxy"}`,
		`{"version":1,"x":[1,{"a":null}]}`,
		`{"version":1}{}`,
		``,
	} {
		f.Add([]byte(s))
	}
}

// FuzzParseSettings checks that the parser never panics, that every error
// wraps ErrInvalid, and that accepted input survives a round trip (N-6).
func FuzzParseSettings(f *testing.F) {
	fuzzSeeds(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		s, err := ParseSettings(data)
		if err != nil {
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("error does not wrap ErrInvalid: %v", err)
			}
			return
		}
		out, err := MarshalSettings(s)
		if err != nil {
			t.Fatalf("accepted value does not marshal: %v", err)
		}
		again, err := ParseSettings(out)
		if err != nil {
			t.Fatalf("re-parse failed: %v\n%s", err, out)
		}
		if d := again.Diff(s); len(d) != 0 {
			t.Fatalf("round trip changed %v", d)
		}
		if out2, _ := MarshalSettings(again); !bytes.Equal(out, out2) {
			t.Fatal("encoding not stable")
		}
	})
}

func FuzzParseServer(f *testing.F) {
	fuzzSeeds(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		s, err := ParseServer(data)
		if err != nil {
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("error does not wrap ErrInvalid: %v", err)
			}
			return
		}
		out, err := MarshalServer(s)
		if err != nil {
			t.Fatalf("accepted value does not marshal: %v", err)
		}
		if _, err := ParseServer(out); err != nil {
			t.Fatalf("re-parse failed: %v\n%s", err, out)
		}
	})
}
