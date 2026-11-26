package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/fornex/fngx/internal/product"
)

func TestRun(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		wantCode  int
		wantOut   string
		wantErr   string
		wantNoOut bool
		wantNoErr bool
	}{
		{name: "no args prints usage to stderr", args: nil, wantCode: ExitUsage, wantErr: "Usage:", wantNoOut: true},
		{name: "help", args: []string{"help"}, wantCode: ExitOK, wantOut: "Usage:", wantNoErr: true},
		{name: "help flag", args: []string{"--help"}, wantCode: ExitOK, wantOut: "version", wantNoErr: true},
		{name: "help with extra args", args: []string{"help", "x"}, wantCode: ExitUsage, wantErr: "unexpected arguments", wantNoOut: true},
		{name: "version", args: []string{"version"}, wantCode: ExitOK, wantOut: product.Name + " " + product.Version, wantNoErr: true},
		{name: "version flag", args: []string{"-v"}, wantCode: ExitOK, wantOut: "commit " + product.Commit, wantNoErr: true},
		{name: "version with extra args", args: []string{"version", "x"}, wantCode: ExitUsage, wantErr: "unexpected arguments", wantNoOut: true},
		{name: "unknown command", args: []string{"bogus"}, wantCode: ExitUsage, wantErr: `unknown command "bogus"`, wantNoOut: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			code := Run(tt.args, &out, &errOut)
			if code != tt.wantCode {
				t.Errorf("exit code = %d, want %d", code, tt.wantCode)
			}
			if !strings.Contains(out.String(), tt.wantOut) {
				t.Errorf("stdout = %q, want substring %q", out.String(), tt.wantOut)
			}
			if !strings.Contains(errOut.String(), tt.wantErr) {
				t.Errorf("stderr = %q, want substring %q", errOut.String(), tt.wantErr)
			}
			if tt.wantNoOut && out.Len() != 0 {
				t.Errorf("stdout = %q, want empty", out.String())
			}
			if tt.wantNoErr && errOut.Len() != 0 {
				t.Errorf("stderr = %q, want empty", errOut.String())
			}
		})
	}
}

func TestCommandNamesUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range commands() {
		if seen[c.name] {
			t.Errorf("duplicate command %q", c.name)
		}
		seen[c.name] = true
	}
}
