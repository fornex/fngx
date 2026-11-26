// SPDX-License-Identifier: GPL-3.0-or-later

package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/fornex/fngx/internal/product"
	"github.com/fornex/fngx/internal/respdiff"
)

// ExitDiff is returned by "respdiff compare" when significant
// differences were found.
const ExitDiff = 3

func runRespdiff(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		respdiffUsage(stderr)
		return ExitUsage
	}
	switch args[0] {
	case "snapshot":
		return runSnapshot(args[1:], stdout, stderr)
	case "compare":
		return runCompare(args[1:], stdout, stderr)
	case "rules":
		if len(args) > 1 {
			fmt.Fprintf(stderr, "%s respdiff rules: unexpected arguments\n", product.Name)
			return ExitUsage
		}
		fmt.Fprintln(stdout, respdiff.DefaultRulesJSON)
		return ExitOK
	case "help", "-h", "--help":
		respdiffUsage(stdout)
		return ExitOK
	}
	fmt.Fprintf(stderr, "%s respdiff: unknown subcommand %q\n\n", product.Name, args[0])
	respdiffUsage(stderr)
	return ExitUsage
}

func respdiffUsage(w io.Writer) {
	fmt.Fprintf(w, `Usage:
  %[1]s respdiff snapshot -server IP -targets FILE -out FILE [options]
  %[1]s respdiff compare [-rules FILE] [-json FILE] [-fail-on LEVEL] [-v] BEFORE AFTER
  %[1]s respdiff rules

snapshot  request every target from the server and record the answers
compare   compare two snapshots; exit code %[2]d when significant differences exist
rules     print the default normalization rules (the format of -rules files)

Run '%[1]s respdiff snapshot -h' or '%[1]s respdiff compare -h' for options.
`, product.Name, ExitDiff)
}

func newFlagSet(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(product.Name+" respdiff "+name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

func parseFlags(fs *flag.FlagSet, args []string) (int, bool) {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK, false
		}
		return ExitUsage, false
	}
	return 0, true
}

func loadRules(path string) (*respdiff.Rules, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path) //nolint:gosec // the path is given by the administrator
	if err != nil {
		return nil, err
	}
	r, err := respdiff.ParseRules(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &r, nil
}

func runSnapshot(args []string, _, stderr io.Writer) int {
	fs := newFlagSet("snapshot", stderr)
	server := fs.String("server", "", "IP address to send every request to (required; DNS is not used)")
	targetsPath := fs.String("targets", "", "file with one target per line: domain or domain/path (required)")
	out := fs.String("out", "", "snapshot file to write (required)")
	force := fs.Bool("force", false, "overwrite the output file if it exists")
	schemes := fs.String("schemes", "http,https", "schemes to request")
	httpPort := fs.Int("http-port", 80, "HTTP port")
	httpsPort := fs.Int("https-port", 443, "HTTPS port")
	method := fs.String("method", "GET", "GET or HEAD")
	conc := fs.Int("concurrency", respdiff.DefaultConcurrency, "maximum requests in flight")
	rate := fs.Float64("rate", respdiff.DefaultRate, "maximum requests started per second (all go to one IP)")
	timeout := fs.Duration("timeout", respdiff.DefaultTimeout, "time limit per request, including the body")
	maxBody := fs.Int64("max-body", respdiff.DefaultMaxBody, "body bytes read and hashed per response")
	tlsMode := fs.String("tls", string(respdiff.TLSStrict), "certificate check: strict (invalid = error) or record (record and continue)")
	repeat := fs.Int("repeat", 2, "requests per target and scheme; 2 or more detects dynamic pages and flaky answers")
	retries := fs.Int("retries", respdiff.DefaultRetries, "extra attempts after a network error or timeout")
	rulesPath := fs.String("rules", "", "rules file merged over the defaults")
	quiet := fs.Bool("quiet", false, "do not report progress")
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}
	if fs.NArg() > 0 || *server == "" || *targetsPath == "" || *out == "" {
		fmt.Fprintf(stderr, "%s respdiff snapshot: -server, -targets and -out are required and no arguments are allowed\n", product.Name)
		return ExitUsage
	}
	if *timeout <= 0 || *maxBody <= 0 || *conc <= 0 || *rate <= 0 || *retries < 0 || *repeat < 1 {
		fmt.Fprintf(stderr, "%s respdiff snapshot: -timeout, -max-body, -concurrency, -rate and -repeat must be positive, -retries not negative\n", product.Name)
		return ExitUsage
	}
	addr, err := netip.ParseAddr(*server)
	if err != nil {
		fmt.Fprintf(stderr, "%s respdiff snapshot: -server: %v\n", product.Name, err)
		return ExitUsage
	}
	if !*force {
		if _, err := os.Stat(*out); err == nil {
			fmt.Fprintf(stderr, "%s respdiff snapshot: %s exists; use -force to overwrite\n", product.Name, *out)
			return ExitError
		}
	}
	rules, err := loadRules(*rulesPath)
	if err != nil {
		fmt.Fprintf(stderr, "%s respdiff snapshot: %v\n", product.Name, err)
		return ExitError
	}
	f, err := os.Open(*targetsPath)
	if err != nil {
		fmt.Fprintf(stderr, "%s respdiff snapshot: %v\n", product.Name, err)
		return ExitError
	}
	targets, err := respdiff.ParseTargets(f)
	_ = f.Close()
	if err != nil {
		fmt.Fprintf(stderr, "%s respdiff snapshot: %s: %v\n", product.Name, *targetsPath, err)
		return ExitError
	}
	cfg := respdiff.Config{
		Server:      addr,
		Schemes:     strings.Split(*schemes, ","),
		HTTPPort:    *httpPort,
		HTTPSPort:   *httpsPort,
		Method:      strings.ToUpper(*method),
		Timeout:     *timeout,
		MaxBody:     *maxBody,
		TLSMode:     respdiff.TLSMode(*tlsMode),
		Concurrency: *conc,
		Rate:        *rate,
		Repeat:      *repeat,
		Retries:     *retries,
		Rules:       rules,
	}
	if !*quiet {
		total := len(targets) * len(cfg.Schemes)
		fmt.Fprintf(stderr, "Requesting %d targets x %d schemes from %s: at most %d in flight, %g per second.\n",
			len(targets), len(cfg.Schemes), addr, cfg.Concurrency, cfg.Rate)
		last := time.Now()
		cfg.Progress = func(done, all int) {
			if done == all || time.Since(last) >= 10*time.Second {
				last = time.Now()
				fmt.Fprintf(stderr, "  %d/%d done\n", done, total)
			}
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	snap, err := respdiff.Take(ctx, cfg, targets)
	if err != nil {
		fmt.Fprintf(stderr, "%s respdiff snapshot: %v\n", product.Name, err)
		return ExitError
	}
	if err := snap.WriteFile(*out, *force); err != nil {
		fmt.Fprintf(stderr, "%s respdiff snapshot: %v\n", product.Name, err)
		return ExitError
	}
	if !*quiet {
		errs, bad := 0, 0
		for i := range snap.Results {
			if snap.Results[i].Error != nil {
				errs++
			}
			if t := snap.Results[i].TLS; t != nil && !t.Verified {
				bad++
			}
		}
		fmt.Fprintf(stderr, "Wrote %s: %d results, %d failed requests, %d invalid certificates (tls mode %s).\n",
			*out, len(snap.Results), errs, bad, cfg.TLSMode)
	}
	return ExitOK
}

func runCompare(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("compare", stderr)
	rulesPath := fs.String("rules", "", "rules file merged over the defaults")
	jsonPath := fs.String("json", "", "also write the report as JSON to this file ('-' for stdout instead of text)")
	failOn := fs.String("fail-on", "critical", "lowest severity that makes the exit code non-zero: info, warning or critical")
	verbose := fs.Bool("v", false, "list info-level differences too")
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}
	if fs.NArg() != 2 {
		fmt.Fprintf(stderr, "%s respdiff compare: need exactly two snapshot files: BEFORE AFTER\n", product.Name)
		return ExitUsage
	}
	threshold, err := respdiff.ParseSeverity(*failOn)
	if err != nil || threshold == respdiff.SevIgnore {
		fmt.Fprintf(stderr, "%s respdiff compare: -fail-on must be info, warning or critical\n", product.Name)
		return ExitUsage
	}
	rules, err := loadRules(*rulesPath)
	if err != nil {
		fmt.Fprintf(stderr, "%s respdiff compare: %v\n", product.Name, err)
		return ExitError
	}
	before, err := respdiff.LoadSnapshotFile(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(stderr, "%s respdiff compare: %v\n", product.Name, err)
		return ExitError
	}
	after, err := respdiff.LoadSnapshotFile(fs.Arg(1))
	if err != nil {
		fmt.Fprintf(stderr, "%s respdiff compare: %v\n", product.Name, err)
		return ExitError
	}
	rep, err := respdiff.Compare(before, after, rules)
	if err != nil {
		fmt.Fprintf(stderr, "%s respdiff compare: %v\n", product.Name, err)
		return ExitError
	}
	switch *jsonPath {
	case "-":
		if err := rep.WriteJSON(stdout); err != nil {
			fmt.Fprintf(stderr, "%s respdiff compare: %v\n", product.Name, err)
			return ExitError
		}
	case "":
		rep.WriteText(stdout, *verbose)
	default:
		if err := writeJSONFile(*jsonPath, rep); err != nil {
			fmt.Fprintf(stderr, "%s respdiff compare: %v\n", product.Name, err)
			return ExitError
		}
		rep.WriteText(stdout, *verbose)
	}
	if rep.Significant(threshold) {
		if *jsonPath != "-" {
			fmt.Fprintf(stdout, "\nResult: DIFFERENT (differences at level %s or above).\n", threshold)
		}
		return ExitDiff
	}
	if *jsonPath != "-" {
		fmt.Fprintf(stdout, "\nResult: SAME (no differences at level %s or above).\n", threshold)
	}
	return ExitOK
}

func writeJSONFile(path string, rep *respdiff.Report) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) //nolint:gosec // the path is given by the administrator
	if err != nil {
		return err
	}
	if err := rep.WriteJSON(f); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
