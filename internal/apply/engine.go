// SPDX-License-Identifier: GPL-3.0-or-later

package apply

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/fornex/fngx/internal/product"
)

// Names inside Config.Root.
const (
	liveName    = "live"
	gensName    = "generations"
	lockName    = ".lock"
	pendingName = ".pending"
	genPrefix   = "gen-"
	tmpInfix    = ".tmp-"
)

// Defaults. They are derived from the product name and do not assume any
// cPanel or third-party layout.
var (
	DefaultRoot        = "/etc/" + product.Name + "/nginx"
	DefaultLogFile     = "/var/log/" + product.Name + "/apply.log"
	DefaultNginxBinary = "/usr/local/" + product.Name + "/sbin/nginx" // assumption: install path of the nginx build
	DefaultPIDFile     = "/run/" + product.Name + "/nginx.pid"        // assumption: "pid" directive of the generated main file
)

// Default values for Config.
const (
	DefaultMainFile = "nginx.conf"
	DefaultKeep     = 5
	DefaultMaxTests = 64
)

// Config configures an Engine.
type Config struct {
	// Root holds generations, the live symlink and the lock file.
	Root string
	// MainFile is the main nginx configuration file, relative to a
	// generation. nginx must run with -c Root/live/MainFile.
	MainFile string
	// Keep is how many generations older than the live one are kept for
	// rollback. At least 1.
	Keep int
	// MaxTests bounds the number of "nginx -t" runs per operation, including
	// those spent isolating broken units (N-4).
	MaxTests int
	// Nginx tests and reloads configurations.
	Nginx Nginx
	// Logger receives one structured record per step (N-9). Required.
	Logger *slog.Logger
}

// DefaultConfig returns a configuration with default paths. The caller must
// still set Logger.
func DefaultConfig() Config {
	return Config{
		Root:     DefaultRoot,
		MainFile: DefaultMainFile,
		Keep:     DefaultKeep,
		MaxTests: DefaultMaxTests,
		Nginx: &ExecNginx{
			Binary:        DefaultNginxBinary,
			PIDFile:       DefaultPIDFile,
			TestTimeout:   DefaultTestTimeout,
			ReloadTimeout: DefaultReloadTimeout,
		},
	}
}

// Engine applies configuration changes. Every operation holds an exclusive
// lock on Root/.lock for its whole duration, so operations from any number
// of goroutines and processes run one at a time (A-6).
type Engine struct {
	cfg     Config
	root    string
	gens    string
	live    string
	lock    string
	pending string
}

// New checks cfg and creates Root and its generations directory.
func New(cfg Config) (*Engine, error) {
	if cfg.Root == "" || !filepath.IsAbs(cfg.Root) {
		return nil, fmt.Errorf("apply: root must be an absolute path, got %q", cfg.Root)
	}
	if cfg.MainFile == "" {
		cfg.MainFile = DefaultMainFile
	}
	if err := validPath(cfg.MainFile); err != nil {
		return nil, fmt.Errorf("apply: main file: %w", err)
	}
	if cfg.Keep < 1 {
		return nil, errors.New("apply: keep must be at least 1 so that rollback is possible")
	}
	if cfg.MaxTests < 1 {
		return nil, errors.New("apply: max tests must be at least 1")
	}
	if cfg.Nginx == nil {
		return nil, errors.New("apply: nginx is not configured")
	}
	if cfg.Logger == nil {
		return nil, errors.New("apply: logger is not configured")
	}
	root := filepath.Clean(cfg.Root)
	e := &Engine{
		cfg:     cfg,
		root:    root,
		gens:    filepath.Join(root, gensName),
		live:    filepath.Join(root, liveName),
		lock:    filepath.Join(root, lockName),
		pending: filepath.Join(root, pendingName),
	}
	if err := os.MkdirAll(e.gens, dirMode); err != nil {
		return nil, err
	}
	// The engine runs as root and follows paths under Root; a directory that
	// others can write would let them redirect those paths.
	for _, d := range []string{e.root, e.gens} {
		if err := checkPrivate(d); err != nil {
			return nil, err
		}
	}
	return e, nil
}

// LiveConf is the main file nginx must be started with.
func (e *Engine) LiveConf() string { return filepath.Join(e.live, e.cfg.MainFile) }

// Result describes a finished operation.
type Result struct {
	// Generation is the generation that is live after the operation, or the
	// candidate that was checked. Empty if nothing was built.
	Generation string
	// Rejected lists units that failed the test and were left at their
	// previous version (N-4). Their errors are for their authors only.
	Rejected []UnitError
	// Tests is the number of "nginx -t" runs.
	Tests int
	// Unchanged is set when the change matched the live set: no generation
	// was created and nginx was not reloaded.
	Unchanged bool
	// Reloaded is set when nginx confirmed the reload. It is false after a
	// successful Apply only if nginx is not running (ErrNotRunning); the new
	// set is then used when nginx starts.
	Reloaded bool
}

// UnitError is the test output that made a unit fail.
type UnitError struct {
	Unit   string
	Output string
}

// TestError means the configuration did not pass "nginx -t" and nothing was
// applied (T-9). Output is the nginx output with the candidate directory
// stripped from paths, so that it names files relative to the generation.
type TestError struct {
	Output string
}

func (e *TestError) Error() string {
	return "apply: configuration test failed: " + strings.TrimSpace(e.Output)
}

// ReloadError means the new configuration passed the test and was swapped
// in, but the reload command failed. RolledBack tells whether the previous
// generation is live again and was reloaded; if not, RollbackErr says why.
type ReloadError struct {
	Output      string
	Err         error
	RolledBack  bool
	RollbackErr error
}

func (e *ReloadError) Error() string {
	msg := fmt.Sprintf("apply: reload failed: %v", e.Err)
	if out := strings.TrimSpace(e.Output); out != "" {
		msg += ": " + out
	}
	if e.RolledBack {
		return msg + "; previous configuration restored"
	}
	return fmt.Sprintf("%s; rollback failed: %v", msg, e.RollbackErr)
}

func (e *ReloadError) Unwrap() []error {
	if e.RollbackErr == nil {
		return []error{e.Err}
	}
	return []error{e.Err, e.RollbackErr}
}

// ErrNoChange is returned when every changed unit was rejected and nothing
// else changed, so there is nothing to apply.
var ErrNoChange = errors.New("apply: no change left to apply")

// Apply validates the change and makes it live (A-5).
func (e *Engine) Apply(ctx context.Context, ch Change) (*Result, error) {
	return e.run(ctx, "apply", ch, true)
}

// Check builds and tests the change like Apply but never makes it live.
// Use it to show an author the nginx error before saving (T-9).
func (e *Engine) Check(ctx context.Context, ch Change) (*Result, error) {
	return e.run(ctx, "check", ch, false)
}

// Recover finishes or cleans up after an operation that was interrupted,
// for example by a crash or power loss. Apply and Check call it themselves;
// call it at service start to reload nginx after an interrupted swap.
func (e *Engine) Recover(ctx context.Context) error {
	log := e.cfg.Logger.With("op", newOpID(), "action", "recover")
	l, err := lockFile(ctx, e.lock)
	if err != nil {
		log.Error("lock failed", "error", err)
		return err
	}
	defer func() { _ = l.unlock() }()
	return e.recover(ctx, log)
}

func (e *Engine) run(ctx context.Context, action string, ch Change, commit bool) (res *Result, err error) {
	start := time.Now()
	log := e.cfg.Logger.With("op", newOpID(), "action", action)
	log.Info("start", "full", ch.Full, "common", len(ch.Common), "units", len(ch.Units),
		"remove", len(ch.Remove), "all_or_nothing", ch.AllOrNothing)
	defer func() {
		attrs := []any{"duration_ms", time.Since(start).Milliseconds()}
		if res != nil {
			attrs = append(attrs, "generation", res.Generation, "tests", res.Tests, "rejected", len(res.Rejected))
		}
		if err != nil {
			log.Error("failed", append(attrs, "error", capText(err.Error()))...)
		} else {
			log.Info("done", attrs...)
		}
	}()

	if err := ch.validate(e.cfg.MainFile); err != nil {
		return nil, err
	}
	l, err := lockFile(ctx, e.lock)
	if err != nil {
		return nil, fmt.Errorf("apply: lock: %w", err)
	}
	defer func() { _ = l.unlock() }()
	if err := e.recover(ctx, log); err != nil {
		return nil, err
	}

	liveName, err := e.liveGeneration()
	if err != nil {
		return nil, err
	}
	var liveDir string
	var liveM *manifest
	if liveName != "" {
		liveDir = filepath.Join(e.gens, liveName)
		if liveM, err = readManifest(liveDir); err != nil {
			return nil, err
		}
	}
	name, err := e.nextGeneration()
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(e.gens, name)
	res = &Result{Generation: name}
	keepCandidate := false
	defer func() {
		if !keepCandidate {
			if rmErr := os.RemoveAll(dir); rmErr != nil {
				log.Warn("remove candidate failed", "generation", name, "error", rmErr)
			}
		}
	}()

	c, err := buildCandidate(name, dir, liveDir, liveM, &ch)
	if err != nil {
		return res, err
	}
	log.Info("candidate built", "generation", name, "live", liveName, "changed_units", len(c.suspects))

	if err := e.settle(ctx, c, &ch, res, log); err != nil {
		return res, err
	}
	if !commit {
		return res, nil
	}
	if c.sameAsLive() && liveName != "" {
		if len(res.Rejected) > 0 {
			return res, ErrNoChange
		}
		// Nothing to do. Not creating a generation keeps the rollback
		// history from being pushed out by repeated identical applies.
		log.Info("candidate equals live set", "live", liveName)
		res.Generation, res.Unchanged = liveName, true
		return res, nil
	}
	if err := ctx.Err(); err != nil {
		return res, err
	}
	if err := c.finish(); err != nil {
		return res, err
	}

	// From here on the operation must run to the end even if the caller
	// gives up, otherwise nginx could be left between two sets (N-3).
	ctx = context.WithoutCancel(ctx)
	keepCandidate = true
	if err := e.writePending(liveName, name); err != nil {
		keepCandidate = false
		return res, err
	}
	if err := e.swap(name); err != nil {
		// The rename may have succeeded and only the directory sync failed:
		// look at what is live before deciding what to clean up.
		now, lerr := e.liveGeneration()
		switch {
		case lerr != nil:
			// Keep the candidate and the marker; recovery sorts it out.
			log.Error("swap failed, live link state unknown", "error", err, "check_error", lerr)
			return res, fmt.Errorf("apply: swap: %w", err)
		case now == liveName:
			keepCandidate = false
			_ = e.clearPending()
			return res, err
		default:
			log.Warn("swapped, but syncing the root directory failed", "error", err)
		}
	}
	log.Info("swapped", "from", liveName, "to", name)

	out, rerr := e.cfg.Nginx.Reload(ctx, e.LiveConf())
	if errors.Is(rerr, ErrNotRunning) {
		log.Warn("nginx not running; new set will be used when it starts", "generation", name, "error", rerr)
		rerr = nil
	} else if rerr == nil {
		res.Reloaded = true
	}
	if rerr != nil {
		log.Error("reload failed", "generation", name, "error", rerr, "output", capText(out))
		rerrFull := &ReloadError{Output: out, Err: rerr}
		rerrFull.RollbackErr = e.rollback(ctx, liveName, log)
		rerrFull.RolledBack = rerrFull.RollbackErr == nil
		if rerrFull.RolledBack {
			res.Generation = liveName
			_ = e.clearPending()
			e.prune(log)
		}
		return res, rerrFull
	}
	log.Info("reloaded", "generation", name)
	if err := e.clearPending(); err != nil {
		log.Warn("clear pending marker failed", "error", err)
	}
	e.prune(log)
	return res, nil
}

// rollback points live back at prev and reloads. With no previous
// generation the live link is removed, which restores the state before the
// first apply.
func (e *Engine) rollback(ctx context.Context, prev string, log *slog.Logger) error {
	var err error
	if prev == "" {
		err = os.Remove(e.live)
		if err == nil {
			err = syncPath(e.root)
		}
		if err != nil {
			log.Error("rollback failed", "error", err)
			return err
		}
		log.Warn("rolled back to no configuration")
		return errors.New("apply: no previous configuration to reload")
	}
	if err = e.swap(prev); err != nil {
		log.Error("rollback swap failed", "to", prev, "error", err)
		return err
	}
	out, err := e.cfg.Nginx.Reload(ctx, e.LiveConf())
	if errors.Is(err, ErrNotRunning) {
		log.Warn("rolled back; nginx not running", "to", prev)
		return nil
	}
	if err != nil {
		log.Error("rollback reload failed", "to", prev, "error", err, "output", capText(out))
		return fmt.Errorf("reload of %s: %w: %s", prev, err, strings.TrimSpace(out))
	}
	log.Warn("rolled back", "to", prev)
	return nil
}

// swap points the live symlink at generation name. The new link is created
// under a temporary name and renamed over the old one; rename(2) replaces
// the target atomically, so readers see either the old or the new link
// (https://pubs.opengroup.org/onlinepubs/9799919799/functions/rename.html).
func (e *Engine) swap(name string) error {
	tmp := e.live + tmpInfix + newOpID()
	if err := os.Symlink(filepath.Join(gensName, name), tmp); err != nil {
		return err
	}
	if err := os.Rename(tmp, e.live); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return syncPath(e.root)
}

// liveGeneration returns the name of the live generation, or "" if there is
// none. A live link that does not point at one of our generations is an
// error: it was changed by someone else and must not be overwritten.
func (e *Engine) liveGeneration() (string, error) {
	target, err := os.Readlink(e.live)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("apply: live link: %w", err)
	}
	dir, name := filepath.Split(target)
	if filepath.Clean(dir) != gensName || genSeq(name) < 0 {
		return "", fmt.Errorf("apply: live link %s points to %q, which is not a generation", e.live, target)
	}
	if _, err := os.Stat(filepath.Join(e.gens, name)); err != nil {
		return "", fmt.Errorf("apply: live generation: %w", err)
	}
	return name, nil
}

func genName(seq int) string { return fmt.Sprintf("%s%09d", genPrefix, seq) }

// genSeq parses a generation name; -1 means it is not one.
func genSeq(name string) int {
	s, ok := strings.CutPrefix(name, genPrefix)
	if !ok || len(s) != 9 {
		return -1
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return -1
	}
	return n
}

// generations lists generation names, oldest first.
func (e *Engine) generations() ([]string, error) {
	entries, err := os.ReadDir(e.gens)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, ent := range entries {
		if ent.IsDir() && genSeq(ent.Name()) >= 0 {
			names = append(names, ent.Name())
		}
	}
	sort.Slice(names, func(i, j int) bool { return genSeq(names[i]) < genSeq(names[j]) })
	return names, nil
}

func (e *Engine) nextGeneration() (string, error) {
	names, err := e.generations()
	if err != nil {
		return "", err
	}
	next := 1
	if len(names) > 0 {
		next = genSeq(names[len(names)-1]) + 1
	}
	if next > 999_999_999 {
		return "", errors.New("apply: generation counter exhausted")
	}
	return genName(next), nil
}

type pendingMarker struct {
	Prev string `json:"prev"`
	Next string `json:"next"`
}

// writePending records, durably, that a swap is about to happen and that
// nginx has not yet confirmed a reload.
func (e *Engine) writePending(prev, next string) error {
	data, err := json.Marshal(pendingMarker{Prev: prev, Next: next})
	if err != nil {
		return err
	}
	tmp := e.pending + tmpInfix + newOpID()
	if err := writeNewFile(tmp, data); err != nil {
		return err
	}
	if err := syncPath(tmp); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, e.pending); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return syncPath(e.root)
}

func (e *Engine) clearPending() error {
	if err := os.Remove(e.pending); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncPath(e.root)
}

// recover runs under the lock. It removes temporary files of interrupted
// operations, reloads nginx if a swap was not followed by a confirmed
// reload, and removes generations that never went live.
func (e *Engine) recover(ctx context.Context, log *slog.Logger) error {
	entries, err := os.ReadDir(e.root)
	if err != nil {
		return err
	}
	for _, ent := range entries {
		n := ent.Name()
		if strings.HasPrefix(n, liveName+tmpInfix) || strings.HasPrefix(n, pendingName+tmpInfix) {
			if err := os.Remove(filepath.Join(e.root, n)); err != nil {
				return err
			}
			log.Warn("removed leftover", "path", n)
		}
	}

	data, err := os.ReadFile(e.pending)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return err
	default:
		var pm pendingMarker
		if err := json.Unmarshal(data, &pm); err != nil {
			log.Warn("ignoring unreadable pending marker", "error", err)
		}
		if err := e.finishInterrupted(context.WithoutCancel(ctx), pm, log); err != nil {
			return err
		}
	}

	live, err := e.liveGeneration()
	if err != nil {
		return err
	}
	names, err := e.generations()
	if err != nil {
		return err
	}
	for _, n := range names {
		if live == "" || genSeq(n) > genSeq(live) {
			if err := os.RemoveAll(filepath.Join(e.gens, n)); err != nil {
				return err
			}
			log.Warn("removed generation that never went live", "generation", n)
		}
	}
	return nil
}

// finishInterrupted completes an operation that stopped between the swap
// and a confirmed reload. Whatever is live passed "nginx -t", so it is
// reloaded; if that fails and the newer set is live, the older one is
// restored.
func (e *Engine) finishInterrupted(ctx context.Context, pm pendingMarker, log *slog.Logger) error {
	live, err := e.liveGeneration()
	if err != nil {
		return err
	}
	log.Warn("finishing interrupted operation", "prev", pm.Prev, "next", pm.Next, "live", live)
	if live != "" {
		out, rerr := e.cfg.Nginx.Reload(ctx, e.LiveConf())
		if rerr == nil || errors.Is(rerr, ErrNotRunning) {
			log.Info("interrupted operation finished", "generation", live, "reload", errString(rerr))
			return e.clearPending()
		}
		log.Error("reload failed", "generation", live, "error", rerr, "output", capText(out))
		if live != pm.Next || genSeq(pm.Prev) < 0 {
			return &ReloadError{Output: out, Err: rerr, RollbackErr: errors.New("no previous generation to restore")}
		}
		if _, err := os.Stat(filepath.Join(e.gens, pm.Prev)); err != nil {
			return &ReloadError{Output: out, Err: rerr, RollbackErr: err}
		}
		if rbErr := e.rollback(ctx, pm.Prev, log); rbErr != nil {
			return &ReloadError{Output: out, Err: rerr, RollbackErr: rbErr}
		}
	}
	return e.clearPending()
}

// prune removes generations newer than the live one (failed candidates) and
// all but the newest Keep older ones. Errors are logged, not returned: the
// operation itself has already succeeded.
func (e *Engine) prune(log *slog.Logger) {
	live, err := e.liveGeneration()
	if err != nil || live == "" {
		return
	}
	names, err := e.generations()
	if err != nil {
		log.Warn("prune: list generations failed", "error", err)
		return
	}
	liveSeq := genSeq(live)
	var older []string
	for _, n := range names {
		switch s := genSeq(n); {
		case s > liveSeq:
			e.removeGeneration(n, log)
		case s < liveSeq:
			older = append(older, n)
		}
	}
	if extra := len(older) - e.cfg.Keep; extra > 0 {
		for _, n := range older[:extra] {
			e.removeGeneration(n, log)
		}
	}
}

func (e *Engine) removeGeneration(name string, log *slog.Logger) {
	if err := os.RemoveAll(filepath.Join(e.gens, name)); err != nil {
		log.Warn("prune failed", "generation", name, "error", err)
		return
	}
	log.Info("pruned", "generation", name)
}

func newOpID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// capText keeps log records bounded; nginx output for a large broken set
// can be long.
func capText(s string) string {
	const limit = 4096
	s = strings.TrimSpace(s)
	if len(s) > limit {
		return s[:limit] + "...(truncated)"
	}
	return s
}

func errString(err error) string {
	if err == nil {
		return "ok"
	}
	return err.Error()
}
