package apply

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"syscall"
)

// OpenLog opens the plugin's own operation log (N-9) for appending and
// returns a logger that writes one JSON object per line. Values that contain
// newlines, such as nginx output, are escaped, so every record stays on one
// line. The caller closes the returned file.
func OpenLog(path string) (*slog.Logger, io.Closer, error) {
	if err := os.MkdirAll(filepath.Dir(path), dirMode); err != nil {
		return nil, nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, fileMode) //nolint:gosec // path comes from configuration
	if err != nil {
		return nil, nil, err
	}
	return NewLogger(f), f, nil
}

// NewLogger returns a JSON-lines logger writing to w.
func NewLogger(w io.Writer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: slog.LevelInfo})).
		With("component", "apply")
}
