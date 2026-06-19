package metrics

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"time"
)

// DefaultPath is used when no metrics path is configured.
const DefaultPath = "/metrics"

// Serve exposes the metrics handler at path on the given listener until ctx is
// cancelled, then shuts the server down gracefully. The caller creates the
// listener (so bind errors surface at startup) and Serve takes ownership of it.
// Serve blocks; run it in a goroutine.
func (m *Metrics) Serve(ctx context.Context, ln net.Listener, path string, logger *slog.Logger) error {
	if path == "" {
		path = DefaultPath
	}
	if logger == nil {
		logger = slog.Default()
	}

	mux := http.NewServeMux()
	mux.Handle(path, m.Handler())
	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("metrics endpoint listening", "address", ln.Addr().String(), "path", path)
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	case err := <-errCh:
		return err
	}
}
