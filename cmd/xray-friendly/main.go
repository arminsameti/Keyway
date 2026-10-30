// Command xray-friendly runs the local backend (JSON API) used by the native
// macOS app to manage the proxy engines.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"xray-friendly/internal/api"
	"xray-friendly/internal/core"
	"xray-friendly/internal/engine"
	"xray-friendly/internal/service"
	"xray-friendly/internal/store"
	"xray-friendly/internal/sysproxy"
)

// version is stamped at build time: -ldflags "-X main.version=1.2.3".
var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "xray-friendly:", err)
		os.Exit(1)
	}
}

func run() error {
	port := flag.Int("port", 0, "API port (default: from settings, else 12345)")
	dataDir := flag.String("data-dir", "", "data directory (default ~/.xray-friendly)")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("xray-friendly", version)
		return nil
	}

	level := slog.LevelInfo
	if os.Getenv("XF_DEBUG") != "" {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	dir := *dataDir
	if dir == "" {
		d, err := store.DefaultDir()
		if err != nil {
			return err
		}
		dir = d
	}
	st, err := store.Open(dir)
	if err != nil {
		return err
	}
	if w := st.Warning(); w != "" {
		log.Warn("store", "warning", w)
	}

	apiPort := st.Get().Settings.APIPort
	if *port != 0 {
		apiPort = *port
	}
	// Bind first: a second instance must fail here, before it can touch the
	// first instance's xray process or system proxy during recovery.
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(apiPort)))
	if err != nil {
		return fmt.Errorf("cannot listen on 127.0.0.1:%d (already running? choose another with -port): %w", apiPort, err)
	}

	enginesDir := filepath.Join(dir, "engines")
	migrateCoresDir(dir, enginesDir, log)
	xrayCores, err := core.NewManager(filepath.Join(enginesDir, engine.NameXray), core.XraySource)
	if err != nil {
		return err
	}
	sbCores, err := core.NewManager(filepath.Join(enginesDir, engine.NameSingBox), core.SingBoxSource)
	if err != nil {
		return err
	}
	runner := engine.NewRunner(filepath.Join(dir, "xray.pid"))
	svc, err := service.New(service.Config{
		Store: st,
		Engines: []service.EngineSlot{
			{Engine: engine.Xray{}, Manager: xrayCores},
			{Engine: &engine.SingBox{RuleSetPath: sbCores.RuleSetPath}, Manager: sbCores},
		},
		EnginesDir: enginesDir,
		Runner:     runner, Sys: sysproxy.New(), Logger: log, Dir: dir,
		AutoDownload: true,
	})
	if err != nil {
		return err
	}

	token, err := newToken()
	if err != nil {
		return err
	}
	// The native menu-bar app reads these to talk to the backend.
	tokenFile, portFile := filepath.Join(dir, "api-token"), filepath.Join(dir, "api-port")
	if err := os.WriteFile(tokenFile, []byte(token), 0o600); err != nil {
		return fmt.Errorf("write token file: %w", err)
	}
	if err := os.WriteFile(portFile, []byte(strconv.Itoa(apiPort)), 0o600); err != nil {
		return fmt.Errorf("write port file: %w", err)
	}
	defer os.Remove(tokenFile)
	defer os.Remove(portFile)

	apiSrv, err := api.New(svc, api.Config{Token: token, Port: apiPort, Logger: log})
	if err != nil {
		return err
	}
	httpSrv := &http.Server{
		Handler:           apiSrv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       60 * time.Second,
		// No WriteTimeout: core downloads and real-latency tests legitimately
		// take minutes; they are bounded by their own contexts instead.
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	svc.Recover(ctx)
	go svc.Run(ctx)

	serveErr := make(chan error, 1)
	go func() {
		url := fmt.Sprintf("http://127.0.0.1:%d", apiPort)
		log.Info("listening", "url", url, "version", version, "data", dir)
		if err := httpSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
		}
	}()
	select {
	case <-ctx.Done():
		log.Info("shutting down")
	case err := <-serveErr:
		log.Error("server failed", "err", err)
	}

	// Order matters: stop xray and restore the system proxy first, so the user
	// is never left with a proxy setting that points at nothing.
	svc.Shutdown()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return httpSrv.Shutdown(shutdownCtx)
}

func newToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// migrateCoresDir moves Xray installs from the schema-2 location (cores/) to
// engines/xray/. If the move fails the old directory is left alone and a fresh
// one is used, so nothing is lost; the user can download the core again.
func migrateCoresDir(dataDir, enginesDir string, log *slog.Logger) {
	old := filepath.Join(dataDir, "cores")
	dst := filepath.Join(enginesDir, engine.NameXray)
	if _, err := os.Stat(old); err != nil {
		return
	}
	if _, err := os.Stat(dst); err == nil {
		return
	}
	if err := os.MkdirAll(enginesDir, 0o700); err != nil {
		log.Warn("could not create engines/", "err", err)
		return
	}
	if err := os.Rename(old, dst); err != nil {
		log.Warn("could not move cores/ to engines/xray/", "err", err)
	}
}
