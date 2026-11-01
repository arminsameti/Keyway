package engine

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// FreePort returns an unused loopback TCP port.
func FreePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// cappedBuffer keeps only the tail of a stream, for error reporting.
type cappedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.buf.Write(p)
	if over := c.buf.Len() - 4096; over > 0 {
		c.buf.Next(over)
	}
	return len(p), nil
}

func (c *cappedBuffer) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return strings.TrimSpace(c.buf.String())
}

// TempProc is one throw-away engine process of a probe.
type TempProc struct {
	Engine   Engine
	Install  Install
	Cfg      []byte
	WaitPort int // loopback port that accepts connections once the process is ready
}

// StartTemp launches a throw-away engine with cfg and waits until its SOCKS
// inbound on 127.0.0.1:port accepts connections. stop terminates it and
// removes its files.
func StartTemp(ctx context.Context, e Engine, in Install, cfg []byte, port int) (stop func(), err error) {
	return StartTempChain(ctx, []TempProc{{Engine: e, Install: in, Cfg: cfg, WaitPort: port}})
}

// StartTempChain starts the processes of a chain in order, each waiting until
// it listens, so a later process can dial the bridge of an earlier one. stop
// terminates them all, last first.
func StartTempChain(ctx context.Context, procs []TempProc) (stop func(), err error) {
	var stops []func()
	stopAll := func() {
		for i := len(stops) - 1; i >= 0; i-- {
			stops[i]()
		}
	}
	for _, tp := range procs {
		s, err := startTempProc(ctx, tp)
		if err != nil {
			stopAll()
			return nil, err
		}
		stops = append(stops, s)
	}
	return stopAll, nil
}

func startTempProc(ctx context.Context, tp TempProc) (stop func(), err error) {
	dir, err := os.MkdirTemp("", "xf-probe-*")
	if err != nil {
		return nil, err
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, tp.Cfg, 0o600); err != nil {
		cleanup()
		return nil, err
	}

	l := tp.Engine.Launch(tp.Install, path)
	cmd := exec.CommandContext(ctx, l.Binary, l.Args...)
	cmd.Env = append(os.Environ(), l.Env...)
	var out cappedBuffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		cleanup()
		return nil, err
	}
	exited := make(chan struct{})
	go func() { _ = cmd.Wait(); close(exited) }()
	stop = func() {
		_ = cmd.Process.Kill()
		<-exited
		cleanup()
	}

	addr := net.JoinHostPort("127.0.0.1", fmt.Sprint(tp.WaitPort))
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-exited:
			cleanup()
			return nil, fmt.Errorf("probe engine exited: %s", out.String())
		case <-ctx.Done():
			stop()
			return nil, ctx.Err()
		default:
		}
		if c, err := net.DialTimeout("tcp", addr, 150*time.Millisecond); err == nil {
			c.Close()
			return stop, nil
		}
		time.Sleep(60 * time.Millisecond)
	}
	stop()
	return nil, fmt.Errorf("probe engine did not start listening")
}

// URLTest fetches target through the SOCKS5 proxy at socksAddr and returns the
// elapsed milliseconds. A 204 endpoint is used by default.
func URLTest(ctx context.Context, socksAddr, target string, timeout time.Duration) (int64, error) {
	if target == "" {
		target = "http://www.gstatic.com/generate_204"
	}
	tr := &http.Transport{
		Proxy:             http.ProxyURL(&url.URL{Scheme: "socks5", Host: socksAddr}),
		DisableKeepAlives: true,
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{
		Transport:     tr,
		Timeout:       timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return -1, err
	}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return -1, err
	}
	resp.Body.Close()
	if resp.StatusCode >= 500 {
		return -1, fmt.Errorf("probe target answered %s", resp.Status)
	}
	return time.Since(start).Milliseconds(), nil
}
