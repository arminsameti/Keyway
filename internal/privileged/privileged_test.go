package privileged

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const goodConfig = `{"log":{"level":"warn","output":""},"inbounds":[
 {"type":"tun","tag":"tun-in","auto_route":true},
 {"type":"socks","tag":"s","listen":"127.0.0.1","listen_port":1080}],
 "outbounds":[{"type":"direct","tag":"direct"}],
 "route":{"rule_set":[{"type":"local","tag":"x","format":"binary","path":"/u/x.srs"}],"rules":[{"process_path":["/a/xray"],"outbound":"direct"}]}}`

func TestValidateConfigAcceptsOurShapeAndRefusesFileAccess(t *testing.T) {
	if err := ValidateConfig([]byte(goodConfig)); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct{ cfg, want string }{
		"log file":      {`{"log":{"output":"/etc/passwd"},"inbounds":[{"type":"tun"}]}`, "writing logs"},
		"cache file":    {`{"experimental":{"cache_file":{"enabled":true,"path":"/x"}},"inbounds":[{"type":"tun"}]}`, "cache file"},
		"key path":      {`{"outbounds":[{"type":"ssh","private_key_path":"/var/root/.ssh/id"}],"inbounds":[{"type":"tun"}]}`, "private key"},
		"cert path":     {`{"outbounds":[{"tls":{"certificate_path":"/x"}}],"inbounds":[{"type":"tun"}]}`, "certificate"},
		"open inbound":  {`{"inbounds":[{"type":"tun"},{"type":"socks","listen":"0.0.0.0"}]}`, "loopback"},
		"other inbound": {`{"inbounds":[{"type":"tun"},{"type":"shadowsocks"}]}`, "not allowed"},
		"no tun":        {`{"inbounds":[{"type":"socks","listen":"127.0.0.1"}]}`, "no tun"},
		"remote rules":  {`{"inbounds":[{"type":"tun"}],"route":{"rule_set":[{"type":"remote"}]}}`, "local rule sets"},
		"not json":      {`nope`, "not valid JSON"},
	} {
		if err := ValidateConfig([]byte(c.cfg)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", name, err, c.want)
		}
	}
}

// fakeSingBox is a shell script that behaves like a long-running engine.
func fakeSingBox(t *testing.T, dir string) string {
	t.Helper()
	p := filepath.Join(dir, "fake-sing-box")
	if err := os.WriteFile(p, []byte("#!/bin/sh\necho started \"$@\"\nsleep 30\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func runOpts(t *testing.T) (RunOptions, string) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfg, []byte(goodConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	return RunOptions{Binary: fakeSingBox(t, dir), ConfigPath: cfg, ParentPID: os.Getpid(), UID: os.Getuid(),
		LogFile: filepath.Join(dir, "log"), StopFile: filepath.Join(dir, "stop"), ReadyFile: filepath.Join(dir, "ready"),
		PIDFile: filepath.Join(dir, "pid"), TempRoot: dir, AllowNonRoot: true}, dir
}

func wait(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for end := time.Now().Add(6 * time.Second); time.Now().Before(end); time.Sleep(50 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestRunSupervisesUntilTheStopFileAppears(t *testing.T) {
	o, dir := runOpts(t)
	done := make(chan error, 1)
	go func() { done <- Run(o) }()
	wait(t, "ready file", func() bool { _, err := os.Stat(o.ReadyFile); return err == nil })
	wait(t, "the engine's output in the log file", func() bool {
		b, _ := os.ReadFile(o.LogFile)
		return strings.Contains(string(b), "started run -c")
	})
	if _, err := os.Stat(o.PIDFile); err != nil {
		t.Error("the helper records its pid for the app")
	}
	if err := os.WriteFile(o.StopFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("a requested stop is not an error: %v", err)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("the helper did not stop")
	}
	if left, _ := filepath.Glob(filepath.Join(dir, "xf-tun-*")); len(left) != 0 {
		t.Errorf("the private working directory must be removed: %v", left)
	}
	if _, err := os.Stat(o.PIDFile); err == nil {
		t.Error("the pid file must be removed")
	}
}

func TestRunRefusesABadConfigAndAnOrphan(t *testing.T) {
	o, _ := runOpts(t)
	if err := os.WriteFile(o.ConfigPath, []byte(`{"log":{"output":"/etc/hosts"},"inbounds":[{"type":"tun"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Run(o); err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Errorf("bad config: %v", err)
	}
	o, _ = runOpts(t)
	o.ParentPID = 0
	if err := Run(o); err == nil {
		t.Error("a parent pid is required")
	}
	o, _ = runOpts(t)
	o.AllowNonRoot = false
	if os.Geteuid() != 0 {
		if err := Run(o); err == nil || !strings.Contains(err.Error(), "root") {
			t.Errorf("not root: %v", err)
		}
	}
}

func TestRunStopsWhenTheParentAppIsGone(t *testing.T) {
	o, _ := runOpts(t)
	o.ParentPID = 999999 // no such process
	start := time.Now()
	if err := Run(o); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > 4*time.Second {
		t.Error("an orphaned helper must exit quickly")
	}
}

func TestOpenOwnedRefusesSymlinksAndOtherPeoplesFiles(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	_ = os.WriteFile(target, []byte("precious"), 0o600)
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := openOwned(link, os.Getuid(), 0); err == nil {
		t.Error("a symbolic link must be refused")
	}
	if b, _ := os.ReadFile(target); string(b) != "precious" {
		t.Error("the link target must be untouched")
	}
	if _, err := openOwned("", 0, 0); err == nil {
		t.Error("an empty path must be refused")
	}
}
