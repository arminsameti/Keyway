package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"xray-friendly/internal/models"
	"xray-friendly/internal/profile"
	"xray-friendly/internal/singbox"
)

// SingBox is the sing-box engine. Which protocols it can run depends on the
// build tags of the installed binary, which the service reports via SetTags.
type SingBox struct {
	// RuleSetPath maps a rule set name ("geosite-cn") to its local file.
	RuleSetPath func(name string) string

	mu   sync.RWMutex
	tags map[string]bool // nil until a binary is known
}

func (*SingBox) Name() string        { return NameSingBox }
func (*SingBox) DisplayName() string { return "sing-box" }

// SetTags records the build tags of the active binary (nil = unknown).
func (s *SingBox) SetTags(tags map[string]bool) {
	s.mu.Lock()
	s.tags = tags
	s.mu.Unlock()
}

func (s *SingBox) Supports(p profile.Profile) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return singbox.Supports(p, s.tags)
}

// RuleSets lists the rule-set files the routing settings need.
func (*SingBox) RuleSets(st models.Settings) []string { return singbox.RequiredRuleSets(st) }

func (s *SingBox) Config(p profile.Profile, st models.Settings) ([]byte, error) {
	cfg, err := singbox.BuildConfig(p, st, s.RuleSetPath)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(cfg, "", "  ")
}

func (*SingBox) ProbeConfig(p profile.Profile, port int) ([]byte, error) {
	cfg, err := singbox.ProbeConfig(p, port)
	if err != nil {
		return nil, err
	}
	return json.Marshal(cfg)
}

func (*SingBox) Check(ctx context.Context, in Install, cfgPath string) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, in.Bin, "check", "-c", cfgPath, "--disable-color")
	cmd.Dir = in.AssetDir
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", TailOf(string(out), err))
	}
	return nil
}

func (*SingBox) Launch(in Install, cfgPath string) Launch {
	// -D keeps any state sing-box writes inside its own install directory.
	return Launch{Binary: in.Bin, Args: []string{"run", "-c", cfgPath, "-D", in.AssetDir, "--disable-color"}}
}

// TailOf returns the last part of a process's output (at most 600 bytes,
// starting at a line boundary), or err when there was no output.
func TailOf(out string, err error) string {
	msg := strings.TrimSpace(out)
	if len(msg) > 600 {
		msg = msg[len(msg)-600:]
		if i := strings.IndexByte(msg, '\n'); i >= 0 {
			msg = msg[i+1:]
		}
	}
	if msg == "" && err != nil {
		msg = err.Error()
	}
	return msg
}
