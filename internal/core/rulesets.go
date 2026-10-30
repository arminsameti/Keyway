package core

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const maxRuleSetSize = 32 << 20

// ruleSetRe validates rule-set names such as "geosite-cn", "geosite-google@cn",
// "geosite-geolocation-!cn" or "geoip-ir". No path separators are possible.
var ruleSetRe = regexp.MustCompile(`^(geosite|geoip)-[a-z0-9][a-z0-9._@!-]{0,63}$`)

// ValidRuleSet reports whether name is a well-formed rule-set name.
func ValidRuleSet(name string) bool { return ruleSetRe.MatchString(name) }

// RuleSetDir is where downloaded sing-box rule sets live.
func (m *Manager) RuleSetDir() string { return filepath.Join(m.dir, "rules") }

// RuleSetPath is the local file of a rule set (it may not exist yet).
func (m *Manager) RuleSetPath(name string) string { return filepath.Join(m.RuleSetDir(), name+".srs") }

// EnsureRuleSets downloads the named sing-box rule sets that are not present
// yet, from SagerNet's official "rule-set" branches. Each file is verified
// against the git blob SHA-1 that GitHub's contents API reports for it, the
// same trust root as the engine download itself.
func (m *Manager) EnsureRuleSets(ctx context.Context, names []string) error {
	if err := os.MkdirAll(m.RuleSetDir(), 0o700); err != nil {
		return err
	}
	for _, name := range names {
		if !ValidRuleSet(name) {
			return fmt.Errorf("invalid rule set name %q", name)
		}
		if _, err := os.Stat(m.RuleSetPath(name)); err == nil {
			continue
		}
		if err := m.fetchRuleSet(ctx, name); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) fetchRuleSet(ctx context.Context, name string) error {
	repo := "SagerNet/sing-geosite"
	if strings.HasPrefix(name, "geoip-") {
		repo = "SagerNet/sing-geoip"
	}
	label := strings.Replace(name, "-", ":", 1) // geosite-cn -> geosite:cn, for messages
	b, err := m.get(ctx, fmt.Sprintf("%s/repos/%s/contents/%s.srs?ref=rule-set", m.apiBase, repo, name), "application/vnd.github+json", maxAPIBody)
	if err != nil {
		if strings.Contains(err.Error(), "404") {
			return fmt.Errorf("%s does not exist as a sing-box rule set", label)
		}
		return fmt.Errorf("look up rule set %s: %w", label, err)
	}
	var meta struct {
		Type        string `json:"type"`
		SHA         string `json:"sha"`
		Size        int64  `json:"size"`
		DownloadURL string `json:"download_url"`
	}
	if err := json.Unmarshal(b, &meta); err != nil {
		return fmt.Errorf("decode rule set %s: %w", label, err)
	}
	if meta.Type != "file" || len(meta.SHA) != 40 || meta.Size <= 0 || meta.Size > maxRuleSetSize || meta.DownloadURL == "" {
		return fmt.Errorf("rule set %s: unexpected metadata; refusing unverified download", label)
	}
	data, err := m.get(ctx, meta.DownloadURL, "", maxRuleSetSize)
	if err != nil {
		return fmt.Errorf("download rule set %s: %w", label, err)
	}
	h := sha1.New() // git's blob hash: sha1("blob <size>\x00" + content)
	fmt.Fprintf(h, "blob %d\x00", len(data))
	h.Write(data)
	if got := hex.EncodeToString(h.Sum(nil)); got != strings.ToLower(meta.SHA) {
		return fmt.Errorf("rule set %s: checksum mismatch", label)
	}
	tmp, err := os.CreateTemp(m.RuleSetDir(), ".rs-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	_ = os.Chmod(tmp.Name(), 0o644)
	if err := os.Rename(tmp.Name(), m.RuleSetPath(name)); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return nil
}
