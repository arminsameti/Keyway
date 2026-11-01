package xray

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// ErrInsecureUnsupported means the core refuses allowInsecure, which recent
// Xray releases removed in favour of certificate pinning.
var ErrInsecureUnsupported = errors.New("this Xray core no longer supports insecure TLS (insecure=1 / allowInsecure=1); " +
	"add the server's certificate fingerprint to the link as pinSHA256, or use a node with a valid certificate")

// Test validates a config with "xray -test" so a broken config is rejected
// before it can replace a working connection.
func Test(ctx context.Context, binary, configPath, assetDir string) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "-test", "-c", configPath)
	cmd.Env = append(os.Environ(), "XRAY_LOCATION_ASSET="+assetDir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if strings.Contains(msg, `"allowInsecure" has been removed`) {
			return ErrInsecureUnsupported
		}
		if len(msg) > 600 {
			msg = msg[len(msg)-600:]
			if i := strings.IndexByte(msg, '\n'); i >= 0 {
				msg = msg[i+1:] // don't start mid-line
			}
		}
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("%s", msg)
	}
	return nil
}
