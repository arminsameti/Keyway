package tor

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"keyway/internal/profile"
)

// Timeouts for Tor to build its first circuit: bridges add a hop to every step.
const (
	BootstrapTimeout       = 60 * time.Second
	BootstrapTimeoutBridge = 120 * time.Second
)

var (
	progressRe = regexp.MustCompile(`PROGRESS=(\d+)`)
	summaryRe  = regexp.MustCompile(`SUMMARY="([^"]*)"`)
)

// control is one authenticated control-port connection.
type control struct {
	c net.Conn
	r *bufio.Reader
}

func dialControl(ctx context.Context, rt *profile.Runtime) (*control, error) {
	cookie, err := os.ReadFile(filepath.Join(rt.Dir, "control_auth_cookie"))
	if err != nil {
		return nil, err
	}
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(rt.ControlPort)))
	if err != nil {
		return nil, err
	}
	ct := &control{c: c, r: bufio.NewReader(c)}
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := fmt.Fprintf(c, "AUTHENTICATE %s\r\n", hex.EncodeToString(cookie)); err != nil {
		c.Close()
		return nil, err
	}
	if l, err := ct.r.ReadString('\n'); err != nil || !strings.HasPrefix(l, "250") {
		c.Close()
		return nil, fmt.Errorf("control authentication failed")
	}
	return ct, nil
}

// phase asks for the current bootstrap progress.
func (ct *control) phase() (int, string, error) {
	_ = ct.c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := fmt.Fprintf(ct.c, "GETINFO status/bootstrap-phase\r\n"); err != nil {
		return 0, "", err
	}
	l, err := ct.r.ReadString('\n')
	if err != nil {
		return 0, "", err
	}
	if _, err := ct.r.ReadString('\n'); err != nil { // the "250 OK" that ends the reply
		return 0, "", err
	}
	m := progressRe.FindStringSubmatch(l)
	if m == nil {
		return 0, "", fmt.Errorf("unexpected control reply")
	}
	pct, _ := strconv.Atoi(m[1])
	sum := ""
	if s := summaryRe.FindStringSubmatch(l); s != nil {
		sum = s[1]
	}
	return pct, sum, nil
}

// WaitReady blocks until Tor reports 100% bootstrap on its control port.
func WaitReady(ctx context.Context, seg profile.Segment, progress func(int, string)) error {
	if seg.Runtime == nil {
		return fmt.Errorf("internal error: Tor has no control port")
	}
	limit := BootstrapTimeout
	if len(seg.Hops) == 1 && seg.Hops[0].Tor != nil && seg.Hops[0].Tor.Bridges != profile.TorBridgeNone {
		limit = BootstrapTimeoutBridge
	}
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	last := "starting"
	var ct *control
	defer func() {
		if ct != nil {
			ct.c.Close()
		}
	}()
	for {
		if ct == nil {
			ct, _ = dialControl(ctx, seg.Runtime)
		}
		if ct != nil {
			pct, sum, err := ct.phase()
			if err != nil {
				ct.c.Close()
				ct = nil
			} else {
				last = sum
				if progress != nil {
					progress(pct, sum)
				}
				if pct >= 100 {
					return nil
				}
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("Tor did not finish connecting (%s)", last)
		case <-time.After(500 * time.Millisecond):
		}
	}
}
