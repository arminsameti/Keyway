package engine

import (
	"bufio"
	"context"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeSOCKS refuses the first `refuse` connections the way an OpenVPN endpoint
// does before its tunnel is up (instantly), then answers every request with 204.
func fakeSOCKS(t *testing.T, refuse int32) (addr string, calls *atomic.Int32) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	calls = new(atomic.Int32)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				n := calls.Add(1)
				r := bufio.NewReader(c)
				hello := make([]byte, 3)
				if _, err := r.Read(hello); err != nil {
					return
				}
				c.Write([]byte{5, 0})
				req := make([]byte, 262)
				if _, err := r.Read(req); err != nil {
					return
				}
				if n <= refuse {
					c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0}) // connection refused
					return
				}
				c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
				for {
					line, err := r.ReadString('\n')
					if err != nil || strings.TrimSpace(line) == "" {
						break
					}
				}
				c.Write([]byte("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"))
			}(c)
		}
	}()
	return l.Addr().String(), calls
}

func TestWaitUsableRetriesUntilTunnelIsUp(t *testing.T) {
	addr, calls := fakeSOCKS(t, 3)
	if err := WaitUsable(context.Background(), addr, 10*time.Second); err != nil {
		t.Fatalf("WaitUsable: %v (after %d attempts)", err, calls.Load())
	}
	if calls.Load() < 4 {
		t.Fatalf("expected a retry after each refusal, got %d attempts", calls.Load())
	}
}

func TestWaitUsableGivesUp(t *testing.T) {
	addr, _ := fakeSOCKS(t, 1<<30)
	start := time.Now()
	if err := WaitUsable(context.Background(), addr, 1500*time.Millisecond); err == nil {
		t.Fatal("expected an error when the tunnel never comes up")
	}
	if d := time.Since(start); d > 4*time.Second {
		t.Fatalf("took %s, should stop near the timeout", d)
	}
}
