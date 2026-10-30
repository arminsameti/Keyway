package sysproxy

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
)

const listOut = `An asterisk (*) denotes that a network service is disabled.
Wi-Fi
*Thunderbolt Bridge
USB 10/100/1000 LAN
`

const orderOut = `An asterisk (*) denotes that a network service is disabled.
(1) USB 10/100/1000 LAN
(Hardware Port: USB 10/100/1000 LAN, Device: en5)

(2) Wi-Fi
(Hardware Port: Wi-Fi, Device: en0)

(3) *Thunderbolt Bridge
(Hardware Port: Thunderbolt Bridge, Device: bridge0)
`

type fake struct {
	mu    sync.Mutex
	calls [][]string
	fail  string // substring of args that should fail
}

func (f *fake) run(_ context.Context, name string, args ...string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, append([]string{name}, args...))
	joined := strings.Join(args, " ")
	if f.fail != "" && strings.Contains(joined, f.fail) {
		return "boom", errors.New("failed")
	}
	switch {
	case joined == "-listallnetworkservices":
		return listOut, nil
	case joined == "-listnetworkserviceorder":
		return orderOut, nil
	case name == "route":
		return "   route to: default\n  interface: en0\n", nil
	case strings.HasPrefix(joined, "-getsocksfirewallproxy"):
		return "Enabled: Yes\nServer: 127.0.0.1", nil
	case strings.HasPrefix(joined, "-getwebproxy"):
		return "Enabled: No", nil
	}
	return "", nil
}

func TestParseServices(t *testing.T) {
	got := strings.Join(parseServices(listOut), "|")
	if got != "Wi-Fi|USB 10/100/1000 LAN" {
		t.Fatalf("got %q", got)
	}
}

func TestServiceForDevice(t *testing.T) {
	if got := serviceForDevice(orderOut, "en0"); got != "Wi-Fi" {
		t.Fatalf("en0 -> %q", got)
	}
	if got := serviceForDevice(orderOut, "bridge0"); got != "Thunderbolt Bridge" {
		t.Fatalf("bridge0 -> %q", got)
	}
	if serviceForDevice(orderOut, "en9") != "" {
		t.Fatal("unknown device should give empty")
	}
}

func TestPrimary(t *testing.T) {
	m := NewWithRunner("darwin", (&fake{}).run)
	if got := m.Primary(context.Background()); got != "Wi-Fi" {
		t.Fatalf("primary = %q", got)
	}
}

func TestEnableValidatesServiceAndSetsAllKinds(t *testing.T) {
	f := &fake{}
	m := NewWithRunner("darwin", f.run)
	ctx := context.Background()

	for _, bad := range []string{"", "-setsocksfirewallproxy", "Nonexistent", "*Thunderbolt Bridge"} {
		if err := m.Enable(ctx, bad, "127.0.0.1", 1080, 8080); err == nil {
			t.Errorf("service %q must be rejected", bad)
		}
	}
	f.calls = nil
	if err := m.Enable(ctx, "Wi-Fi", "127.0.0.1", 1080, 8080); err != nil {
		t.Fatal(err)
	}
	var cmds []string
	for _, c := range f.calls {
		if len(c) > 1 && strings.HasPrefix(c[1], "-set") {
			cmds = append(cmds, c[1])
		}
	}
	want := "-setsocksfirewallproxy,-setsocksfirewallproxystate,-setwebproxy,-setwebproxystate,-setsecurewebproxy,-setsecurewebproxystate"
	if strings.Join(cmds, ",") != want {
		t.Fatalf("commands: %v", cmds)
	}
}

func TestEnableRollsBackOnFailure(t *testing.T) {
	f := &fake{fail: "-setwebproxy Wi-Fi"}
	m := NewWithRunner("darwin", f.run)
	if err := m.Enable(context.Background(), "Wi-Fi", "127.0.0.1", 1080, 8080); err == nil {
		t.Fatal("expected failure")
	}
	var off int
	for _, c := range f.calls {
		if strings.Join(c[1:], " ") == "-setsocksfirewallproxystate Wi-Fi off" {
			off++
		}
	}
	if off == 0 {
		t.Fatal("half-configured proxy was not rolled back")
	}
}

func TestDisableAndGet(t *testing.T) {
	f := &fake{}
	m := NewWithRunner("darwin", f.run)
	if err := m.Disable(context.Background(), "Wi-Fi"); err != nil {
		t.Fatal(err)
	}
	st := m.Get(context.Background(), "Wi-Fi")
	if !st.Socks || st.Web || !st.On() {
		t.Fatalf("state: %+v", st)
	}
}

func TestUnsupportedPlatform(t *testing.T) {
	m := NewWithRunner("linux", (&fake{}).run)
	if _, err := m.Services(context.Background()); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("err = %v", err)
	}
	if m.Primary(context.Background()) != "" {
		t.Fatal("primary on linux must be empty")
	}
}
