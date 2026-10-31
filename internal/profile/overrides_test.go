package profile

import (
	"strings"
	"testing"
)

func tlsServer() Profile {
	return Profile{Protocol: Trojan, Server: "a.example.com", Port: 443, Password: "p", Security: Security{Kind: "tls", SNI: "a.example.com", Fingerprint: "chrome"}}
}

func TestOverridesApplyTLSFields(t *testing.T) {
	yes := true
	o := &Overrides{Mux: &yes, SNI: "front.example.net", Fingerprint: "firefox", Fragment: &Fragment{}}
	p, err := o.Apply(tlsServer())
	if err != nil {
		t.Fatal(err)
	}
	if p.Security.SNI != "front.example.net" || p.Security.Fingerprint != "firefox" || p.Overrides != o {
		t.Errorf("profile = %+v", p)
	}
	if d := (Fragment{}).Defaults(); d.Packets != "tlshello" || d.Length != "100-200" || d.Interval != "10-20" {
		t.Errorf("defaults = %+v", d)
	}
}

func TestOverridesRefuseWhatCannotWork(t *testing.T) {
	plain := tlsServer()
	plain.Security = Security{Kind: "none"}
	wg := Profile{Protocol: WireGuard, Server: "w.example.com", Port: 51820, Security: Security{Kind: "tls"}}
	for name, c := range map[string]struct {
		o    *Overrides
		p    Profile
		want string
	}{
		"sni on plain":       {&Overrides{SNI: "x.com"}, plain, "TLS"},
		"fingerprint":        {&Overrides{Fingerprint: "netscape"}, tlsServer(), "unknown TLS fingerprint"},
		"fragment on plain":  {&Overrides{Fragment: &Fragment{}}, plain, "TLS"},
		"fragment on udp":    {&Overrides{Fragment: &Fragment{}}, wg, "TCP"},
		"bad fragment range": {&Overrides{Fragment: &Fragment{Length: "big"}}, tlsServer(), "range"},
		"bad mux":            {&Overrides{MuxConcurrency: 5000}, tlsServer(), "mux"},
		"sni with space":     {&Overrides{SNI: "a b"}, tlsServer(), "host name"},
	} {
		if _, err := c.o.Apply(c.p); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", name, err, c.want)
		}
	}
	var none *Overrides
	if p, err := none.Apply(tlsServer()); err != nil || p.Overrides != nil || !none.IsZero() {
		t.Error("nil overrides must change nothing")
	}
}
