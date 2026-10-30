package profile

import (
	"strings"
	"testing"
)

const xrayOut = `{"tag":"main","protocol":"vless","settings":{"vnext":[{"address":"a.example.com","port":443,"users":[{"id":"u","encryption":"none"}]}]},
  "streamSettings":{"network":"tcp","sockopt":{"dialerProxy":"hop"}}}`

func TestParseCustomAcceptsOutboundListAndFullConfig(t *testing.T) {
	for name, text := range map[string]string{
		"single":      xrayOut,
		"list":        `[` + xrayOut + `]`,
		"full config": `{"log":{"loglevel":"debug"},"inbounds":[{"port":1}],"outbounds":[` + xrayOut + `]}`,
	} {
		parts, err := ParseCustom(&CustomOpts{Engine: "xray", Config: text})
		if err != nil || len(parts.Outbounds) != 1 || parts.Outbounds[0]["tag"] != "proxy" {
			t.Errorf("%s: %+v %v", name, parts, err)
		}
	}
	host, port := CustomEndpoint(&CustomOpts{Engine: "xray", Config: xrayOut})
	if host != "a.example.com" || port != 443 {
		t.Errorf("endpoint = %s:%d", host, port)
	}
	h, p := CustomEndpoint(&CustomOpts{Engine: "sing-box", Config: `{"type":"trojan","server":"t.example.com","server_port":8443,"password":"x"}`})
	if h != "t.example.com" || p != 8443 {
		t.Errorf("sing-box endpoint = %s:%d", h, p)
	}
}

func TestParseCustomRenamesTheExitAndItsReferences(t *testing.T) {
	text := `[{"tag":"front","protocol":"vmess","settings":{}},
	          {"tag":"hop","protocol":"freedom","streamSettings":{"sockopt":{"dialerProxy":"front"}}}]`
	parts, err := ParseCustom(&CustomOpts{Engine: "xray", Config: text})
	if err != nil {
		t.Fatal(err)
	}
	ss := parts.Outbounds[1]["streamSettings"].(map[string]any)["sockopt"].(map[string]any)
	if parts.Outbounds[0]["tag"] != "proxy" || ss["dialerProxy"] != "proxy" {
		t.Errorf("exit tag and references must follow the rename: %+v", parts.Outbounds)
	}
}

func TestParseCustomRefusals(t *testing.T) {
	for name, c := range map[string]struct {
		o    CustomOpts
		want string
	}{
		"no engine":      {CustomOpts{Config: xrayOut}, "choose Xray or sing-box"},
		"empty":          {CustomOpts{Engine: "xray"}, "paste"},
		"not json":       {CustomOpts{Engine: "xray", Config: "{nope"}, "not valid JSON"},
		"two documents":  {CustomOpts{Engine: "xray", Config: `{"protocol":"x"} {"protocol":"y"}`}, "more than one"},
		"no outbounds":   {CustomOpts{Engine: "xray", Config: `{"log":{}}`}, "no outbounds"},
		"reserved tag":   {CustomOpts{Engine: "xray", Config: `[{"tag":"direct","protocol":"freedom"}]`}, "used by the app"},
		"proxy conflict": {CustomOpts{Engine: "xray", Config: `[{"tag":"a","protocol":"vless"},{"tag":"proxy","protocol":"freedom"}]`}, "rename the other"},
		"wrong kind":     {CustomOpts{Engine: "sing-box", Config: `[{"protocol":"vless"}]`}, "\"type\" field"},
		"too big":        {CustomOpts{Engine: "xray", Config: `[{"protocol":"` + strings.Repeat("x", MaxCustomBytes) + `"}]`}, "larger than"},
	} {
		if _, err := ParseCustom(&c.o); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", name, err, c.want)
		}
	}
	custom := Profile{Protocol: Custom, Custom: &CustomOpts{Engine: "xray", Config: xrayOut}}
	if err := CheckChain([]Profile{custom, custom}, nil); err == nil || !strings.Contains(err.Error(), "cannot be part of a chain") {
		t.Errorf("custom in a chain: %v", err)
	}
	if custom.Validate() != nil || custom.DisplayTransport() != "Custom" || ProtocolName(Custom) != "Custom" {
		t.Error("custom profile display / validation")
	}
}
