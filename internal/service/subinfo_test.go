package service

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const vlessA = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@a.example.com:443?security=tls&sni=a.example.com&type=tcp#Alpha"
const vlessB = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@b.example.com:443?security=tls&sni=b.example.com&type=tcp#Beta"

func TestParseUserinfo(t *testing.T) {
	u, ok := parseUserinfo("upload=455727941; download=6174315083; total=1073741824000; expire=1671815872")
	if !ok {
		t.Fatal("not parsed")
	}
	if u.Upload != 455727941 || u.Download != 6174315083 || u.Total != 1073741824000 {
		t.Fatalf("usage = %+v", u)
	}
	if u.Expire == nil || !u.Expire.Equal(time.Unix(1671815872, 0).UTC()) {
		t.Fatalf("expire = %v", u.Expire)
	}
}

func TestParseUserinfoTolerance(t *testing.T) {
	// unlimited plans report expire=0 or leave it out; keys vary in case and spacing
	u, ok := parseUserinfo("Upload=1;DOWNLOAD=2 ; total=0;expire=0")
	if !ok || u.Upload != 1 || u.Download != 2 || u.Total != 0 || u.Expire != nil {
		t.Fatalf("got %+v ok=%v", u, ok)
	}
	if u, ok := parseUserinfo("download=5"); !ok || u.Download != 5 {
		t.Fatalf("partial header: %+v ok=%v", u, ok)
	}
	for _, bad := range []string{"", "   ", "garbage", "upload=abc; download=x", "upload=-5; download=-1; total=-2"} {
		if _, ok := parseUserinfo(bad); ok {
			t.Errorf("%q should not parse", bad)
		}
	}
}

func TestParseProfileTitle(t *testing.T) {
	cases := map[string]string{
		"My Provider":             "My Provider",
		"base64:TXkgUHJvdmlkZXI=": "My Provider",
		"My%20Provider":           "My Provider",
		"  padded \t":             "padded",
		"":                        "",
		"base64:!!!notbase64":     "",
		"line\r\nbreak":           "linebreak",
		strings.Repeat("x", 300):  strings.Repeat("x", 80),
	}
	for in, want := range cases {
		if got := parseProfileTitle(in); got != want {
			t.Errorf("parseProfileTitle(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseUpdateInterval(t *testing.T) {
	cases := map[string]int{"12": 12, " 24 ": 24, "": 0, "abc": 0, "-3": 0, "0": 0, "100000": 720}
	for in, want := range cases {
		if got := parseUpdateInterval(in); got != want {
			t.Errorf("parseUpdateInterval(%q) = %d, want %d", in, got, want)
		}
	}
}

func subServer(t *testing.T, hdr map[string]string, body *string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for k, v := range hdr {
			w.Header().Set(k, v)
		}
		_, _ = w.Write([]byte(*body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestRefreshStoresSubscriptionDetails(t *testing.T) {
	body := vlessA + "\n" + vlessB + "\n"
	srv := subServer(t, map[string]string{
		"Subscription-Userinfo":   "upload=100; download=200; total=1000; expire=1893456000",
		"Profile-Title":           "base64:TXkgUHJvdmlkZXI=",
		"Profile-Update-Interval": "6",
	}, &body)
	svc := newTestService(t)

	sub, added, _, err := svc.AddSubscription(t.Context(), "", srv.URL)
	if err != nil || added != 2 {
		t.Fatalf("added=%d err=%v", added, err)
	}
	if sub.Name != "My Provider" {
		t.Errorf("a subscription added without a name adopts the provider title, got %q", sub.Name)
	}
	if sub.Title != "My Provider" || sub.UpdateHours != 6 {
		t.Errorf("title=%q updateHours=%d", sub.Title, sub.UpdateHours)
	}
	if sub.Usage == nil || sub.Usage.Upload != 100 || sub.Usage.Download != 200 || sub.Usage.Total != 1000 ||
		sub.Usage.Expire == nil || sub.Usage.Expire.Unix() != 1893456000 {
		t.Errorf("usage = %+v", sub.Usage)
	}
}

func TestAddSubscriptionKeepsGivenName(t *testing.T) {
	body := vlessA
	srv := subServer(t, map[string]string{"Profile-Title": "Provider"}, &body)
	svc := newTestService(t)
	sub, _, _, err := svc.AddSubscription(t.Context(), "Mine", srv.URL)
	if err != nil || sub.Name != "Mine" || sub.Title != "Provider" {
		t.Fatalf("sub=%+v err=%v", sub, err)
	}
}

func TestRefreshClearsDetailsTheProviderStopsSending(t *testing.T) {
	body := vlessA
	hdr := map[string]string{"Subscription-Userinfo": "upload=1; download=2; total=3", "Profile-Update-Interval": "6"}
	srv := subServer(t, hdr, &body)
	svc := newTestService(t)
	sub, _, _, err := svc.AddSubscription(t.Context(), "n", srv.URL)
	if err != nil || sub.Usage == nil {
		t.Fatalf("sub=%+v err=%v", sub, err)
	}
	delete(hdr, "Subscription-Userinfo")
	delete(hdr, "Profile-Update-Interval")
	if _, _, _, err := svc.RefreshSubscription(t.Context(), sub.ID); err != nil {
		t.Fatal(err)
	}
	got, _ := svc.findSub(sub.ID)
	if got.Usage != nil || got.UpdateHours != 0 {
		t.Errorf("stale details kept: usage=%+v hours=%d", got.Usage, got.UpdateHours)
	}
}

func TestFailedRefreshKeepsDetails(t *testing.T) {
	body := vlessA
	srv := subServer(t, map[string]string{"Subscription-Userinfo": "upload=1; download=2; total=3"}, &body)
	svc := newTestService(t)
	sub, _, _, err := svc.AddSubscription(t.Context(), "n", srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	body = "<html>nope</html>"
	if _, _, _, err := svc.RefreshSubscription(t.Context(), sub.ID); err == nil {
		t.Fatal("expected an error")
	}
	got, _ := svc.findSub(sub.ID)
	if got.Usage == nil || got.Usage.Total != 3 {
		t.Errorf("a failed refresh must not wipe the last known usage: %+v", got.Usage)
	}
}

func TestSubscriptionDue(t *testing.T) {
	now := time.Now()
	hoursAgo := func(h int) time.Time { return now.Add(-time.Duration(h) * time.Hour) }
	cases := []struct {
		name        string
		setting     int
		updateHours int
		updatedAgo  int
		want        bool
	}{
		{"auto-update off wins over the provider", 0, 1, 100, false},
		{"global interval, not yet", 24, 0, 5, false},
		{"global interval, due", 24, 0, 25, true},
		{"provider interval shorter, due", 24, 6, 7, true},
		{"provider interval longer, not due", 24, 72, 30, false},
	}
	for _, c := range cases {
		if got := subscriptionDue(c.setting, c.updateHours, hoursAgo(c.updatedAgo)); got != c.want {
			t.Errorf("%s: got %v", c.name, got)
		}
	}
}
