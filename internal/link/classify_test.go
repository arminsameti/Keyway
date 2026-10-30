package link

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestClassifyMixedText(t *testing.T) {
	text := strings.Join([]string{
		"vless://u@fra1.example.net:443?security=reality&pbk=K&sni=www.example.com#Frankfurt%2001",
		"trojan://p@hel.example.net:443?sni=hel.example.net#Helsinki",
		"",
		"https://sub.example.net/api/v1/client/TOKEN",
		"ssr://bG9uZy1sZWdhY3ktbGluay4uLg",
		"just some words",
		"trojan://p@hel.example.net:443?sni=hel.example.net#Helsinki%20again",
	}, "\n")
	items := Classify(text)
	got := []string{}
	for _, it := range items {
		got = append(got, it.Kind)
	}
	want := "ready ready subscription skipped skipped skipped"
	if strings.Join(got, " ") != want {
		t.Fatalf("kinds = %v, want %s", got, want)
	}
	if items[3].Reason != "ShadowsocksR is retired — skipped" || items[3].Line != 5 || items[3].Scheme != "ssr" {
		t.Errorf("ssr: %+v", items[3])
	}
	if items[5].Reason != "Same server as line 2" {
		t.Errorf("duplicate: %+v", items[5])
	}
	for _, it := range items {
		if strings.Contains(it.Reason, "://") {
			t.Errorf("reason must not echo the link: %q", it.Reason)
		}
	}
}

func TestClassifyBase64Blob(t *testing.T) {
	blob := base64.StdEncoding.EncodeToString([]byte("trojan://p@a.com:443#A\nvless://u@b.com:443?security=tls#B\n"))
	items := Classify(blob)
	if len(items) != 2 || items[0].Kind != KindReady || items[1].Result.Node.Name != "B" {
		t.Fatalf("%+v", items)
	}
}

func TestClassifyKeepsUnencodedSpacesInNames(t *testing.T) {
	items := Classify("trojan://p@a.com:443#Frankfurt 01 fast, vless://u@b.com:443?security=tls#B two")
	if len(items) != 2 || items[0].Result.Node.Name != "Frankfurt 01 fast" || items[1].Result.Node.Name != "B two" {
		t.Fatalf("%+v", items)
	}
}
