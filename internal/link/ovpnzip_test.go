package link

import (
	"archive/zip"
	"bytes"
	"testing"
)

func makeZip(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, content := range files {
		fw, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

const testOVPNExternal = `client
dev tun
proto udp
remote v.example 1194
ca ca.crt
cert client.crt
key client.key
tls-auth ta.key 1
remote-cert-tls server
`

func TestParseOVPNZipResolvesExternalFiles(t *testing.T) {
	data := makeZip(t, map[string]string{
		"client.ovpn": testOVPNExternal,
		"ca.crt":      "FAKE-CA",
		"client.crt":  "FAKE-CERT",
		"client.key":  "FAKE-KEY",
		"ta.key":      "FAKE-TA",
	})
	items, err := ParseOVPNZip(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("items = %d", len(items))
	}
	if items[0].Kind != KindReady {
		t.Fatalf("kind = %s reason = %s", items[0].Kind, items[0].Reason)
	}
	p := items[0].Result.Profile
	if p.OpenVPN.CA != "FAKE-CA" || p.OpenVPN.Cert != "FAKE-CERT" || p.OpenVPN.Key != "FAKE-KEY" {
		t.Fatalf("certs not resolved: %+v", p.OpenVPN)
	}
	if p.OpenVPN.ControlWrap == nil || p.OpenVPN.ControlWrap.Key != "FAKE-TA" {
		t.Fatalf("tls-auth not resolved: %+v", p.OpenVPN.ControlWrap)
	}
}

func TestParseOVPNZipMissingFileSkips(t *testing.T) {
	data := makeZip(t, map[string]string{
		"client.ovpn": testOVPNExternal,
		"ca.crt":      "FAKE-CA",
	})
	items, err := ParseOVPNZip(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Kind != KindSkipped {
		t.Fatalf("expected skipped, got %+v", items)
	}
}

func TestParseOVPNZipNoOVPN(t *testing.T) {
	data := makeZip(t, map[string]string{"readme.txt": "hello"})
	if _, err := ParseOVPNZip(data); err == nil {
		t.Fatal("expected error for zip without .ovpn")
	}
}

func TestParseOVPNZipEmbeddedStillWorks(t *testing.T) {
	ovpn := "client\ndev tun\nremote v.example 1194\nremote-cert-tls server\n<ca>\nEMBEDDED-CA\n</ca>\n<cert>\nEMBEDDED-CERT\n</cert>\n<key>\nEMBEDDED-KEY\n</key>\n"
	data := makeZip(t, map[string]string{"a.ovpn": ovpn})
	items, err := ParseOVPNZip(data)
	if err != nil {
		t.Fatal(err)
	}
	if items[0].Kind != KindReady {
		t.Fatalf("kind = %s reason = %s", items[0].Kind, items[0].Reason)
	}
}

func TestParseOVPNZipSubdirRefs(t *testing.T) {
	ovpn := "client\ndev tun\nremote v.example 1194\nremote-cert-tls server\nca certs/ca.crt\ncert certs/client.crt\nkey certs/client.key\n"
	data := makeZip(t, map[string]string{
		"vpn/client.ovpn":  ovpn,
		"vpn/certs/ca.crt": "SUB-CA",
		"certs/client.crt": "SUB-CERT",
		"other/client.key": "SUB-KEY",
		"vpn/ignore.txt":   "x",
		"__MACOSX/._junk":  "x",
		"vpn/.DS_Store":    "x",
	})
	items, err := ParseOVPNZip(data)
	if err != nil {
		t.Fatal(err)
	}
	if items[0].Kind != KindReady {
		t.Fatalf("kind = %s reason = %s", items[0].Kind, items[0].Reason)
	}
	if items[0].Result.Profile.OpenVPN.CA != "SUB-CA" {
		t.Fatalf("subdir ca not resolved")
	}
}
