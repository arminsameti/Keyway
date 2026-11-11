package service

import (
	"context"
	"errors"
	"strings"
	"testing"

	"keyway/internal/link"
	"keyway/internal/models"
	"keyway/internal/profile"
)

const credlessOVPNText = `client
dev tun
proto udp
remote v.example 1194
ca ca.crt
auth-user-pass
remote-cert-tls server
<ca>
FAKE-CA
</ca>
`

func TestImportCredentialLessOVPN(t *testing.T) {
	svc := newTestServiceWithSingBox(t)
	res, err := svc.Import(context.Background(), credlessOVPNText, "", Credentials{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Added != 1 {
		t.Fatalf("added = %d errs = %v", res.Added, res.Errors)
	}
	nodes := svc.Nodes()
	if len(nodes) != 1 {
		t.Fatalf("nodes = %d", len(nodes))
	}
	if nodes[0].Warning == "" {
		t.Fatal("expected a needs-credentials warning on the node")
	}
	p := svc.PreviewImport(credlessOVPNText, Credentials{})
	if p.Ready != 1 || p.Skipped != 0 {
		t.Fatalf("preview = %+v", p)
	}
	if !p.Items[0].NeedsCredential {
		t.Fatal("preview should flag needsCredential")
	}
}

func TestImportOVPNWithCredentials(t *testing.T) {
	svc := newTestServiceWithSingBox(t)
	creds := Credentials{Username: "user", Password: "pass"}
	res, err := svc.Import(context.Background(), credlessOVPNText, "", creds)
	if err != nil {
		t.Fatal(err)
	}
	if res.Added != 1 {
		t.Fatalf("added = %d errs = %v", res.Added, res.Errors)
	}
	nodes := svc.Nodes()
	if len(nodes) != 1 {
		t.Fatalf("nodes = %d", len(nodes))
	}
	if nodes[0].Warning != "" {
		t.Fatalf("warning should clear once filled: %q", nodes[0].Warning)
	}
	p := svc.PreviewImport(credlessOVPNText, creds)
	if p.Ready != 1 || p.Items[0].NeedsCredential {
		t.Fatalf("preview should clear needsCredential: %+v", p)
	}
}

func TestImportOVNPartialCredentialsRefused(t *testing.T) {
	svc := newTestService(t)
	creds := Credentials{Username: "user"}
	if _, err := svc.Import(context.Background(), credlessOVPNText, "", creds); err == nil {
		t.Fatal("one-sided credentials should be refused")
	} else if !strings.Contains(err.Error(), "together") {
		t.Fatalf("err = %v", err)
	}
}

func TestPlanRefusesCredentialLess(t *testing.T) {
	svc := newTestService(t)
	res, err := link.ParseOVPN(credlessOVPNText, "Credless")
	if err != nil {
		t.Fatal(err)
	}
	d := svc.store.Get()
	_, err = svc.planFor([]profile.Profile{res.Profile}, []string{"Credless"}, d, "")
	if err == nil {
		t.Fatal("plan should refuse a server without credentials")
	} else if !strings.Contains(err.Error(), "username and password") {
		t.Fatalf("err = %v", err)
	}
	var ve *models.ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("err should be a ValidationError: %v", err)
	}
}

func TestPlanAcceptsFilledCredentials(t *testing.T) {
	svc := newTestServiceWithSingBox(t)
	res, err := link.ParseOVPN(credlessOVPNText, "Credless")
	if err != nil {
		t.Fatal(err)
	}
	p := res.Profile
	p.Username, p.Password = "user", "pass"
	p.OpenVPN.NeedsCredential = false
	d := svc.store.Get()
	_, err = svc.planFor([]profile.Profile{p}, []string{"Credless"}, d, "")
	if err != nil {
		var ve *models.ValidationError
		if errors.As(err, &ve) && strings.Contains(err.Error(), "username and password") {
			t.Fatalf("filled profile wrongly refused for creds: %v", err)
		}
		// Anything else (e.g. engine not installed) is fine: the point is
		// the credential gate passed.
	}
}
