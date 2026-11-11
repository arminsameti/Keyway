package profile

import "testing"

func credlessOVPN() Profile {
	return Profile{
		Protocol:  OpenVPN,
		Server:    "v.example",
		Port:      1194,
		Transport: Transport{Type: "udp"},
		OpenVPN:   &OpenVPNOpts{CA: "FAKE-CA", NeedsCredential: true},
	}
}

func TestCredentialLessOVPNValidates(t *testing.T) {
	p := credlessOVPN()
	if err := p.Validate(); err != nil {
		t.Fatalf("credential-less profile should store: %v", err)
	}
	if !p.NeedsCredentials() {
		t.Fatal("NeedsCredentials should be true")
	}
}

func TestCredentialFilledOVPNValidates(t *testing.T) {
	p := credlessOVPN()
	p.Username, p.Password = "user", "pass"
	if err := p.Validate(); err != nil {
		t.Fatalf("filled profile should validate: %v", err)
	}
	if p.NeedsCredentials() {
		t.Fatal("NeedsCredentials should be false once filled")
	}
}

func TestPartialCredentialsStillRefused(t *testing.T) {
	p := credlessOVPN()
	p.Username = "user"
	if err := p.Validate(); err == nil {
		t.Fatal("username without password should be refused")
	}
}

func TestMissingCAStillRefused(t *testing.T) {
	p := credlessOVPN()
	p.OpenVPN.CA = ""
	if err := p.Validate(); err == nil {
		t.Fatal("missing CA should still be refused")
	}
}

func TestNoCredsNoCertStillRefused(t *testing.T) {
	p := credlessOVPN()
	p.OpenVPN.NeedsCredential = false
	if err := p.Validate(); err == nil {
		t.Fatal("no cert and no credentials should still be refused")
	}
}
