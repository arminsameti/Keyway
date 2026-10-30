package models

import (
	"errors"
	"testing"
)

func TestDefaultsAreValid(t *testing.T) {
	if err := DefaultSettings().Validate(); err != nil {
		t.Fatalf("defaults must validate: %v", err)
	}
}

func TestValidateRejects(t *testing.T) {
	mut := func(f func(*Settings)) Settings { s := DefaultSettings(); f(&s); return s }
	cases := map[string]Settings{
		"bad routing": mut(func(s *Settings) { s.RoutingMode = "weird" }),
		"dup port":    mut(func(s *Settings) { s.Inbounds[1].Port = s.Inbounds[0].Port }),
		"dup tag":     mut(func(s *Settings) { s.Inbounds[1].Tag = s.Inbounds[0].Tag }),
		"port range":  mut(func(s *Settings) { s.Inbounds[0].Port = 70000 }),
		"api clash":   mut(func(s *Settings) { s.Inbounds[0].Port = s.APIPort }),
		"no inbound":  mut(func(s *Settings) { s.Inbounds = nil }),
		"all disabled": mut(func(s *Settings) {
			for i := range s.Inbounds {
				s.Inbounds[i].Enabled = false
			}
		}),
		"lan no creds":   mut(func(s *Settings) { s.AllowLAN = true }),
		"lan listen":     mut(func(s *Settings) { s.Inbounds[0].Listen = "0.0.0.0" }),
		"half creds":     mut(func(s *Settings) { s.Inbounds[0].Username = "u" }),
		"engine pref":    mut(func(s *Settings) { s.EnginePreference = "v2ray" }),
		"update check":   mut(func(s *Settings) { s.EngineUpdateCheck = "hourly" }),
		"latency method": mut(func(s *Settings) { s.LatencyMethod = "icmp" }),
		"bad tag":        mut(func(s *Settings) { s.Inbounds[0].Tag = "a b" }),
		"bad proto":      mut(func(s *Settings) { s.Inbounds[0].Protocol = "ftp" }),
		"mux range":      mut(func(s *Settings) { s.MuxConcurrency = 5000 }),
		"bad log":        mut(func(s *Settings) { s.LogLevel = "loud" }),
		"dns whitespace": mut(func(s *Settings) { s.DNS = []string{"1.1.1.1 8.8.8.8"} }),
	}
	for name, s := range cases {
		err := s.Validate()
		var ve *ValidationError
		if err == nil || !errors.As(err, &ve) {
			t.Errorf("%s: expected ValidationError, got %v", name, err)
		}
	}
}

func TestLANAllowedWithCredentials(t *testing.T) {
	s := DefaultSettings()
	s.AllowLAN = true
	for i := range s.Inbounds {
		s.Inbounds[i].Username, s.Inbounds[i].Password = "u", "p"
	}
	if err := s.Validate(); err != nil {
		t.Fatalf("LAN with credentials should be valid: %v", err)
	}
	if got := s.EffectiveListen(s.Inbounds[0]); got != "0.0.0.0" {
		t.Fatalf("effective listen = %s", got)
	}
}

func TestCloneIsDeep(t *testing.T) {
	d := DefaultAppData()
	d.Nodes = append(d.Nodes, Node{ID: "a"})
	c := d.Clone()
	c.Nodes[0].ID = "changed"
	c.Settings.Inbounds[0].Port = 1
	c.Settings.DNS[0] = "x"
	if d.Nodes[0].ID != "a" || d.Settings.Inbounds[0].Port == 1 || d.Settings.DNS[0] == "x" {
		t.Fatal("Clone aliases original data")
	}
}
