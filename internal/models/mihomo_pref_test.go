package models

import "testing"

func TestMihomoPreferenceValid(t *testing.T) {
	s := DefaultSettings()
	if s.EnginePreference != "xray" {
		t.Fatalf("the default preference is %q: Mihomo must stay opt-in", s.EnginePreference)
	}
	s.EnginePreference = "mihomo"
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	s.EnginePreference = "clash"
	if err := s.Validate(); err == nil {
		t.Fatal("want an error")
	}
}
