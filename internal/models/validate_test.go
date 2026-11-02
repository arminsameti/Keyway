package models

import "testing"

func TestV2RayPreferenceValid(t *testing.T) {
	s := DefaultSettings()
	s.EnginePreference = "v2ray"
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	s.EnginePreference = "v3ray"
	if err := s.Validate(); err == nil {
		t.Fatal("want an error")
	}
}
