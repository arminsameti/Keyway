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

// Documents saved before the app-update check existed have no value for it.
func TestAppUpdateCheckDefaultsToDaily(t *testing.T) {
	if DefaultSettings().AppUpdateCheck != "daily" {
		t.Fatal("default should be daily")
	}
	s := DefaultSettings()
	s.AppUpdateCheck = ""
	s.Normalize()
	if s.AppUpdateCheck != "daily" {
		t.Fatalf("got %q", s.AppUpdateCheck)
	}
	s.AppUpdateCheck = "never"
	s.Normalize()
	if err := s.Validate(); err != nil || s.AppUpdateCheck != "never" {
		t.Fatalf("never must stay valid: %v", err)
	}
	s.AppUpdateCheck = "weekly"
	if err := s.Validate(); err == nil {
		t.Fatal("want an error: only daily and never exist")
	}
}
