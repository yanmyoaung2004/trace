package locale

import (
	"testing"
)

func TestDefaultLocale(t *testing.T) {
	l := Get()
	if l.Code != "en" {
		t.Errorf("expected en, got %s", l.Code)
	}
}

func TestTExisting(t *testing.T) {
	v := T("dashboard_title")
	if v == "" || v == "dashboard_title" {
		t.Errorf("expected translation, got %q", v)
	}
}

func TestTMissing(t *testing.T) {
	v := T("nonexistent_key_xyz")
	if v != "nonexistent_key_xyz" {
		t.Errorf("expected key fallback, got %q", v)
	}
}

func TestSetMyanmar(t *testing.T) {
	Set("my")
	if Get().Code != "my" {
		t.Errorf("expected my, got %s", Get().Code)
	}
	v := T("dashboard_title")
	if v == "" {
		t.Errorf("expected my translation, got empty")
	}
	Set("en")
}

func TestInvalidCode(t *testing.T) {
	Set("fr")
	if Get().Code != "en" {
		t.Errorf("expected en fallback, got %s", Get().Code)
	}
}

func TestDetect(t *testing.T) {
	if d := Detect(); d != "en" {
		t.Errorf("expected en in test env, got %s", d)
	}
}
