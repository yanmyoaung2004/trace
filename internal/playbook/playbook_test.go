package playbook_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/innoigniter/edge/internal/playbook"
)

func TestLoadFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.yaml")
	content := `name: hash-lookup
description: Check a file hash
triggers:
  - hash
  - sha256
steps:
  - agent: detection
    action: hash_lookup
    params:
      hash: ${input.hash}
  - agent: host
    action: synthesize_report
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	e := playbook.New()
	if err := e.LoadDir(dir); err != nil {
		t.Fatalf("LoadDir failed: %v", err)
	}

	pb := e.Get("hash-lookup")
	if pb == nil {
		t.Fatal("playbook not found")
	}
	if pb.Description != "Check a file hash" {
		t.Fatalf("unexpected description: %s", pb.Description)
	}
	if len(pb.Steps) != 2 {
		t.Fatalf("expected 2 steps, got %d", len(pb.Steps))
	}
	if pb.Steps[0].Agent != "detection" {
		t.Fatalf("expected agent detection, got %s", pb.Steps[0].Agent)
	}
}

func TestLoadDirMissing(t *testing.T) {
	e := playbook.New()
	err := e.LoadDir("/nonexistent/path")
	if err != nil {
		t.Fatalf("LoadDir on missing dir should not error: %v", err)
	}
}

func TestList(t *testing.T) {
	dir := t.TempDir()

	p1 := "name: pb1\ntriggers: []\nsteps: []\n"
	p2 := "name: pb2\ntriggers: []\nsteps: []\n"
	os.WriteFile(filepath.Join(dir, "pb1.yaml"), []byte(p1), 0644)
	os.WriteFile(filepath.Join(dir, "pb2.yaml"), []byte(p2), 0644)

	e := playbook.New()
	e.LoadDir(dir)

	if len(e.List()) != 2 {
		t.Fatalf("expected 2 playbooks, got %d", len(e.List()))
	}
}

func TestSkipNonYaml(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("hello"), 0644)

	e := playbook.New()
	if err := e.LoadDir(dir); err != nil {
		t.Fatalf("LoadDir failed: %v", err)
	}
}

func TestBadYaml(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "bad.yaml"), []byte("{{invalid"), 0644)

	e := playbook.New()
	err := e.LoadDir(dir)
	if err == nil {
		t.Fatal("expected error for bad YAML")
	}
}
