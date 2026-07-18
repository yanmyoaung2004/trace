package knowledge_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/yanmyoaung2004/innoigniter-ai/internal/db"
	"github.com/yanmyoaung2004/innoigniter-ai/internal/knowledge"
)

func setupKnowledge(t *testing.T) *knowledge.Agent {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	database, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db open: %v", err)
	}
	t.Cleanup(func() { database.Close() })

	mitreDB, err := knowledge.LoadMitreSeed()
	if err != nil {
		t.Fatalf("load mitre: %v", err)
	}

	return knowledge.New(database.DB, mitreDB)
}

func TestMitreLookup(t *testing.T) {
	agent := setupKnowledge(t)
	ctx := context.Background()

	output, err := agent.Execute(ctx, map[string]any{
		"action":    "mitre_lookup",
		"technique": "T1566",
	})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if output["found"] != true {
		t.Fatal("expected found=true")
	}
	if output["name"] != "Phishing" {
		t.Fatalf("expected Phishing, got %v", output["name"])
	}
}

func TestMitreLookupMissing(t *testing.T) {
	agent := setupKnowledge(t)
	ctx := context.Background()

	output, err := agent.Execute(ctx, map[string]any{
		"action":    "mitre_lookup",
		"technique": "T9999",
	})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if output["found"] != false {
		t.Fatal("expected found=false for missing technique")
	}
}

func TestCveLookupBadID(t *testing.T) {
	agent := setupKnowledge(t)
	ctx := context.Background()

	output, err := agent.Execute(ctx, map[string]any{
		"action": "cve_lookup",
		"cve_id": "CVE-9999-99999",
	})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if output["found"] != false {
		t.Fatal("expected not found for bogus CVE")
	}
}

func TestIocEnrichHash(t *testing.T) {
	agent := setupKnowledge(t)
	ctx := context.Background()

	output, err := agent.Execute(ctx, map[string]any{
		"action": "ioc_enrich",
		"ioc":    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
	})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	intel, ok := output["intel"].(map[string]any)
	if !ok {
		t.Fatal("intel not a map")
	}

	if intel["builtin_match"] != true {
		t.Fatal("expected builtin_match for known mimikatz hash")
	}
}

func TestIocEnrichIOC(t *testing.T) {
	agent := setupKnowledge(t)
	ctx := context.Background()

	output, err := agent.Execute(ctx, map[string]any{
		"action": "ioc_enrich",
		"ioc":    "evil.com",
	})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	intel, ok := output["intel"].(map[string]any)
	if !ok {
		t.Fatal("intel not a map")
	}

	if intel["type"] != "domain" {
		t.Fatalf("expected domain, got %v", intel["type"])
	}
}

func TestMalwareLookup(t *testing.T) {
	agent := setupKnowledge(t)
	ctx := context.Background()

	output, err := agent.Execute(ctx, map[string]any{
		"action": "malware_lookup",
		"name":   "mimikatz",
	})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if output["name"] != "mimikatz" {
		t.Fatalf("expected mimikatz, got %v", output["name"])
	}

	mappings, ok := output["mitre_mapping"].([]*knowledge.Technique)
	if !ok || len(mappings) == 0 {
		return
	}
}
