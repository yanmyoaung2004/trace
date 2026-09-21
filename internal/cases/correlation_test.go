package cases

import (
	"context"
	"testing"
)

func TestBuildEntityGraph_SingleCase(t *testing.T) {
	m := newTestManager(t)
	ctx := context.Background()

	c, err := m.Create(ctx, "Phish", "desc", "high")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.AddIOC(ctx, c.ID, "ip", "10.0.0.5", "c2"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.AddIOC(ctx, c.ID, "hash", "abc123", "payload"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.AddEvent(ctx, c.ID, "note", "host: web-01 user: jdoe process: mimikatz.exe saw 10.0.0.5", "manual"); err != nil {
		t.Fatal(err)
	}

	g, err := m.BuildEntityGraph(ctx, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[EntityKind]int{}
	for _, n := range g.Nodes {
		kinds[n.Kind]++
	}
	for _, want := range []EntityKind{EntityCase, EntityIP, EntityHash, EntityHost, EntityUser, EntityProcess} {
		if kinds[want] == 0 {
			t.Errorf("missing node kind %q (nodes: %+v)", want, g.Nodes)
		}
	}
	if len(g.Edges) == 0 {
		t.Error("expected contains/co-occurs edges")
	}
	// Host entity must link back to the case via observed-in.
	found := false
	for _, e := range g.Edges {
		if e.Relation == "observed-in" && e.CaseID == c.ID {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected observed-in edge")
	}
}

func TestBuildEntityGraph_CrossCaseSharedInfra(t *testing.T) {
	m := newTestManager(t)
	ctx := context.Background()

	c1, _ := m.Create(ctx, "Case one", "", "high")
	c2, _ := m.Create(ctx, "Case two", "", "medium")
	if _, err := m.AddIOC(ctx, c1.ID, "ip", "10.9.9.9", "shared c2"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.AddIOC(ctx, c2.ID, "ip", "10.9.9.9", "same c2"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.AddIOC(ctx, c2.ID, "domain", "evil.example", "other"); err != nil {
		t.Fatal(err)
	}

	g, err := m.BuildEntityGraph(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	shared := g.SharedEntities(2)
	if len(shared) == 0 {
		t.Fatalf("expected shared entity across cases, got %+v", g.Nodes)
	}
	if shared[0].Kind != EntityIP || shared[0].Value != "10.9.9.9" {
		t.Errorf("top shared = %s:%s, want ip:10.9.9.9", shared[0].Kind, shared[0].Value)
	}
	if len(shared[0].Cases) != 2 {
		t.Errorf("shared cases = %v, want both cases", shared[0].Cases)
	}
	// Single-case entities must not appear in the shared set.
	for _, n := range shared {
		if n.Value == "evil.example" {
			t.Errorf("evil.example seen in 1 case but listed as shared")
		}
	}
}

func TestBuildEntityGraph_UnknownCase(t *testing.T) {
	m := newTestManager(t)
	if _, err := m.BuildEntityGraph(context.Background(), "nope"); err == nil {
		t.Error("expected error for unknown case")
	}
}
