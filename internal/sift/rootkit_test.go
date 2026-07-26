package sift

import (
	"context"
	"testing"

	"github.com/yanmyoaung2004/trace/internal/agent"
)

func TestRootkitScanner_Name(t *testing.T) {
	s := NewRootkitScanner()
	if s.Name() != "rootkit" {
		t.Errorf("name = %q", s.Name())
	}
}

func TestRootkitScanner_Capabilities(t *testing.T) {
	s := NewRootkitScanner()
	caps := s.Capabilities()
	if len(caps) == 0 {
		t.Fatal("expected capabilities")
	}
}

func TestRootkitScanner_BehaviorScan(t *testing.T) {
	s := NewRootkitScanner()
	out, err := s.Execute(context.Background(), agent.Input{
		"action": "behavior_scan",
	})
	if err != nil {
		t.Fatal(err)
	}
	if out["total_checks"] == 0 {
		t.Log("behavior scan checks:", out["total_checks"])
	}
}

func TestRootkitScanner_UnknownAction(t *testing.T) {
	s := NewRootkitScanner()
	_, err := s.Execute(context.Background(), agent.Input{"action": "unknown"})
	if err == nil {
		t.Fatal("expected error for unknown action")
	}
}


