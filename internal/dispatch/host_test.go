package dispatch_test

import (
	"context"
	"strings"
	"testing"

	"github.com/yanmyoaung2004/trace/internal/dispatch"
	"github.com/yanmyoaung2004/trace/internal/playbook"
)

func setupDispatch(t *testing.T) *dispatch.Agent {
	pbEngine := playbook.New()
	if err := pbEngine.LoadBuiltin(); err != nil {
		t.Fatalf("load builtin: %v", err)
	}
	return dispatch.New(pbEngine)
}

func TestClassifyIntentTek(t *testing.T) {
	dispatchAgent := setupDispatch(t)
	ctx := context.Background()

	output, err := dispatchAgent.Execute(ctx, map[string]any{
		"action": "classify_intent",
		"query":  "check this file for malware",
	})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	pb, _ := output["playbook"].(string)
	if pb == "" {
		t.Fatal("expected a playbook name")
	}
}

func TestClassifyIntentWithHashFlag(t *testing.T) {
	dispatchAgent := setupDispatch(t)
	ctx := context.Background()

	output, err := dispatchAgent.Execute(ctx, map[string]any{
		"action": "classify_intent",
		"query":  "analyze this",
		"hash":   "abc123",
	})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	pb, _ := output["playbook"].(string)
	if pb != "hash-lookup" {
		t.Fatalf("expected hash-lookup, got %s", pb)
	}
}

func TestClassifyIntentWithTechnique(t *testing.T) {
	dispatchAgent := setupDispatch(t)
	ctx := context.Background()

	output, err := dispatchAgent.Execute(ctx, map[string]any{
		"action":    "classify_intent",
		"query":     "mitre technique",
		"technique": "T1566",
	})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	pb, _ := output["playbook"].(string)
	if pb != "mitre-lookup" {
		t.Fatalf("expected mitre-lookup, got %s", pb)
	}
}

func TestSynthesizeReportEmpty(t *testing.T) {
	dispatchAgent := setupDispatch(t)
	ctx := context.Background()

	output, err := dispatchAgent.Execute(ctx, map[string]any{
		"action":  "synthesize_report",
		"results": map[string]any{},
		"intent":  "test intent",
		"investigation_id": "test-123",
	})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	report, _ := output["report"].(string)
	if report == "" {
		t.Fatal("expected report content")
	}

	if !strings.Contains(report, "Investigation Report") {
		t.Fatal("expected markdown report header")
	}
}

func TestSynthesizeReportWithResults(t *testing.T) {
	dispatchAgent := setupDispatch(t)
	ctx := context.Background()

	output, err := dispatchAgent.Execute(ctx, map[string]any{
		"action":  "synthesize_report",
		"results": map[string]any{
			"detection.yara_scan": map[string]any{
				"count":   3,
				"matches": []any{"EICAR_Test", "Suspicious_PowerShell"},
			},
			"knowledge.mitre_lookup": map[string]any{
				"found":   true,
				"name":    "Phishing",
				"tactics": []string{"initial-access"},
			},
		},
		"intent":  "check file",
		"investigation_id": "test-456",
	})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	report, _ := output["report"].(string)
	if report == "" {
		t.Fatal("expected report")
	}

	if !strings.Contains(report, "YARA matches") {
		t.Fatal("expected YARA matches in report")
	}
}

func TestConfidenceCalculation(t *testing.T) {
	dispatchAgent := setupDispatch(t)
	ctx := context.Background()

	output, err := dispatchAgent.Execute(ctx, map[string]any{
		"action": "calculate_confidence",
		"results": map[string]any{
			"detection.yara_scan": map[string]any{
				"count":   3,
				"matches": []string{"EICAR_Test"},
			},
			"detection.hash_lookup": map[string]any{
				"reputation": "malicious",
				"source":     "builtin",
			},
		},
	})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	confidence, _ := output["confidence"].(float64)
	if confidence <= 0 {
		t.Fatal("expected positive confidence score")
	}

	factors, ok := output["factors"].(map[string]float64)
	if !ok || len(factors) == 0 {
		t.Fatalf("expected confidence factors, got %T %v", output["factors"], output["factors"])
	}
}

func TestConfidenceLow(t *testing.T) {
	dispatchAgent := setupDispatch(t)
	ctx := context.Background()

	output, err := dispatchAgent.Execute(ctx, map[string]any{
		"action": "calculate_confidence",
		"results": map[string]any{
			"detection.hash_lookup": map[string]any{
				"reputation": "unknown",
				"source":     "local",
			},
		},
	})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	confidence, _ := output["confidence"].(float64)
	if confidence > 0.6 {
		t.Fatalf("expected low confidence for unknown result, got %.2f", confidence)
	}
}

func TestPlanInvestigation(t *testing.T) {
	dispatchAgent := setupDispatch(t)
	ctx := context.Background()

	output, err := dispatchAgent.Execute(ctx, map[string]any{
		"action": "plan_investigation",
		"intent": "check file hash",
		"hash":   "abc123",
	})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	pb, _ := output["playbook"].(string)
	if pb != "hash-lookup" {
		t.Fatalf("expected hash-lookup, got %s", pb)
	}
}

func TestUnknownAction(t *testing.T) {
	dispatchAgent := setupDispatch(t)
	ctx := context.Background()

	_, err := dispatchAgent.Execute(ctx, map[string]any{
		"action": "nonexistent",
	})
	if err == nil {
		t.Fatal("expected error for unknown action")
	}
}


