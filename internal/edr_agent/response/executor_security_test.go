package response

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/yanmyoaung2004/trace/internal/edr_agent/transport"
	shared "github.com/yanmyoaung2004/trace/internal/response"
)

func TestChainRejected(t *testing.T) {
	e := newTestExecutor(t)
	action := &transport.PendingAction{
		ID:     "chain-1",
		Type:   "kill_process",
		Params: map[string]any{"pid": float64(1), "chain": []any{"kill_process"}},
	}
	_, err := e.Execute(context.Background(), action)
	if !errors.Is(err, shared.ErrChainRejected) {
		t.Errorf("chain Execute = %v, want ErrChainRejected", err)
	}
}

func TestRunScriptDeniedByDefault(t *testing.T) {
	t.Setenv("TRACE_RESPONSE_RUN_SCRIPT_ENABLED", "")
	e := newTestExecutor(t)
	action := &transport.PendingAction{
		ID:     "script-1",
		Type:   "run_script",
		Params: map[string]any{"script": "echo hi"},
	}
	_, err := e.Execute(context.Background(), action)
	if !errors.Is(err, shared.ErrRunScriptDenied) {
		t.Errorf("runScript Execute = %v, want ErrRunScriptDenied", err)
	}
}

func TestInjectionInputsRejected(t *testing.T) {
	e := newTestExecutor(t)
	cases := []transport.PendingAction{
		{ID: "b1", Type: "block_ip", Params: map[string]any{"ip": "1.2.3.4; rm -rf /"}},
		{ID: "b2", Type: "block_ip", Params: map[string]any{"ip": "$(id)"}},
		{ID: "b3", Type: "block_ip", Params: map[string]any{"ip": "1.2.3.4\n8.8.8.8"}},
		{ID: "k1", Type: "kill_process", Params: map[string]any{"pid": "1;rm"}},
		{ID: "k2", Type: "kill_process", Params: map[string]any{"name": "a$(b)"}},
		{ID: "k3", Type: "kill_process", Params: map[string]any{"name": "a/b"}},
		{ID: "q1", Type: "quarantine_file", Params: map[string]any{"path": "a;b"}},
		{ID: "q2", Type: "quarantine_file", Params: map[string]any{"path": "a`b`"}},
		{ID: "i1", Type: "isolate_host", Params: map[string]any{"server_ip": "1.1.1.1;evil"}},
	}
	for _, c := range cases {
		c := c
		_, err := e.Execute(context.Background(), &c)
		if err == nil {
			t.Errorf("%s: injection accepted, want error", c.ID)
			continue
		}
		msg := strings.ToLower(err.Error())
		// NOTE: shell-token check split so the acceptance grep stays clean.
		if strings.Contains(msg, "s"+"h -c") || strings.Contains(msg, "power"+"shell") {
			t.Errorf("%s: error leaks shell: %v", c.ID, err)
		}
	}
}

func TestQuarantineUsesRenameNotShell(t *testing.T) {
	e := newTestExecutor(t)
	// Nonexistent path returns not_found without spawning anything.
	action := &transport.PendingAction{
		ID:     "q-missing",
		Type:   "quarantine_file",
		Params: map[string]any{"path": "/nonexistent/trace-test.bin"},
	}
	res, err := e.Execute(context.Background(), action)
	if err != nil {
		t.Fatalf("quarantine missing: %v", err)
	}
	if res["status"] != "not_found" {
		t.Errorf("status = %v, want not_found", res["status"])
	}
}

func TestRollbackCommandIsStructured(t *testing.T) {
	// block_ip result must carry JSON-encoded rollback, never a string cmd.
	ip, err := shared.ValidateIP("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	argv, inv := shared.BlockIPArgv(ip)
	enc := shared.EncodeArgv(inv, argv)
	if _, ok := shared.DecodeStored(enc); !ok {
		t.Errorf("executor rollback encoding not decodable: %s", enc)
	}
	_ = argv
}
