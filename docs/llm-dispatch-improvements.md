# LLM Dispatch — Remaining Gaps

Current rating: 8/10. Target: 10/10.

---

## Gap 1: Prompt Versioning (Cache Invalidation)

**Problem:** Cache key = SHA-256(intent + playbooks). If the prompt template changes, old cached responses are still served. A user who runs the same intent after a prompt update gets the old (potentially wrong) result.

**Fix:** Add a `promptVersion` constant to `LLMPlanner`. Include it in the cache key:

```go
const currentPromptVersion = 1

func cacheKey(intent string, playbooks []string) string {
    version := fmt.Sprintf("v%d", currentPromptVersion)
    h := sha256.Sum256([]byte(version + intent + strings.Join(playbooks, ",")))
    return hex.EncodeToString(h[:16])
}
```

When the prompt is changed, bump `currentPromptVersion`. Old cache entries become automatically stale.

**Effort:** 15min

**Side effect:** Server restart after a prompt version bump invalidates the old cache faster than waiting 10min TTL.

---

## Gap 2: Model Fallback (Provider Chaining)

**Problem:** If OpenAI returns 500, the LLM dispatch tries 2 retries on OpenAI, then fails. It doesn't try Anthropic or Ollama as a backup.

**Fix:** Allow multiple providers to be configured. `Plan()` tries them in order:

```go
type LLMPlanner struct {
    providers []*LLMProvider  // tried in order
}

type LLMProvider struct {
    Name   string  // "openai", "anthropic", "ollama"
    URL    string
    APIKey string
    Model  string
}
```

`NewLLMPlanner` accepts one provider (backward compatible). New `AddProvider()` method adds fallbacks. `Plan()` iterates providers: try primary, if fails → try fallback, if fails → return error.

**Config:**
```bash
export TRACE_LLM_PROVIDERS='[{"name":"openai","url":"...","api_key":"...","model":"gpt-4"},{"name":"ollama","url":"http://localhost:11434","model":"llama3"}]'
```

Default behavior unchanged if only one provider is configured.

**Effort:** 3h

---

## Gap 3: Streaming / Progress Reporting

**Problem:** `Plan()` blocks the investigation for up to 10s (1 attempt × 10s timeout). The user sees nothing during that time. For slow models, this feels like a hang.

**Fix:** Add a progress callback to `Plan()`:

```go
type ProgressFunc func(stage string, detail string)

func (lp *LLMPlanner) Plan(ctx context.Context, intent string, playbooks []string, progress ProgressFunc) (string, map[string]any, error) {
    progress("llm", "Querying AI planner...")
    ...
}
```

The caller shows progress in the CLI:
```
$ trace investigate "check hash abc123"
Dispatch: classifying intent...
Dispatch: Querying AI planner... (⏳ waiting for LLM)
Dispatch: Heuristic: hash-lookup (LLM timed out)
```

The `ProgressFunc` is optional — pass `nil` for no reporting.

**Effort:** 2h

---

## Gap 4: Cost Tracking

**Problem:** No counter for LLM calls made, cache hits, or estimated cost. Operators can't monitor LLM spend.

**Fix:** Add atomic counters to `LLMPlanner`:

```go
type LLMPlanner struct {
    // ...existing fields...
    TotalCalls    atomic.Int64
    CacheHits     atomic.Int64
    TotalFailures atomic.Int64
}
```

Expose via `Stats()` method:

```go
func (lp *LLMPlanner) Stats() map[string]any {
    return map[string]any{
        "total_calls":    lp.TotalCalls.Load(),
        "cache_hits":     lp.CacheHits.Load(),
        "total_failures": lp.TotalFailures.Load(),
    }
}
```

Integrate with `trace tse metrics` or the dispatch agent's `Capabilities()`.

**Effort:** 1h

---

## Gap 5: Persistent Cache

**Problem:** Restart the server, cache is gone. First 100 unique intents after restart pay full LLM price.

**Fix:** Optional SQLite-backed cache:

```go
type LLMPlanner struct {
    // ...existing fields...
    cacheDB *sql.DB  // optional SQLite for persistent cache
}

func (lp *LLMPlanner) WithCacheDB(db *sql.DB) *LLMPlanner {
    lp.cacheDB = db
    lp.initCacheTable()
    return lp
}
```

SQLite table:
```sql
CREATE TABLE IF NOT EXISTS llm_cache (
    key TEXT PRIMARY KEY,
    playbook TEXT NOT NULL,
    params TEXT NOT NULL,  -- JSON
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
```

Check SQLite cache before in-memory cache. Write to both on success. TTL enforced by in-memory (10min) and SQLite (configurable, default 24h).

**Effort:** 2h

---

## Execution Order

| # | Gap | Effort | Impact | Priority |
|---|-----|--------|--------|:--------:|
| 1 | Prompt versioning | 15min | Prevents stale cache after prompt changes | P0 |
| 4 | Cost tracking | 1h | Operators can monitor LLM spend | P1 |
| 2 | Model fallback | 3h | Resilience when primary LLM is down | P2 |
| 3 | Streaming | 2h | Better UX during slow LLM calls | P3 |
| 5 | Persistent cache | 2h | Survives restarts, saves money | P4 |

**Total: ~8h**
