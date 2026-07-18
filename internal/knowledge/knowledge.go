package knowledge

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/innoigniter/edge/internal/agent"
)

type Agent struct {
	mitreDB      *MitreDB
	cveClient    *CVEClient
	intelCache   *IntelCache
	searchClient *WebSearchClient
}

func New(cacheDB *sql.DB, mitreDB *MitreDB) *Agent {
	return &Agent{
		mitreDB:      mitreDB,
		cveClient:    NewCVEClient(cacheDB),
		intelCache:   NewIntelCache(cacheDB),
		searchClient: NewWebSearchClient(""),
	}
}

func (a *Agent) WithWebSearch(apiKey string) *Agent {
	a.searchClient = NewWebSearchClient(apiKey)
	return a
}

func (a *Agent) Name() string { return "knowledge" }

func (a *Agent) Capabilities() []agent.Capability {
	return []agent.Capability{
		{Action: "mitre_lookup", Inputs: []string{"technique"}, Outputs: []string{"id", "name", "description", "tactics", "mitigations"}},
		{Action: "cve_lookup", Inputs: []string{"cve_id"}, Outputs: []string{"severity", "cvss", "description", "affected"}},
		{Action: "malware_lookup", Inputs: []string{"name"}, Outputs: []string{"aliases", "behaviors", "mitre_mapping"}},
		{Action: "ioc_enrich", Inputs: []string{"ioc"}, Outputs: []string{"intel", "mitre_mappings"}},
		{Action: "web_search", Inputs: []string{"query"}, Outputs: []string{"results"}},
	}
}

func (a *Agent) Execute(ctx context.Context, input agent.Input) (agent.Output, error) {
	action, _ := input["action"].(string)
	switch action {
	case "mitre_lookup":
		return a.mitreLookup(ctx, input)
	case "cve_lookup":
		return a.cveLookup(ctx, input)
	case "malware_lookup":
		return a.malwareLookup(ctx, input)
	case "ioc_enrich":
		return a.iocEnrich(ctx, input)
	case "web_search":
		return a.webSearch(ctx, input)
	default:
		return nil, fmt.Errorf("unknown action: %s", action)
	}
}

func (a *Agent) mitreLookup(_ context.Context, input agent.Input) (agent.Output, error) {
	technique, _ := input["technique"].(string)
	if technique == "" {
		return nil, fmt.Errorf("technique is required")
	}

	t := a.mitreDB.GetByID(technique)
	if t == nil {
		matches := a.mitreDB.Search(technique)
		if len(matches) > 0 {
			t = matches[0]
		}
	}

	if t == nil {
		return agent.Output{
			"found":       false,
			"message":     fmt.Sprintf("No MITRE technique found matching: %s", technique),
		}, nil
	}

	return agent.Output{
		"found":       true,
		"id":          t.ID,
		"name":        t.Name,
		"description": t.Description,
		"tactics":     t.Tactics,
		"platforms":   t.Platforms,
		"mitigations": t.Mitigations,
		"detection":   t.Detection,
	}, nil
}

func (a *Agent) cveLookup(ctx context.Context, input agent.Input) (agent.Output, error) {
	cveID, _ := input["cve_id"].(string)
	if cveID == "" {
		cveID, _ = input["ioc"].(string)
	}
	if cveID == "" {
		return nil, fmt.Errorf("cve_id is required")
	}

	result, err := a.cveClient.Lookup(ctx, cveID)
	if err != nil {
		return agent.Output{
			"found":   false,
			"message": err.Error(),
		}, nil
	}

	return agent.Output{
		"found":       true,
		"cve_id":      result.ID,
		"severity":    result.Severity,
		"cvss":        result.CVSS,
		"description": result.Description,
		"vector":      result.Vector,
		"published":   result.Published,
		"affected":    result.Affected,
	}, nil
}

func (a *Agent) malwareLookup(_ context.Context, input agent.Input) (agent.Output, error) {
	name, _ := input["name"].(string)
	if name == "" {
		name, _ = input["family"].(string)
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	mitreMatches := a.mitreDB.Search(name)

	return agent.Output{
		"name":       name,
		"aliases":    []string{},
		"behaviors":  []string{},
		"mitre_mapping": mitreMatches,
	}, nil
}

func (a *Agent) iocEnrich(ctx context.Context, input agent.Input) (agent.Output, error) {
	ioc, _ := input["ioc"].(string)
	if ioc == "" {
		ioc, _ = input["hash"].(string)
	}
	if ioc == "" {
		return agent.Output{"intel": map[string]any{"ioc": "", "type": "unknown"}, "mitre_mappings": []any{}}, nil
	}

	intel := map[string]any{
		"ioc":          ioc,
		"type":         classifyIOC(ioc),
		"lookups":      []map[string]any{},
	}

	cached, _ := a.intelCache.Get(ctx, ioc)
	if len(cached) > 0 {
		intel["cache_hit"] = true
		intel["reputation"] = cached[0].Reputation
		intel["confidence"] = cached[0].Confidence
	}

	builtin := a.intelCache.LookupBuiltin(ioc)
	if len(builtin) > 0 {
		intel["builtin_match"] = true
		intel["reputation"] = builtin[0].Reputation
		intel["confidence"] = builtin[0].Confidence
		intel["description"] = builtin[0].Description
		intel["tags"] = builtin[0].Tags
	}

	mitreMatches := a.mitreDB.Search(ioc)

	return agent.Output{
		"intel":         intel,
		"mitre_mappings": mitreMatches,
	}, nil
}

func (a *Agent) webSearch(ctx context.Context, input agent.Input) (agent.Output, error) {
	query, _ := input["query"].(string)
	if query == "" {
		return nil, fmt.Errorf("query is required")
	}

	results, err := a.searchClient.Search(ctx, query)
	if err != nil {
		return agent.Output{"results": []string{}, "error": err.Error()}, nil
	}

	return agent.Output{"results": results}, nil
}

func classifyIOC(s string) string {
	if len(s) == 32 {
		return "md5"
	}
	if len(s) == 40 {
		return "sha1"
	}
	if len(s) == 64 {
		return "sha256"
	}
	if strings.Contains(s, ".") && !strings.Contains(s, " ") {
		return "domain"
	}
	return "unknown"
}

func init() {
	_ = context.Background()
}
