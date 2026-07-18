package sift

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/yanmyoaung2004/trace/internal/agent"
)

type Agent struct {
	yaraScanner *YaraScanner
	hashCache   *HashCache
	vtClient    *VTClient
}

func New(cacheDB *sql.DB, vtAPIKey string) *Agent {
	ys := NewYaraScanner()
	ys.LoadEmbedded()

	hc := NewHashCache(cacheDB)
	hc.WarmBuiltin(context.Background())

	vt := NewVTClient(vtAPIKey, cacheDB)

	return &Agent{
		yaraScanner: ys,
		hashCache:   hc,
		vtClient:    vt,
	}
}

func (a *Agent) Name() string { return "sift" }

func (a *Agent) Capabilities() []agent.Capability {
	return []agent.Capability{
		{Action: "yara_scan", Inputs: []string{"path"}, Outputs: []string{"matches", "count"}},
		{Action: "pe_analyze", Inputs: []string{"path"}, Outputs: []string{"metadata", "suspicious"}},
		{Action: "hash_lookup", Inputs: []string{"hash"}, Outputs: []string{"reputation", "source"}},
		{Action: "vt_lookup", Inputs: []string{"indicator"}, Outputs: []string{"detection_ratio", "vendors"}},
	}
}

func (a *Agent) Execute(ctx context.Context, input agent.Input) (agent.Output, error) {
	action, _ := input["action"].(string)
	switch action {
	case "yara_scan":
		return a.yaraScan(ctx, input)
	case "pe_analyze":
		return a.peAnalyze(ctx, input)
	case "hash_lookup":
		return a.hashLookup(ctx, input)
	case "vt_lookup":
		return a.vtLookup(ctx, input)
	default:
		return nil, fmt.Errorf("unknown action: %s", action)
	}
}

func (a *Agent) yaraScan(_ context.Context, input agent.Input) (agent.Output, error) {
	path, _ := input["path"].(string)
	if path == "" {
		return agent.Output{"matches": []string{}, "count": 0, "error": "path is required"}, nil
	}

	matches, err := a.yaraScanner.ScanFile(path)
	if err != nil {
		return agent.Output{"matches": []string{}, "count": 0, "error": err.Error()}, nil
	}

	var matchNames []string
	for _, m := range matches {
		matchNames = append(matchNames, m.Rule)
	}

	return agent.Output{
		"matches": matchNames,
		"count":   len(matches),
		"details": matches,
	}, nil
}

func (a *Agent) peAnalyze(_ context.Context, input agent.Input) (agent.Output, error) {
	path, _ := input["path"].(string)
	if path == "" {
		return agent.Output{"error": "path is required"}, nil
	}

	meta, err := AnalyzePE(path)
	if err != nil {
		return agent.Output{"error": err.Error()}, nil
	}

	return agent.Output{
		"is_pe":          meta.IsPE,
		"md5":            meta.MD5,
		"sha1":           meta.SHA1,
		"sha256":         meta.SHA256,
		"file_size":      meta.FileSize,
		"compile_time":   meta.CompileTime,
		"entry_point":    meta.EntryPoint,
		"image_base":     meta.ImageBase,
		"subsystem":      meta.Subsystem,
		"imports":        meta.Imports,
		"sections":       meta.Sections,
		"suspicious":     meta.Suspicious,
		"entropy":        meta.Entropy,
		"high_entropy":   meta.HighEntropy,
	}, nil
}

func (a *Agent) hashLookup(ctx context.Context, input agent.Input) (agent.Output, error) {
	hash, _ := input["hash"].(string)
	if hash == "" {
		hash, _ = input["ioc"].(string)
	}
	if hash == "" {
		return agent.Output{"error": "hash is required"}, nil
	}

	cached, err := a.hashCache.Get(ctx, hash)
	if err == nil && cached != nil {
		return agent.Output{
			"hash":       hash,
			"reputation": cached.Reputation,
			"source":     cached.Source,
			"confidence": cached.Confidence,
		}, nil
	}

	if len(hash) == 64 && a.vtClient.apiKey != "" {
		vtResult, vtErr := a.vtClient.LookupHash(ctx, hash)
		if vtErr == nil && vtResult.Total > 0 {
			return agent.Output{
				"hash":       hash,
				"reputation": vtResult.Reputation,
				"source":     "virustotal",
				"malicious":  vtResult.Malicious,
				"total":      vtResult.Total,
			}, nil
		}
	}

	return agent.Output{
		"hash":       hash,
		"reputation": "unknown",
		"source":     "local",
		"confidence": 0,
	}, nil
}

func (a *Agent) vtLookup(ctx context.Context, input agent.Input) (agent.Output, error) {
	indicator, _ := input["indicator"].(string)
	if indicator == "" {
		indicator, _ = input["hash"].(string)
	}
	if indicator == "" {
		return agent.Output{"error": "indicator is required"}, nil
	}

	if isValidHash(indicator) {
		a.hashCache.Get(ctx, indicator)
		result, err := a.vtClient.LookupHash(ctx, indicator)
		if err != nil {
			return agent.Output{"indicator": indicator, "error": err.Error()}, nil
		}
		if result.Error != "" {
			return agent.Output{"indicator": indicator, "error": result.Error, "reputation": "unknown"}, nil
		}
		return agent.Output{
			"indicator":       indicator,
			"type":            "hash",
			"reputation":      result.Reputation,
			"detection_ratio": fmt.Sprintf("%d/%d", result.Malicious, result.Total),
			"malicious":       result.Malicious,
			"total":           result.Total,
			"vendors":         result.Vendors,
		}, nil
	}

	if len(indicator) > 0 && (indicator[0] >= '0' && indicator[0] <= '9') {
		result, err := a.vtClient.LookupIP(ctx, indicator)
		if err != nil {
			return agent.Output{"indicator": indicator, "error": err.Error()}, nil
		}
		return agent.Output{
			"indicator":  indicator,
			"type":       "ip",
			"reputation": result.Reputation,
		}, nil
	}

	result, err := a.vtClient.LookupURL(ctx, indicator)
	if err != nil {
		return agent.Output{"indicator": indicator, "error": err.Error()}, nil
	}
	return agent.Output{
		"indicator":  indicator,
		"type":       "url",
		"reputation": result.Reputation,
	}, nil
}
