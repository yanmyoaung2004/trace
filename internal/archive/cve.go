package archive

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type CVEResult struct {
	ID          string   `json:"id"`
	Severity    string   `json:"severity"`
	CVSS        float64  `json:"cvss"`
	Description string   `json:"description"`
	Vector      string   `json:"vector"`
	Published   string   `json:"published"`
	Affected    []string `json:"affected"`
}

type CVEClient struct {
	httpClient *http.Client
	cacheDB    *sql.DB
}

func NewCVEClient(cacheDB *sql.DB) *CVEClient {
	return &CVEClient{
		httpClient: &http.Client{Timeout: 10 * time.Second},
		cacheDB:    cacheDB,
	}
}

func (c *CVEClient) Lookup(ctx context.Context, cveID string) (*CVEResult, error) {
	cveID = strings.ToUpper(strings.TrimSpace(cveID))
	if !strings.HasPrefix(cveID, "CVE-") {
		return nil, fmt.Errorf("invalid CVE ID format: %s", cveID)
	}

	result, err := c.checkCache(ctx, cveID)
	if err == nil && result != nil {
		return result, nil
	}

	result, err = c.fetchFromNVD(ctx, cveID)
	if err != nil {
		return nil, fmt.Errorf("fetch CVE: %w", err)
	}

	c.storeCache(ctx, cveID, result)
	return result, nil
}

func (c *CVEClient) checkCache(ctx context.Context, cveID string) (*CVEResult, error) {
	var data string
	err := c.cacheDB.QueryRowContext(ctx,
		`SELECT value FROM cache WHERE key = ? AND ttl > CAST(strftime('%s','now') AS INTEGER)`,
		"cve:"+cveID).Scan(&data)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var result CVEResult
	if err := json.Unmarshal([]byte(data), &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *CVEClient) fetchFromNVD(ctx context.Context, cveID string) (*CVEResult, error) {
	apiURL := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=%s", url.QueryEscape(cveID))

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "trace/0.1.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("nvd request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return nil, fmt.Errorf("CVE not found: %s", cveID)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("nvd returned status %d", resp.StatusCode)
	}

	var nvdResp struct {
		Vulnerabilities []struct {
			CVE struct {
				ID      string `json:"id"`
				Published string `json:"published"`
				Descriptions []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"descriptions"`
				Metrics struct {
					CVSSMetricV31 []struct {
						CVSSData struct {
							BaseScore    float64 `json:"baseScore"`
							Severity     string `json:"baseSeverity"`
							VectorString string `json:"vectorString"`
						} `json:"cvssData"`
					} `json:"cvssMetricV31"`
					CVSSMetricV30 []struct {
						CVSSData struct {
							BaseScore    float64 `json:"baseScore"`
							Severity     string  `json:"baseSeverity"`
							VectorString string  `json:"vectorString"`
						} `json:"cvssData"`
					} `json:"cvssMetricV30"`
					CVSSMetricV2 []struct {
						CVSSData struct {
							BaseScore    float64 `json:"baseScore"`
							Severity     string  `json:"baseSeverity"`
							VectorString string  `json:"vectorString"`
						} `json:"cvssData"`
					} `json:"cvssMetricV2"`
				} `json:"metrics"`
				Weaknesses []struct {
					Description []struct {
						Value string `json:"value"`
					} `json:"description"`
				} `json:"weaknesses"`
				Configurations []struct {
					Nodes []struct {
						CPEMatch []struct {
							Criteria string `json:"criteria"`
						} `json:"cpeMatch"`
					} `json:"nodes"`
				} `json:"configurations"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&nvdResp); err != nil {
		return nil, fmt.Errorf("decode nvd response: %w", err)
	}

	if len(nvdResp.Vulnerabilities) == 0 {
		return nil, fmt.Errorf("CVE not found: %s", cveID)
	}

	vuln := nvdResp.Vulnerabilities[0].CVE

	result := &CVEResult{
		ID:        vuln.ID,
		Published: vuln.Published,
	}

	for _, desc := range vuln.Descriptions {
		if desc.Lang == "en" || len(result.Description) == 0 {
			result.Description = desc.Value
		}
	}

	if len(vuln.Metrics.CVSSMetricV31) > 0 {
		result.CVSS = vuln.Metrics.CVSSMetricV31[0].CVSSData.BaseScore
		result.Severity = vuln.Metrics.CVSSMetricV31[0].CVSSData.Severity
		result.Vector = vuln.Metrics.CVSSMetricV31[0].CVSSData.VectorString
	} else if len(vuln.Metrics.CVSSMetricV30) > 0 {
		result.CVSS = vuln.Metrics.CVSSMetricV30[0].CVSSData.BaseScore
		result.Severity = vuln.Metrics.CVSSMetricV30[0].CVSSData.Severity
		result.Vector = vuln.Metrics.CVSSMetricV30[0].CVSSData.VectorString
	} else if len(vuln.Metrics.CVSSMetricV2) > 0 {
		result.CVSS = vuln.Metrics.CVSSMetricV2[0].CVSSData.BaseScore
		result.Severity = vuln.Metrics.CVSSMetricV2[0].CVSSData.Severity
		result.Vector = vuln.Metrics.CVSSMetricV2[0].CVSSData.VectorString
	}

	for _, cfg := range vuln.Configurations {
		for _, node := range cfg.Nodes {
			for _, match := range node.CPEMatch {
				result.Affected = append(result.Affected, match.Criteria)
			}
		}
	}

	if len(result.Affected) > 10 {
		result.Affected = result.Affected[:10]
	}

	return result, nil
}

func (c *CVEClient) storeCache(ctx context.Context, cveID string, result *CVEResult) {
	data, _ := json.Marshal(result)
	ttl := 86400
	c.cacheDB.ExecContext(ctx,
		`INSERT OR REPLACE INTO cache (key, value, ttl) VALUES (?, ?, CAST(strftime('%s','now') AS INTEGER) + ?)`,
		"cve:"+cveID, string(data), ttl)
}
