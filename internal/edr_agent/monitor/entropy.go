package monitor

import (
	"encoding/json"
	"log"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
)

type EntropyBaseline struct {
	mu        sync.RWMutex
	samples   map[string][]float64
	means     map[string]float64
	stddevs   map[string]float64
	dataDir   string
	loaded    bool
	zScore    float64
	decayPct  float64
}

type entropySample struct {
	Name   string    `json:"name"`
	Values []float64 `json:"values"`
}

func NewEntropyBaseline(dataDir string) *EntropyBaseline {
	eb := &EntropyBaseline{
		samples: make(map[string][]float64),
		means:   make(map[string]float64),
		stddevs: make(map[string]float64),
		dataDir: dataDir,
		zScore:  3.0,
		decayPct: 0.01,
	}
	if v := os.Getenv("TRACE_ENTROPY_ZSCORE"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			eb.zScore = f
		}
	}
	if dataDir != "" {
		eb.load()
	}
	return eb
}

func (eb *EntropyBaseline) Record(sectionName string, entropy float64) {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	eb.samples[sectionName] = append(eb.samples[sectionName], entropy)
	if len(eb.samples[sectionName]) > 100 {
		eb.samples[sectionName] = eb.samples[sectionName][len(eb.samples[sectionName])-100:]
	}

	// Recalculate mean + stddev
	vals := eb.samples[sectionName]
	if len(vals) < 3 {
		return
	}

	var sum float64
	for _, v := range vals {
		sum += v
	}
	mean := sum / float64(len(vals))

	var varianceSum float64
	for _, v := range vals {
		diff := v - mean
		varianceSum += diff * diff
	}
	stddev := math.Sqrt(varianceSum / float64(len(vals)))

	eb.means[sectionName] = mean
	eb.stddevs[sectionName] = stddev
}

func (eb *EntropyBaseline) IsAnomalous(sectionName string, entropy float64) (bool, float64) {
	eb.mu.RLock()
	defer eb.mu.RUnlock()

	mean, hasMean := eb.means[sectionName]
	stddev, hasStddev := eb.stddevs[sectionName]

	if !hasMean || !hasStddev || stddev < 0.1 {
		return entropy > 7.0, 0
	}

	// Apply time decay: shift old samples toward new observation
	eb.decayLocked(sectionName, entropy)

	z := math.Abs(entropy-mean) / stddev
	return z > eb.zScore, z
}

func (eb *EntropyBaseline) decayLocked(sectionName string, newEntropy float64) {
	vals, exists := eb.samples[sectionName]
	if !exists || len(vals) < 2 {
		return
	}

	// Shift 1% of each old sample toward the new observation
	for i := range vals {
		diff := newEntropy - vals[i]
		vals[i] += diff * eb.decayPct
	}

	// Recalculate
	var sum float64
	for _, v := range vals {
		sum += v
	}
	mean := sum / float64(len(vals))
	var varianceSum float64
	for _, v := range vals {
		diff := v - mean
		varianceSum += diff * diff
	}

	eb.means[sectionName] = mean
	eb.stddevs[sectionName] = math.Sqrt(varianceSum / float64(len(vals)))
}

func (eb *EntropyBaseline) Warmup(paths []string) {
	for _, root := range paths {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			fpath := filepath.Join(root, entry.Name())
			data, err := os.ReadFile(fpath)
			if err != nil || len(data) > 10*1024*1024 {
				continue
			}
			pe := AnalyzePE(data)
			if !pe.IsPE {
				continue
			}
			for _, sec := range pe.Sections {
				if sec.Entropy > 0 {
					eb.Record(sec.Name, sec.Entropy)
				}
			}
		}
	}
	if eb.loaded {
		log.Printf("[entropy] baseline loaded: %d sections, %d samples", len(eb.means), len(eb.samples))
	} else {
		log.Printf("[entropy] warmup complete: %d sections, %d samples", len(eb.means), len(eb.samples))
		eb.save()
	}
}

func (eb *EntropyBaseline) load() {
	if eb.dataDir == "" {
		return
	}
	path := filepath.Join(eb.dataDir, "entropy_baseline.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var samples []entropySample
	if err := json.Unmarshal(data, &samples); err != nil {
		return
	}
	eb.mu.Lock()
	defer eb.mu.Unlock()
	for _, s := range samples {
		eb.samples[s.Name] = s.Values
		for _, v := range s.Values {
			eb.Record(s.Name, v)
		}
	}
	eb.loaded = true
}

func (eb *EntropyBaseline) save() {
	if eb.dataDir == "" {
		return
	}
	eb.mu.RLock()
	samples := make([]entropySample, 0, len(eb.samples))
	for name, vals := range eb.samples {
		samples = append(samples, entropySample{Name: name, Values: vals})
	}
	eb.mu.RUnlock()

	sort.Slice(samples, func(i, j int) bool { return samples[i].Name < samples[j].Name })

	data, err := json.MarshalIndent(samples, "", "  ")
	if err != nil {
		return
	}
	os.MkdirAll(eb.dataDir, 0700)
	os.WriteFile(filepath.Join(eb.dataDir, "entropy_baseline.json"), data, 0600)
}
