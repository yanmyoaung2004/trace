package telemetry

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"runtime"
	"time"
)

type Report struct {
	Version           string `json:"version"`
	OS                string `json:"os"`
	Arch              string `json:"arch"`
	InvestigationCount int   `json:"investigation_count"`
	PluginCount       int    `json:"plugin_count"`
	UptimeSeconds     int64  `json:"uptime_seconds"`
}

type Telemetry struct {
	enabled    bool
	url        string
	client     *http.Client
	version    string
	startTime  time.Time
	pluginCount func() int
	invCount   func() int
}

func New(enabled bool, version, url string) *Telemetry {
	return &Telemetry{
		enabled:   enabled,
		url:       url,
		client:    &http.Client{Timeout: 10 * time.Second},
		version:   version,
		startTime: time.Now(),
	}
}

func (t *Telemetry) WithCounts(pc func() int, ic func() int) *Telemetry {
	t.pluginCount = pc
	t.invCount = ic
	return t
}

func (t *Telemetry) Start() {
	if !t.enabled || t.url == "" {
		return
	}

	t.send()

	ticker := time.NewTicker(24 * time.Hour)
	go func() {
		for range ticker.C {
			t.send()
		}
	}()
}

func (t *Telemetry) send() {
	report := Report{
		Version:       t.version,
		OS:            runtime.GOOS,
		Arch:          runtime.GOARCH,
		UptimeSeconds: int64(time.Since(t.startTime).Seconds()),
	}

	if t.pluginCount != nil {
		report.PluginCount = t.pluginCount()
	}
	if t.invCount != nil {
		report.InvestigationCount = t.invCount()
	}

	data, _ := json.Marshal(report)
	resp, err := t.client.Post(t.url, "application/json", bytes.NewReader(data))
	if err != nil {
		log.Printf("[telemetry] send failed: %v", err)
		return
	}
	resp.Body.Close()
}

func init() {
	_ = fmt.Sprintf
}
