package compliance

import (
	"context"
	"fmt"
	"time"
)

// ScheduledReport describes a recurring compliance report job.
// New additive type: scheduled reporting runs alongside (never instead of)
// on-demand generation. Persistence stays file-local under DataDir so no
// DB schema change is required.
type ScheduledReport struct {
	Name      string `json:"name"`
	Framework string `json:"framework"`
	Format    string `json:"format"`   // text|markdown|html|json|csv|cef
	Interval  string `json:"interval"` // e.g. "24h", "168h"
	Output    string `json:"output"`   // output file path template
	Enabled   bool   `json:"enabled"`
	LastRun   string `json:"last_run,omitempty"`
	NextRun   string `json:"next_run,omitempty"`
}

// Validate checks a schedule definition without side effects.
func (s ScheduledReport) Validate() error {
	if s.Name == "" {
		return fmt.Errorf("schedule name is required")
	}
	if _, ok := Frameworks[s.Framework]; !ok {
		return fmt.Errorf("unknown framework: %s", s.Framework)
	}
	switch s.Format {
	case "", "text", "markdown", "md", "html", "json", "csv", "cef":
	default:
		return fmt.Errorf("unknown format: %q", s.Format)
	}
	if s.Interval == "" {
		return fmt.Errorf("interval is required (e.g. 24h)")
	}
	if _, err := time.ParseDuration(s.Interval); err != nil {
		return fmt.Errorf("bad interval %q: %w", s.Interval, err)
	}
	return nil
}

// NextRunAfter computes the next run time after the given reference.
func (s ScheduledReport) NextRunAfter(ref time.Time) (time.Time, error) {
	d, err := time.ParseDuration(s.Interval)
	if err != nil {
		return time.Time{}, fmt.Errorf("bad interval %q: %w", s.Interval, err)
	}
	return ref.Add(d), nil
}

// RunScheduled generates the report and renders it in the scheduled
// format. Side-effect surface is limited to the engine's normal snapshot
// recording (same as on-demand reports).
func (e *ReportEngine) RunScheduled(ctx context.Context, s ScheduledReport) (string, error) {
	if err := s.Validate(); err != nil {
		return "", err
	}
	report, err := e.GenerateReport(ctx, ReportOptions{Framework: s.Framework})
	if err != nil {
		return "", fmt.Errorf("scheduled report %q: %w", s.Name, err)
	}
	format := s.Format
	if format == "" {
		format = "markdown"
	}
	out, err := report.RenderFormat(format)
	if err != nil {
		return "", err
	}
	return out, nil
}
