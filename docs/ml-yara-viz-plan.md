# Improvement Plan: ML + YARA Feeds + Dashboard Visualization

## Problem

| Weakness | Priority | Current state |
|----------|----------|---------------|
| PE analysis is signature-only | Medium | Detects packers, sections, imports — but no ML classification |
| Static YARA rules | Low | 17 built-in rules, never updated manually |
| No visualization | Low | Plain HTML tables, no charts or heatmaps |

## Plan

### Phase A: ML Model Infrastructure (for you to train)

I'll add:

A1. **Feature extraction interface** — exports PE features as a flat float64 slice (entropy per section, import counts, compile year, section count, etc.) suitable for ML input.

A2. **ONNX Runtime loader** — loads an `.onnx` model file at startup, runs inference via pure Go (no Python dependency). The model file path is configurable.

A3. **Classification hook** — if a model is loaded, `AnalyzePE()` also calls the classifier and adds `ml_score`, `ml_label`, and `ml_confidence` to `PEMetadata`.

A4. **Training instructions** — a Python script + instructions to train a model on your malware corpus and export to ONNX.

### Phase B: YARA Feed Integration (I can do now)

B1. **OTX feed endpoint** — `trace yara update` fetches rules from AlienVault OTX API.

B2. **Local rule directory** — load `.yar` files from `~/.trace/yara/` at startup, merge with embedded rules.

B3. **Auto-update** — periodic fetch of new rules from configured URLs (OTX, MISP, or custom).

### Phase C: Dashboard Visualization (I can do now)

C1. **Chart.js** — add the library to the dashboard pages.

C2. **Alert timeline chart** — bar chart of alerts over time (last 24h/7d/30d).

C3. **Severity distribution** — pie chart showing alert severity breakdown.

C4. **TSE storage usage** — line chart of hot events vs cold files over time.

C5. **MITRE ATT&CK heatmap** — matrix showing tactics x techniques with alert count cell coloring.
