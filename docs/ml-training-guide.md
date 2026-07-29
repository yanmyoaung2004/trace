# ML Model Training Guide for PE Classification

## Overview

Trace can load an ONNX model to classify PE files as malicious/benign.
You train the model yourself on your malware corpus, export to ONNX,
and Trace loads it at startup.

## Prerequisites

```bash
pip install onnx onnxruntime numpy scikit-learn pandas
```

## Step 1: Extract features from your PE corpus

Use `trace investigate -f` on each sample to get feature data,
or use the built-in feature extractor:

```python
import subprocess, json, sys

def extract_features(path):
    """Run trace PE analysis and return feature vector."""
    result = subprocess.run(
        ["trace", "investigate", "-f", path],
        capture_output=True, text=True
    )
    # Parse the output for PE metadata
    data = {}
    for line in result.stderr.split('\n'):
        if ':' in line:
            key, val = line.split(':', 1)
            data[key.strip()] = val.strip()
    return data
```

**Feature vector** (12 floats):

| Index | Feature | Description |
|-------|---------|-------------|
| 0 | entropy | Overall file entropy (0-8) |
| 1 | section_count | Number of PE sections |
| 2 | import_count | Number of imported DLLs |
| 3 | has_high_entropy | 1 if any section entropy > 7.0 |
| 4 | compile_year | Compile timestamp year (0 if none) |
| 5 | is_dll | 1 if DLL, 0 if EXE |
| 6 | section_0_entropy | First section entropy |
| 7 | section_1_entropy | Second section entropy |
| 8 | max_section_entropy | Highest section entropy |
| 9 | has_tls | 1 if TLS callbacks present |
| 10 | has_reloc | 1 if relocations present |
| 11 | overlay_size_bytes | Size of data after last section |

## Step 2: Train a classifier

```python
import numpy as np
from sklearn.ensemble import RandomForestClassifier
import onnx
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType

# X: shape (n_samples, 12) — your feature vectors
# y: shape (n_samples,) — 0=benign, 1=malicious
X = np.array([...])
y = np.array([...])

model = RandomForestClassifier(n_estimators=100, max_depth=10)
model.fit(X, y)

# Export to ONNX
initial_type = [('float_input', FloatTensorType([None, 12]))]
onnx_model = convert_sklearn(model, initial_types=initial_type)
with open("pe_classifier.onnx", "wb") as f:
    f.write(onnx_model.SerializeToString())

print(f"Accuracy: {model.score(X, y):.2%}")
```

## Step 3: Use with Trace

```bash
# Copy model to trace config directory
cp pe_classifier.onnx ~/.trace/pe_classifier.onnx

# Trace auto-loads it at startup
trace investigate -f suspicious.exe
# Output includes: ML Score: 0.97, Label: malicious
```

## Model Performance Targets

| Metric | Target |
|--------|--------|
| Accuracy | >95% |
| False positive rate | <2% |
| Inference time | <10ms per file |
| Minimum samples | 1,000 benign + 1,000 malicious |
