# InnoIgniterAI

Greenfield project — no code, no build system, no tests yet. The sole source of truth is `docs/product.md`.

## Product vision

Orchestrated multi-agent cybersecurity platform. Architecture from `docs/product.md`:

- **Host Agent** (planner/orchestrator) — intent parsing, task decomposition, response synthesis
- **Knowledge Agent** — threat intel, MITRE ATT&CK, CVE, web search, malware families, RAG
- **Detection Agent** — malware analysis (PE, static/dynamic), VirusTotal, custom ML/DL models
- **SIEM integration** via Wazuh (endpoint monitoring, log collection, intrusion detection)
- **A2A + MCP-style** agent communication, shared file server for large artifacts
- **Multilingual**: English + Myanmar

## Status

No source code exists. See `dev/build-plan.md` for the phased implementation plan. The tech stack, architecture, and plugin system are defined in `dev/edge-deployment.md`. The product vision is in `dev/product.md`. There is no CI yet — Phase 0 creates it.

## Key documents

| File | Purpose |
|---|---|
| `docs/product.md` | Product vision and high-level architecture |
| `docs/edge-deployment.md` | Tech stack, architecture, plugin interfaces, SIEM/SOAR design |
| `docs/improvements.md` | Architecture decisions and rationale |
| `docs/build-plan.md` | Phased build plan with verification steps for each phase |
| `docs/testing-guide.md` | Testing queries and verification commands for each phase |
