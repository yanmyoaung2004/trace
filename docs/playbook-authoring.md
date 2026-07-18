# Playbook Authoring Guide

Playbooks are YAML files that define multi-step investigation workflows.

## Structure

```yaml
name: my-playbook
description: What this playbook does
triggers:
  - keyword1
  - keyword2
steps:
  - agent: detection
    action: yara_scan
    params:
      path: "${input.path}"
    timeout: 30s
```

## Step Fields

| Field | Required | Description |
|---|---|---|
| `agent` | yes | Agent name (detection, knowledge, host, response) |
| `action` | yes | Action name from agent's capabilities |
| `params` | no | Parameters passed to the agent |
| `timeout` | no | Per-step timeout (e.g. `30s`, `5m`) |
| `if` | no | Conditional expression `${result.agent.action.key} == "value"` |
| `wait` | no | Set to `analyst_approval` for HITL gating |
| `label` | no | Human-readable label for approval prompts |
| `optional` | no | If true, step failure doesn't fail the investigation |

## Variable Interpolation

- `${input.key}` — value from investigation input
- `${result.agent.action.key}` — output from a previous step
- `${outputs.agent.action.key}` — same as result

## Conditions

```
if: '${result.detection.yara_scan.count} != "0"'
if: '${result.knowledge.mitre_lookup.found} == "true"'
```

## Example

```yaml
name: ip-reputation
description: Check an IP address against threat intel sources
triggers:
  - ip
  - address
steps:
  - agent: knowledge
    action: ioc_enrich
    params:
      ioc: "${input.ip}"
  - agent: detection
    action: vt_lookup
    params:
      indicator: "${input.ip}"
```

## Loading

Place playbooks in `~/.innoigniter/playbooks/` — they are auto-loaded on startup.
