# Plugin Development Guide

Plugins extend Trace by adding new agents. They are compiled as Go `.so` shared libraries loaded at runtime.

## Interface

Your plugin must export a `Plugin` symbol implementing `agent.AgentPlugin`:

```go
package main

import (
    "context"
    "github.com.trace/edge/internal/agent"
)

type MyAgent struct{}

func (a *MyAgent) Name() string { return "my-agent" }

func (a *MyAgent) Capabilities() []agent.Capability {
    return []agent.Capability{
        {Action: "my_action", Inputs: []string{"input"}, Outputs: []string{"output"}},
    }
}

func (a *MyAgent) Execute(_ context.Context, input agent.Input) (agent.Output, error) {
    return agent.Output{"result": "hello from my plugin"}, nil
}

type Plugin struct{}

func (p *Plugin) Agent() agent.Agent { return &MyAgent{} }

var Export Plugin
```

## Building

```bash
go build -buildmode=plugin -o my-plugin.so .
```

## Installing

```bash
innoigniter plugin install https://example.com/plugins/my-plugin.so
```

Restart the daemon to load it:

```bash
innoigniter serve
```

The plugin appears in .trace plugin list`.

## Capabilities

| Method | Returns |
|---|---|
| `Name()` | Unique agent identifier |
| `Capabilities()` | List of supported actions with input/output schemas |
| `Execute(ctx, input)` | Execute an action, return output or error |

## Distribution

Host the `.so` file on a web server and distribute the URL. Users install via .trace plugin install <url>`.
