package plugin

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"plugin"
	"strings"

	"github.com/yanmyoaung2004/trace/internal/agent"
)

type Registry struct {
	agents map[string]agent.Agent
}

func NewRegistry() *Registry {
	return &Registry{agents: make(map[string]agent.Agent)}
}

func (r *Registry) Register(a agent.Agent) {
	r.agents[a.Name()] = a
}

func (r *Registry) Get(name string) agent.Agent {
	return r.agents[name]
}

func (r *Registry) List() []agent.Agent {
	var out []agent.Agent
	for _, a := range r.agents {
		out = append(out, a)
	}
	return out
}

type AgentPlugin interface {
	Agent() agent.Agent
}

func LoadDir(dir string) ([]agent.Agent, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read plugin dir: %w", err)
	}

	var agents []agent.Agent
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".so") {
			continue
		}

		p, err := plugin.Open(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("open plugin %s: %w", entry.Name(), err)
		}

		sym, err := p.Lookup("Plugin")
		if err != nil {
			return nil, fmt.Errorf("lookup Plugin symbol in %s: %w", entry.Name(), err)
		}

		ap, ok := sym.(AgentPlugin)
		if !ok {
			continue
		}

		agents = append(agents, ap.Agent())
	}

	return agents, nil
}

func init() {
	_ = context.Background()
}
