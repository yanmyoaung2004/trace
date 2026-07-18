package playbook

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed *.yaml
var builtinPlaybooks embed.FS

type Playbook struct {
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"`
	Triggers    []string `yaml:"triggers"`
	Steps       []Step   `yaml:"steps"`
}

type Step struct {
	Agent   string         `yaml:"agent"`
	Action  string         `yaml:"action"`
	Params  map[string]any `yaml:"params"`
	Timeout string         `yaml:"timeout,omitempty"`
	If      string         `yaml:"if,omitempty"`
	Wait    string         `yaml:"wait,omitempty"`
	Label   string         `yaml:"label,omitempty"`
	Optional bool          `yaml:"optional,omitempty"`
}

type Engine struct {
	playbooks map[string]*Playbook
}

func New() *Engine {
	return &Engine{playbooks: make(map[string]*Playbook)}
}

func (e *Engine) LoadBuiltin() error {
	entries, err := builtinPlaybooks.ReadDir(".")
	if err != nil {
		return fmt.Errorf("read builtin playbooks: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}
		pb, err := loadEmbedded(entry.Name())
		if err != nil {
			return fmt.Errorf("load builtin %s: %w", entry.Name(), err)
		}
		e.playbooks[pb.Name] = pb
	}
	return nil
}

func loadEmbedded(name string) (*Playbook, error) {
	data, err := builtinPlaybooks.ReadFile(name)
	if err != nil {
		return nil, err
	}
	var pb Playbook
	if err := yaml.Unmarshal(data, &pb); err != nil {
		return nil, fmt.Errorf("parse %s: %w", name, err)
	}
	return &pb, nil
}

func (e *Engine) LoadDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read playbook dir: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}
		pb, err := loadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return fmt.Errorf("load %s: %w", entry.Name(), err)
		}
		e.playbooks[pb.Name] = pb
	}
	return nil
}

func loadFile(path string) (*Playbook, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var pb Playbook
	if err := yaml.Unmarshal(data, &pb); err != nil {
		return nil, fmt.Errorf("parse playbook: %w", err)
	}

	return &pb, nil
}

func (e *Engine) Get(name string) *Playbook {
	return e.playbooks[name]
}

func (e *Engine) List() []*Playbook {
	var out []*Playbook
	for _, pb := range e.playbooks {
		out = append(out, pb)
	}
	return out
}
