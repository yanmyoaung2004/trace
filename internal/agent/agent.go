package agent

import "context"

type Capability struct {
	Action  string
	Inputs  []string
	Outputs []string
}

type Input map[string]any

type Output map[string]any

type Agent interface {
	Name() string
	Capabilities() []Capability
	Execute(ctx context.Context, input Input) (Output, error)
}
