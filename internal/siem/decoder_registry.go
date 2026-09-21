package siem

import (
	"fmt"
	"sort"
	"sync"
)

// DecoderFactory builds a Decoder. Factories are registered once and the
// engine instantiates from the registry in priority order.
type DecoderFactory func() Decoder

type decoderEntry struct {
	name     string
	priority int
	factory  DecoderFactory
}

var (
	decoderRegistryMu sync.RWMutex
	decoderRegistry   = map[string]decoderEntry{}
	decoderDefaultsMu sync.Mutex
	decoderDefaults   []Decoder
	decoderLoadedOnce sync.Once
)

// RegisterDecoder registers a named decoder factory. Duplicate names are
// rejected (no silent overwrite). Lower priority values decode first.
// It is safe for concurrent use.
func RegisterDecoder(name string, priority int, factory DecoderFactory) error {
	if name == "" {
		return fmt.Errorf("decoder name is required")
	}
	if factory == nil {
		return fmt.Errorf("decoder %q: factory is nil", name)
	}
	decoderRegistryMu.Lock()
	defer decoderRegistryMu.Unlock()
	if _, exists := decoderRegistry[name]; exists {
		return fmt.Errorf("decoder %q already registered", name)
	}
	decoderRegistry[name] = decoderEntry{name: name, priority: priority, factory: factory}
	return nil
}

// RegisteredDecoders lists registered decoder names in priority order.
func RegisteredDecoders() []string {
	decoderRegistryMu.RLock()
	entries := make([]decoderEntry, 0, len(decoderRegistry))
	for _, e := range decoderRegistry {
		entries = append(entries, e)
	}
	decoderRegistryMu.RUnlock()
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].priority == entries[j].priority {
			return entries[i].name < entries[j].name
		}
		return entries[i].priority < entries[j].priority
	})
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.name)
	}
	return names
}

// buildDecoders instantiates decoders from the registry in priority order.
func buildDecoders() []Decoder {
	decoderRegistryMu.RLock()
	entries := make([]decoderEntry, 0, len(decoderRegistry))
	for _, e := range decoderRegistry {
		entries = append(entries, e)
	}
	decoderRegistryMu.RUnlock()
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].priority == entries[j].priority {
			return entries[i].name < entries[j].name
		}
		return entries[i].priority < entries[j].priority
	})
	out := make([]Decoder, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.factory())
	}
	return out
}

// registerDefaultDecoders installs the built-in decoder set exactly once.
func registerDefaultDecoders() {
	decoderLoadedOnce.Do(func() {
		_ = RegisterDecoder("k8s", 10, func() Decoder { return &K8sAuditDecoder{} })
		_ = RegisterDecoder("suricata", 20, func() Decoder { return &SuricataDecoder{} })
		_ = RegisterDecoder("json", 30, func() Decoder { return &JSONDecoder{} })
		_ = RegisterDecoder("apache", 40, func() Decoder { return &ApacheDecoder{} })
		_ = RegisterDecoder("syslog", 50, func() Decoder { return &SyslogDecoder{} })
		_ = RegisterDecoder("evtx", 60, func() Decoder { return &EVTXDecoder{} })
		_ = RegisterDecoder("windows_event", 70, func() Decoder { return &WindowsEventDecoder{} })
		_ = RegisterDecoder("wazuh", 80, func() Decoder { return &WazuhDecoder{} })
		_ = RegisterDecoder("auto", 100, func() Decoder { return &AutoDecoder{} })
	})
}
