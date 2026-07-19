package archive

import (
	"embed"
	"encoding/json"
	"fmt"
	"strings"
)

type Technique struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Tactic      string   `json:"tactic"`
	Tactics     []string `json:"tactics"`
	Platforms   []string `json:"platforms"`
	Mitigations []string `json:"mitigations"`
	Detection   []string `json:"detection"`
}

type MitreDB struct {
	Techniques   map[string]*Technique
	TacticIndex  map[string][]*Technique
}

func NewMitreDB() *MitreDB {
	return &MitreDB{
		Techniques:  make(map[string]*Technique),
		TacticIndex: make(map[string][]*Technique),
	}
}

func (m *MitreDB) Load(data []byte) error {
	var techniques []Technique
	if err := json.Unmarshal(data, &techniques); err != nil {
		return fmt.Errorf("unmarshal mitre data: %w", err)
	}

	for i := range techniques {
		t := &techniques[i]
		m.Techniques[t.ID] = t
		for _, tactic := range t.Tactics {
			m.TacticIndex[tactic] = append(m.TacticIndex[tactic], t)
		}
	}

	return nil
}

func (m *MitreDB) GetByID(id string) *Technique {
	return m.Techniques[id]
}

func (m *MitreDB) Search(query string) []*Technique {
	q := strings.ToLower(query)
	var out []*Technique
	for _, t := range m.Techniques {
		if strings.Contains(strings.ToLower(t.ID), q) ||
			strings.Contains(strings.ToLower(t.Name), q) ||
			strings.Contains(strings.ToLower(t.Description), q) {
			out = append(out, t)
		}
	}
	return out
}

func (m *MitreDB) GetByTactic(tactic string) []*Technique {
	return m.TacticIndex[strings.ToLower(tactic)]
}

//go:embed mitre_data.json
var mitreSeed embed.FS

func LoadMitreSeed() (*MitreDB, error) {
	db := NewMitreDB()

	if mitreSeedJSON != "" {
		if err := db.Load([]byte(mitreSeedJSON)); err == nil {
			return db, nil
		}
	}

	data, err := mitreSeed.ReadFile("mitre_data.json")
	if err != nil {
		return nil, fmt.Errorf("read mitre seed: %w", err)
	}

	if err := db.Load(data); err != nil {
		return nil, fmt.Errorf("load mitre seed: %w", err)
	}

	return db, nil
}
