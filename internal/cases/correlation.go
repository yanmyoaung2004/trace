package cases

import (
	"context"
	"regexp"
	"sort"
	"strings"
)

// Entity correlation graph: a read-only builder over the existing
// cases/case_events/case_iocs tables. It goes beyond IOC counting by
// extracting host/user/process/ip entities from both IOCs and free-text
// event content, then linking entities across cases (shared infrastructure,
// shared actors) and within a case (co-occurrence).
//
// No schema changes, no writes: SELECTs only, via the existing Manager
// read helpers.

// EntityKind classifies a graph node.
type EntityKind string

const (
	EntityCase    EntityKind = "case"
	EntityHost    EntityKind = "host"
	EntityUser    EntityKind = "user"
	EntityProcess EntityKind = "process"
	EntityIP      EntityKind = "ip"
	EntityDomain  EntityKind = "domain"
	EntityHash    EntityKind = "hash"
	EntityURL     EntityKind = "url"
	EntityEmail   EntityKind = "email"
	EntityFile    EntityKind = "filepath"
)

// EntityNode is one correlated entity. Cases lists every case ID the
// entity was observed in; len(Cases) > 1 means cross-case correlation.
type EntityNode struct {
	Kind  EntityKind `json:"kind"`
	Value string     `json:"value"`
	Cases []string   `json:"cases"`
	Count int        `json:"count"` // total observations across cases
}

// EntityEdge links two node keys ("kind\x00value").
type EntityEdge struct {
	From     string `json:"from"`
	To       string `json:"to"`
	Relation string `json:"relation"` // contains|observed-in|co-occurs
	CaseID   string `json:"case_id"`
}

// EntityGraph is the correlation result.
type EntityGraph struct {
	Nodes []EntityNode `json:"nodes"`
	Edges []EntityEdge `json:"edges"`
}

// SharedEntities returns entities observed in at least minCases cases,
// sorted by case spread then observation count. This is the cross-case
// correlation signal (shared infra/actors), not an IOC count.
func (g *EntityGraph) SharedEntities(minCases int) []EntityNode {
	var out []EntityNode
	for _, n := range g.Nodes {
		if n.Kind != EntityCase && len(n.Cases) >= minCases {
			out = append(out, n)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if len(out[i].Cases) == len(out[j].Cases) {
			return out[i].Count > out[j].Count
		}
		return len(out[i].Cases) > len(out[j].Cases)
	})
	return out
}

var (
	ipRe      = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	hostRe    = regexp.MustCompile(`(?i)\bhost(?:name)?\s*[:=]\s*([A-Za-z0-9][A-Za-z0-9.\-]*)`)
	userRe    = regexp.MustCompile(`(?i)\buser(?:name)?\s*[:=]\s*([A-Za-z0-9_.\-\\]+)`)
	processRe = regexp.MustCompile(`(?i)\bprocess\s*[:=]\s*([^\s,;\"']+)`)
)

func entityKey(kind EntityKind, value string) string {
	return string(kind) + "\x00" + value
}

// BuildEntityGraph builds the correlation graph for one case (caseID != "")
// or across all cases (caseID == ""). Read-only.
func (m *Manager) BuildEntityGraph(ctx context.Context, caseID string) (*EntityGraph, error) {
	var caseList []*Case
	if caseID != "" {
		c, err := m.Get(ctx, caseID)
		if err != nil {
			return nil, err
		}
		caseList = []*Case{c}
	} else {
		var err error
		caseList, err = m.List(ctx, "", "")
		if err != nil {
			return nil, err
		}
	}

	g := &EntityGraph{}
	nodeIdx := map[string]int{} // key -> index into g.Nodes
	caseKeys := map[string]string{}

	addObs := func(kind EntityKind, value, cid string) string {
		value = strings.TrimSpace(value)
		if value == "" {
			return ""
		}
		norm := strings.ToLower(value)
		key := entityKey(kind, norm)
		i, ok := nodeIdx[key]
		if !ok {
			g.Nodes = append(g.Nodes, EntityNode{Kind: kind, Value: norm})
			i = len(g.Nodes) - 1
			nodeIdx[key] = i
		}
		n := &g.Nodes[i]
		n.Count++
		found := false
		for _, c := range n.Cases {
			if c == cid {
				found = true
				break
			}
		}
		if !found {
			n.Cases = append(n.Cases, cid)
		}
		return key
	}

	for _, c := range caseList {
		ck := addObs(EntityCase, c.ID, c.ID)
		caseKeys[c.ID] = ck

		var entKeys []string
		iocs, err := m.GetIOCs(ctx, c.ID)
		if err != nil {
			return nil, err
		}
		for _, i := range iocs {
			kind := EntityURL
			switch i.IOCType {
			case "ip":
				kind = EntityIP
			case "domain":
				kind = EntityDomain
			case "hash":
				kind = EntityHash
			case "email":
				kind = EntityEmail
			case "filepath":
				kind = EntityFile
			default:
				if ipRe.MatchString(i.Value) {
					kind = EntityIP
				}
			}
			if k := addObs(kind, i.Value, c.ID); k != "" {
				entKeys = append(entKeys, k)
			}
		}

		events, err := m.GetEvents(ctx, c.ID)
		if err != nil {
			return nil, err
		}
		for _, e := range events {
			for _, mt := range hostRe.FindAllStringSubmatch(e.Content, -1) {
				if k := addObs(EntityHost, mt[1], c.ID); k != "" {
					entKeys = append(entKeys, k)
				}
			}
			for _, mt := range userRe.FindAllStringSubmatch(e.Content, -1) {
				if k := addObs(EntityUser, mt[1], c.ID); k != "" {
					entKeys = append(entKeys, k)
				}
			}
			for _, mt := range processRe.FindAllStringSubmatch(e.Content, -1) {
				if k := addObs(EntityProcess, mt[1], c.ID); k != "" {
					entKeys = append(entKeys, k)
				}
			}
			for _, ip := range ipRe.FindAllString(e.Content, -1) {
				if k := addObs(EntityIP, ip, c.ID); k != "" {
					entKeys = append(entKeys, k)
				}
			}
		}

		// contains edges (case -> entity), deduped per case.
		seen := map[string]bool{}
		for _, k := range entKeys {
			if seen[k] {
				continue
			}
			seen[k] = true
			g.Edges = append(g.Edges, EntityEdge{From: ck, To: k, Relation: "contains", CaseID: c.ID})
			g.Edges = append(g.Edges, EntityEdge{From: k, To: ck, Relation: "observed-in", CaseID: c.ID})
		}
		// co-occurrence edges (entity <-> entity within one case).
		uniq := make([]string, 0, len(seen))
		for k := range seen {
			uniq = append(uniq, k)
		}
		sort.Strings(uniq)
		if len(uniq) <= 40 {
			for i := range uniq {
				for j := range uniq[i+1:] {
					g.Edges = append(g.Edges, EntityEdge{From: uniq[i], To: uniq[i+1+j], Relation: "co-occurs", CaseID: c.ID})
				}
			}
		}
	}

	sort.Slice(g.Nodes, func(i, j int) bool {
		if g.Nodes[i].Count == g.Nodes[j].Count {
			return entityKey(g.Nodes[i].Kind, g.Nodes[i].Value) < entityKey(g.Nodes[j].Kind, g.Nodes[j].Value)
		}
		return g.Nodes[i].Count > g.Nodes[j].Count
	})
	return g, nil
}
