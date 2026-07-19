package siem

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
)

type wazuhDecoderDef struct {
	Name        string   `json:"name"`
	Parent      string   `json:"parent,omitempty"`
	ProgramName string   `json:"program_name,omitempty"`
	PreMatch    string   `json:"prematch,omitempty"`
	Regex       string   `json:"regex,omitempty"`
	Order       []string `json:"order,omitempty"`
}

type compiledWazuhDecoder struct {
	def     wazuhDecoderDef
	preRe   *regexp.Regexp
	regexRe *regexp.Regexp
	progRe  *regexp.Regexp
}

type WazuhDecoder struct {
	decoders []compiledWazuhDecoder
	byName   map[string][]compiledWazuhDecoder
	initOnce sync.Once
}

func NewWazuhDecoder() *WazuhDecoder {
	return &WazuhDecoder{byName: make(map[string][]compiledWazuhDecoder)}
}

func (wd *WazuhDecoder) Name() string { return "wazuh" }

func (wd *WazuhDecoder) init() {
	wd.initOnce.Do(func() {
		if wd.byName == nil {
			wd.byName = make(map[string][]compiledWazuhDecoder)
		}
		var defs []wazuhDecoderDef
		if err := json.Unmarshal([]byte(wazuhDecodersJSON), &defs); err != nil {
			return
		}
		for _, d := range defs {
			c := compiledWazuhDecoder{def: d}
			if d.PreMatch != "" {
				c.preRe = compileWazuhPattern(d.PreMatch)
			}
			if d.Regex != "" {
				c.regexRe = compileWazuhPattern(d.Regex)
			}
			if d.ProgramName != "" {
				c.progRe = compileWazuhPattern(d.ProgramName)
			}
			wd.decoders = append(wd.decoders, c)
			wd.byName[d.Name] = append(wd.byName[d.Name], c)
		}
	})
}

func compileWazuhPattern(pattern string) *regexp.Regexp {
	p := pattern
	p = strings.ReplaceAll(p, `\`, `\\`)
	re, err := regexp.Compile(p)
	if err != nil {
		return nil
	}
	return re
}

func (wd *WazuhDecoder) Decode(raw []byte) (*Event, error) {
	wd.init()
	line := string(raw)

	matchedDecoder := wd.matchDecoder(line)
	if matchedDecoder == nil {
		return nil, fmt.Errorf("no matching decoder")
	}

	fields := make(map[string]any)
	fields["original"] = line

	if matchedDecoder.regexRe != nil && len(matchedDecoder.def.Order) > 0 {
		matches := matchedDecoder.regexRe.FindStringSubmatch(line)
		if len(matches) > 1 {
			for i, name := range matchedDecoder.def.Order {
				if i < len(matches)-1 && matches[i+1] != "" {
					fields[name] = matches[i+1]
				}
			}
		}
	}

	tags := []string{matchedDecoder.def.Name}
	severity := 0

	if matchedDecoder.def.Name == "sshd" {
		tags = append(tags, "sshd")
		lineLower := strings.ToLower(line)
		if strings.Contains(lineLower, "failed password") || strings.Contains(lineLower, "authentication failure") {
			tags = append(tags, "auth_failure")
			severity = 4
		} else if strings.Contains(lineLower, "accepted password") || strings.Contains(lineLower, "accepted publickey") {
			tags = append(tags, "auth_success")
			severity = 3
		}
	}

	return &Event{
		Timestamp: time.Now(),
		Source:    "wazuh-decoder",
		Raw:       line,
		Fields:    fields,
		Tags:      tags,
		Severity:  severity,
	}, nil
}

func (wd *WazuhDecoder) matchDecoder(line string) *compiledWazuhDecoder {
	var candidates []compiledWazuhDecoder

	for _, c := range wd.decoders {
		if c.def.Parent != "" {
			continue
		}
		if c.progRe != nil && c.progRe.MatchString(line) {
			if c.regexRe != nil && !c.regexRe.MatchString(line) {
				continue
			}
			candidates = append(candidates, c)
		}
	}

	if len(candidates) == 0 {
		return nil
	}

	for _, c := range candidates {
		if c.def.Regex != "" {
			return &c
		}
	}
	return &candidates[0]
}
