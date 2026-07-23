package siem

import (
	"encoding/json"
	"fmt"
	"time"
)

type SuricataDecoder struct{}

func (d *SuricataDecoder) Name() string { return "suricata" }

type suricataEvent struct {
	Timestamp string `json:"timestamp"`
	EventType string `json:"event_type"`
	SrcIP     string `json:"src_ip"`
	SrcPort   int    `json:"src_port"`
	DestIP    string `json:"dest_ip"`
	DestPort  int    `json:"dest_port"`
	Proto     string `json:"proto"`
	Alert     *struct {
		Action   string `json:"action"`
		GID      int    `json:"gid"`
		SID      int    `json:"sid"`
		Rev      int    `json:"rev"`
		Rule     string `json:"rule"`
		Category string `json:"category"`
		Severity int    `json:"severity"`
	} `json:"alert,omitempty"`
	DNS *struct {
		Type       string `json:"type"`
		Query      string `json:"query"`
		Rcode      string `json:"rcode"`
		Answers    []struct {
			Name string `json:"rname"`
			Type string `json:"rtype"`
			TTL  int    `json:"ttl"`
		} `json:"answers,omitempty"`
	} `json:"dns,omitempty"`
	HTTP *struct {
		Hostname string `json:"hostname"`
		URL      string `json:"url"`
		Method   string `json:"http_method"`
		Status   int    `json:"status"`
		Length   int    `json:"length"`
	} `json:"http,omitempty"`
	TLS *struct {
		Subject   string `json:"subject"`
		IssuerDN  string `json:"issuerdn"`
		Sni       string `json:"sni"`
		Version   string `json:"version"`
	} `json:"tls,omitempty"`
	Flow *struct {
		BytesToServer int `json:"bytes_toserver"`
		BytesToClient int `json:"bytes_toclient"`
	} `json:"flow,omitempty"`
}

func (d *SuricataDecoder) Decode(raw []byte) (*Event, error) {
	var s suricataEvent
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, err
	}
	if s.EventType == "" {
		return nil, fmt.Errorf("not a suricata event")
	}

	tags := []string{"nids", s.EventType}
	fields := map[string]any{
		"event_type": s.EventType,
	}

	if s.SrcIP != "" {
		fields["src_ip"] = s.SrcIP
		fields["src_port"] = s.SrcPort
	}
	if s.DestIP != "" {
		fields["dest_ip"] = s.DestIP
		fields["dest_port"] = s.DestPort
	}
	if s.Proto != "" {
		fields["protocol"] = s.Proto
	}

	sev := 1
	if s.Alert != nil {
		tags = append(tags, "alert")
		fields["rule"] = s.Alert.Rule
		fields["category"] = s.Alert.Category
		fields["action"] = s.Alert.Action
		fields["sig_id"] = s.Alert.SID

		// Map Suricata severity (1-4) to Trace severity (3,5,7)
		switch s.Alert.Severity {
		case 1:
			sev = 7
		case 2:
			sev = 5
		case 3:
			sev = 3
		default:
			sev = 1
		}
	}

	if s.DNS != nil {
		fields["dns_type"] = s.DNS.Type
		fields["dns_query"] = s.DNS.Query
		fields["dns_rcode"] = s.DNS.Rcode
	}

	if s.HTTP != nil {
		fields["http_hostname"] = s.HTTP.Hostname
		fields["http_url"] = s.HTTP.URL
		fields["http_method"] = s.HTTP.Method
		fields["http_status"] = s.HTTP.Status
	}

	if s.TLS != nil {
		fields["tls_sni"] = s.TLS.Sni
		fields["tls_subject"] = s.TLS.Subject
	}

	ts := time.Now().UTC()
	if s.Timestamp != "" {
		if t, err := time.Parse("2006-01-02T15:04:05.999999-0700", s.Timestamp); err == nil {
			ts = t.UTC()
		} else if t, err := time.Parse(time.RFC3339Nano, s.Timestamp); err == nil {
			ts = t.UTC()
		}
	}

	return &Event{
		Timestamp: ts,
		Source:    "suricata",
		Raw:       string(raw),
		Tags:      tags,
		Fields:    fields,
		Severity:  sev,
	}, nil
}
