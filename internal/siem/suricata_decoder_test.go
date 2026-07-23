package siem

import (
	"testing"
)

func TestSuricataDecoderAlert(t *testing.T) {
	d := &SuricataDecoder{}
	input := []byte(`{"timestamp":"2024-01-15T10:30:45.123456+0200","event_type":"alert","src_ip":"10.0.0.5","src_port":12345,"dest_ip":"203.0.113.42","dest_port":80,"proto":"TCP","alert":{"action":"alert","gid":1,"sid":2100498,"rev":7,"rule":"ET MALWARE Suspicious Traffic","category":"Misc activity","severity":2}}`)

	evt, err := d.Decode(input)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	if evt.Source != "suricata" {
		t.Errorf("expected source=suricata, got %s", evt.Source)
	}
	if evt.Severity != 5 {
		t.Errorf("expected severity 5 (suricata 2), got %d", evt.Severity)
	}
	if v, ok := evt.Fields["rule"]; !ok || v != "ET MALWARE Suspicious Traffic" {
		t.Errorf("expected rule field, got %v", evt.Fields)
	}
	if v, ok := evt.Fields["src_ip"]; !ok || v != "10.0.0.5" {
		t.Errorf("expected src_ip=10.0.0.5, got %v", v)
	}
}

func TestSuricataDecoderDNS(t *testing.T) {
	d := &SuricataDecoder{}
	input := []byte(`{"timestamp":"2024-01-15T10:30:45Z","event_type":"dns","src_ip":"192.168.1.1","dest_ip":"8.8.8.8","dns":{"type":"query","query":"evil.com","rcode":"NXDOMAIN"}}`)

	evt, err := d.Decode(input)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	if v, ok := evt.Fields["dns_query"]; !ok || v != "evil.com" {
		t.Errorf("expected dns_query=evil.com, got %v", v)
	}
}

func TestSuricataDecoderBadJSON(t *testing.T) {
	d := &SuricataDecoder{}
	_, err := d.Decode([]byte(`{not json`))
	if err == nil {
		t.Fatal("expected error for bad JSON")
	}
}

func TestSuricataDecoderNotSuricata(t *testing.T) {
	d := &SuricataDecoder{}
	_, err := d.Decode([]byte(`{"key":"value"}`))
	if err == nil {
		t.Fatal("expected error for non-suricata event")
	}
}

func TestSuricataDecoderHTTP(t *testing.T) {
	d := &SuricataDecoder{}
	input := []byte(`{"timestamp":"2024-01-15T10:30:45.123456789-0700","event_type":"http","src_ip":"10.0.0.5","dest_ip":"93.184.216.34","http":{"hostname":"example.com","url":"/path","http_method":"GET","status":200,"length":1234}}`)

	evt, err := d.Decode(input)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	if v, ok := evt.Fields["http_hostname"]; !ok || v != "example.com" {
		t.Errorf("expected http_hostname=example.com, got %v", v)
	}
	v, ok := evt.Fields["http_status"]
	if !ok {
		t.Fatal("expected http_status field")
	}
	// JSON numbers can be float64 or int depending on decoder
	switch n := v.(type) {
	case float64:
		if n != 200 {
			t.Errorf("expected http_status=200, got %v", v)
		}
	case int:
		if n != 200 {
			t.Errorf("expected http_status=200, got %v", v)
		}
	default:
		t.Errorf("expected numeric http_status, got %T=%v", v, v)
	}
}

func TestSuricataDecoderTLS(t *testing.T) {
	d := &SuricataDecoder{}
	input := []byte(`{"timestamp":"2024-01-15T10:30:45.999999999+0000","event_type":"tls","src_ip":"10.0.0.5","dest_ip":"93.184.216.34","tls":{"sni":"example.com","subject":"CN=example.com","version":"TLSv1.3"}}`)

	evt, err := d.Decode(input)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	if v, ok := evt.Fields["tls_sni"]; !ok || v != "example.com" {
		t.Errorf("expected tls_sni=example.com, got %v", v)
	}
}
