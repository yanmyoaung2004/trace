package siem

import (
	"testing"
)

func BenchmarkFullPipelineSSHBruteForce(b *testing.B) {
	e := New(SIEMConfig{})
	e.ruleEngine.LoadDefault()
	e.ruleEngine.LoadBuiltinYAML()

	alertCount := 0
	e.OnAlert(func(a *Alert) { alertCount++ })

	logLine := []byte(`<34>Jul 18 10:00:00 myserver sshd[1234]: Failed password for root from 10.0.0.5 port 22 ssh2`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.ingest(logLine, "bench")
	}
}

func BenchmarkFullPipelineHTTPError(b *testing.B) {
	e := New(SIEMConfig{})
	e.ruleEngine.LoadDefault()
	e.ruleEngine.LoadBuiltinYAML()

	e.OnAlert(func(a *Alert) {})

	logLine := []byte(`192.168.1.1 - - [18/Jul/2026:10:00:00 +0000] "GET /index.html HTTP/1.1" 500 1234`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.ingest(logLine, "bench")
	}
}

func BenchmarkFullPipelineEVTX(b *testing.B) {
	e := New(SIEMConfig{})
	e.ruleEngine.LoadDefault()
	e.ruleEngine.LoadBuiltinYAML()

	e.OnAlert(func(a *Alert) {})

	logLine := []byte(`<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4625</EventID><Level>0</Level><Channel>Security</Channel><Computer>DESKTOP-123</Computer></System></Event>`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.ingest(logLine, "bench")
	}
}

func BenchmarkFullPipelineK8sAudit(b *testing.B) {
	e := New(SIEMConfig{})
	e.ruleEngine.LoadDefault()
	e.ruleEngine.LoadBuiltinYAML()

	e.OnAlert(func(a *Alert) {})

	logLine := []byte(`{"kind":"Event","apiVersion":"audit.k8s.io/v1","auditID":"test-123","level":"RequestResponse","stage":"ResponseComplete","requestURI":"/api/v1/namespaces/default/secrets","verb":"get","user":{"username":"admin","groups":["system:masters"]},"objectRef":{"resource":"secrets","namespace":"default","name":"my-secret"},"sourceIPs":["10.0.0.1"]}`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.ingest(logLine, "bench")
	}
}

func BenchmarkRuleMatching(b *testing.B) {
	e := New(SIEMConfig{})
	e.ruleEngine.LoadDefault()
	e.ruleEngine.LoadBuiltinYAML()

	event := &Event{
		Tags: []string{"sshd", "auth_failure"},
		Fields: map[string]any{
			"client_ip": "10.0.0.5",
			"message":   "Failed password for root",
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.ruleEngine.Evaluate(event)
	}
}

func BenchmarkAllDecoders(b *testing.B) {
	tests := []struct {
		name string
		data []byte
	}{
		{"syslog_ssh", []byte(`<34>Jul 18 10:00:00 myserver sshd[1234]: Failed password for root from 10.0.0.5 port 22 ssh2`)},
		{"apache_500", []byte(`192.168.1.1 - - [18/Jul/2026:10:00:00 +0000] "GET /index.html HTTP/1.1" 500 1234`)},
		{"json_login", []byte(`{"timestamp":"2026-07-18T10:00:00Z","event":"login","user":"admin","severity":3}`)},
		{"evtx_security", []byte(`<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4625</EventID><Channel>Security</Channel><Computer>DESKTOP-123</Computer></System></Event>`)},
		{"k8s_audit", []byte(`{"kind":"Event","apiVersion":"audit.k8s.io/v1","auditID":"test","level":"RequestResponse","stage":"ResponseComplete","requestURI":"/api/v1/secrets","verb":"get","user":{"username":"admin","groups":["system:masters"]},"objectRef":{"resource":"secrets"}}`)},
	}

	for _, tt := range tests {
		b.Run(tt.name, func(b *testing.B) {
			decoders := []Decoder{&AutoDecoder{}, &JSONDecoder{}, &ApacheDecoder{}, &SyslogDecoder{}, &EVTXDecoder{}, &K8sAuditDecoder{}, &WindowsEventDecoder{}, &WazuhDecoder{}}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				for _, d := range decoders {
					d.Decode(tt.data)
				}
			}
		})
	}
}
