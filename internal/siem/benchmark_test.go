package siem

import (
	"testing"
)

func BenchmarkJSONDecoder(b *testing.B) {
	d := &JSONDecoder{}
	raw := []byte(`{"timestamp":"2026-07-18T12:00:00Z","event":"login","user":"admin","ip":"10.0.0.1","severity":3}`)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.Decode(raw)
	}
}

func BenchmarkApacheDecoder(b *testing.B) {
	d := &ApacheDecoder{}
	raw := []byte(`192.168.1.1 - - [18/Jul/2026:12:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234`)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.Decode(raw)
	}
}

func BenchmarkApacheDecoder_Error(b *testing.B) {
	d := &ApacheDecoder{}
	raw := []byte(`10.0.0.5 - - [18/Jul/2026:12:00:00 +0000] "POST /api/login HTTP/1.1" 500 200`)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.Decode(raw)
	}
}

func BenchmarkSyslogDecoder(b *testing.B) {
	d := &SyslogDecoder{}
	raw := []byte(`<34>Jul 18 12:00:00 server sshd[1234]: Failed password for root from 10.0.0.5 port 22 ssh2`)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.Decode(raw)
	}
}

func BenchmarkAutoDecoder_JSON(b *testing.B) {
	d := &AutoDecoder{}
	raw := []byte(`{"level":"error","msg":"connection refused","addr":"10.0.0.5:443"}`)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.Decode(raw)
	}
}

func BenchmarkAutoDecoder_Syslog(b *testing.B) {
	d := &AutoDecoder{}
	raw := []byte(`<34>Jul 18 12:00:00 server sshd[1234]: Failed password for root from 10.0.0.5 port 22 ssh2`)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.Decode(raw)
	}
}

func BenchmarkAutoDecoder_Apache(b *testing.B) {
	d := &AutoDecoder{}
	raw := []byte(`10.0.0.5 - - [18/Jul/2026:12:00:00 +0000] "POST /api HTTP/1.1" 500 200`)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.Decode(raw)
	}
}

func BenchmarkWindowsEventDecoder(b *testing.B) {
	d := &WindowsEventDecoder{}
	raw := []byte(`2026-07-18 12:00:00,4625,Microsoft-Windows-Security-Auditing,S-1-0-0,SYSTEM,10.0.0.5,LOGON,N/A`)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.Decode(raw)
	}
}
