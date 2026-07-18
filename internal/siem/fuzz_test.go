package siem

import (
	"testing"
)

func FuzzAutoDecoder(f *testing.F) {
	seeds := []string{
		`{"event":"login","user":"admin"}`,
		`192.168.1.1 - - [18/Jul/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 1234`,
		`<34>Jul 18 12:00:00 server sshd[1234]: Failed password for root from 10.0.0.5`,
		`2026-07-18 12:00:00,4625,Microsoft-Windows-Security-Auditing,SYSTEM,10.0.0.5`,
		`plain text log line`,
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		d := &AutoDecoder{}
		evt, err := d.Decode([]byte(raw))
		if err != nil {
			return
		}
		if evt != nil && evt.Source == "" {
			t.Error("decoded event with empty source")
		}
	})
}

func FuzzJSONDecoder(f *testing.F) {
	seeds := []string{
		`{"key":"value"}`,
		`{"nested":{"a":1}}`,
		`[1,2,3]`,
		`not json`,
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		d := &JSONDecoder{}
		evt, err := d.Decode([]byte(raw))
		if err != nil {
			return
		}
		_ = evt
	})
}

func FuzzApacheDecoder(f *testing.F) {
	seeds := []string{
		`192.168.1.1 - - [18/Jul/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 1234`,
		`10.0.0.5 - - [18/Jul/2026:12:00:00 +0000] "POST /api HTTP/1.1" 500 200`,
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		d := &ApacheDecoder{}
		evt, err := d.Decode([]byte(raw))
		if err != nil {
			return
		}
		_ = evt
	})
}

func FuzzSyslogDecoder(f *testing.F) {
	seeds := []string{
		`<34>Jul 18 12:00:00 server sshd[1234]: Failed password for root`,
		`<14>Jul 18 12:00:00 server sudo: session opened for root`,
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		d := &SyslogDecoder{}
		evt, err := d.Decode([]byte(raw))
		if err != nil {
			return
		}
		_ = evt
	})
}

func FuzzWindowsEventDecoder(f *testing.F) {
	seeds := []string{
		`2026-07-18 12:00:00,4625,Microsoft-Windows-Security-Auditing,SYSTEM,10.0.0.5,LOGON,N/A`,
		`2026-07-18 12:00:00,4688,Microsoft-Windows-Security-Auditing,SYSTEM,cmd.exe,PROCESS,1234`,
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		d := &WindowsEventDecoder{}
		evt, err := d.Decode([]byte(raw))
		if err != nil {
			return
		}
		_ = evt
	})
}
