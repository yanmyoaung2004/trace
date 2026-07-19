package siem

import (
	"encoding/json"
	"strings"
	"testing"
)

const realEVTXSample = `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/><EventID>4798</EventID><Version>0</Version><Level>0</Level><Task>13824</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='2026-07-17T18:11:28.9827703Z'/><EventRecordID>4309232</EventRecordID><Correlation ActivityID='{982e88d4-15a5-0002-5e8a-2e98a515dd01}'/><Execution ProcessID='1788' ThreadID='3096'/><Channel>Security</Channel><Computer>YMA</Computer><Security/></System><EventData><Data Name='TargetUserName'>Guest</Data><Data Name='TargetDomainName'>YMA</Data></EventData></Event>`

const evtx4625Sample = `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4625</EventID><Level>0</Level><Channel>Security</Channel><Computer>DESKTOP-123</Computer><TimeCreated SystemTime='2026-07-18T10:00:00.0000000Z'/></System><EventData><Data Name='TargetUserName'>admin</Data><Data Name='WorkstationName'>DESKTOP-123</Data><Data Name='IpAddress'>10.0.0.5</Data></EventData></Event>`

func TestEVTXDecoderRealData(t *testing.T) {
	decoder := &EVTXDecoder{}
	event, err := decoder.Decode([]byte(realEVTXSample))
	if err != nil {
		t.Fatalf("Decode real EVTX: %v", err)
	}

	if event == nil {
		t.Fatal("expected event, got nil")
	}

	t.Logf("Source: %s", event.Source)
	t.Logf("Severity: %d", event.Severity)
	t.Logf("Tags: %v", event.Tags)

	fieldsJSON, _ := json.MarshalIndent(event.Fields, "", "  ")
	t.Logf("Fields: %s", string(fieldsJSON))

	fields := event.Fields
	if fields["event_id"] != "4798" {
		t.Errorf("expected event_id=4798, got %v", fields["event_id"])
	}
	if fields["computer"] != "YMA" {
		t.Errorf("expected computer=YMA, got %v", fields["computer"])
	}
	if fields["provider"] != "Microsoft-Windows-Security-Auditing" {
		t.Errorf("expected provider=Microsoft-Windows-Security-Auditing, got %v", fields["provider"])
	}
	if fields["TargetUserName"] != "Guest" {
		t.Errorf("expected TargetUserName=Guest, got %v", fields["TargetUserName"])
	}

	if !strings.Contains(strings.Join(event.Tags, ","), "windows") {
		t.Errorf("expected 'windows' tag, got %v", event.Tags)
	}
}

func TestEVTXDecoder4625(t *testing.T) {
	decoder := &EVTXDecoder{}
	event, err := decoder.Decode([]byte(evtx4625Sample))
	if err != nil {
		t.Fatalf("Decode 4625 EVTX: %v", err)
	}

	if event == nil {
		t.Fatal("expected event, got nil")
	}

	t.Logf("Source: %s", event.Source)
	t.Logf("Severity: %d", event.Severity)
	t.Logf("Tags: %v", event.Tags)

	fields := event.Fields
	if fields["event_id"] != "4625" {
		t.Errorf("expected event_id=4625, got %v", fields["event_id"])
	}

	hasAuthFailure := false
	for _, tag := range event.Tags {
		if tag == "auth_failure" {
			hasAuthFailure = true
			break
		}
	}
	if !hasAuthFailure {
		t.Errorf("expected auth_failure tag for 4625, got %v", event.Tags)
	}

	if event.Severity < 3 {
		t.Errorf("expected severity >= 3 for 4625, got %d", event.Severity)
	}
}

func TestEVTXDecoderNonEvent(t *testing.T) {
	decoder := &EVTXDecoder{}
	_, err := decoder.Decode([]byte(`{"not": "an event"}`))
	if err == nil {
		t.Fatal("expected error for non-EVTX input")
	}
}

func TestEVTXDecoderEmpty(t *testing.T) {
	decoder := &EVTXDecoder{}
	_, err := decoder.Decode([]byte(``))
	if err == nil {
		t.Fatal("expected error for empty input")
	}
}

func TestEVTXDecoderBulkRealData(t *testing.T) {
	decoder := &EVTXDecoder{}
	events := strings.Split(realEVTXSample, "<Event")
	for i := 1; i < len(events); i++ {
		data := []byte("<Event" + events[i])
		event, err := decoder.Decode(data)
		if err != nil {
			t.Logf("Event %d parse error: %v", i, err)
			continue
		}
		t.Logf("Event %d: ID=%v, Computer=%v", i, event.Fields["event_id"], event.Fields["computer"])
	}
}
