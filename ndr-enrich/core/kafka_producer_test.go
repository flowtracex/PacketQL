package core

import (
	"encoding/json"
	"testing"
)

func TestTransformToKafkaOutput_ConnEvent(t *testing.T) {
	event := makeConnEvent("192.168.1.100", "8.8.8.8", 50000, 443)

	output := transformToKafkaOutput(event)

	if output.LogType != "conn" {
		t.Errorf("LogType = %q, want conn", output.LogType)
	}
	if output.SrcIP != "192.168.1.100" {
		t.Errorf("SrcIP = %q, want 192.168.1.100", output.SrcIP)
	}
	if output.DstIP != "8.8.8.8" {
		t.Errorf("DstIP = %q, want 8.8.8.8", output.DstIP)
	}
	if output.DstPort != 443 {
		t.Errorf("DstPort = %d, want 443", output.DstPort)
	}
	if output.Direction != "outbound" {
		t.Errorf("Direction = %q, want outbound", output.Direction)
	}
	if !output.SrcIPIsPrivate {
		t.Error("SrcIPIsPrivate should be true")
	}
	if output.DstIPIsPrivate {
		t.Error("DstIPIsPrivate should be false")
	}
	if output.LogSource != "zeek" {
		t.Errorf("LogSource = %q, want zeek", output.LogSource)
	}

	// Verify details map contains non-promoted fields
	if _, ok := output.Details["orig_bytes"]; !ok {
		t.Error("Details should contain orig_bytes")
	}
	if _, ok := output.Details["duration"]; !ok {
		t.Error("Details should contain duration")
	}

	// Verify promoted fields are NOT in details
	if _, ok := output.Details["ts"]; ok {
		t.Error("Details should NOT contain 'ts' (promoted field)")
	}
	if _, ok := output.Details["uid"]; ok {
		t.Error("Details should NOT contain 'uid' (promoted field)")
	}
}

func TestTransformToKafkaOutput_DNSEvent(t *testing.T) {
	event := makeDNSEvent("10.0.0.1", "8.8.8.8", "google.com", "A")

	output := transformToKafkaOutput(event)

	if output.LogType != "dns" {
		t.Errorf("LogType = %q, want dns", output.LogType)
	}
	if output.EventType != "dns_query" {
		t.Errorf("EventType = %q, want dns_query", output.EventType)
	}
	if output.Details["query"] != "google.com" {
		t.Errorf("Details[query] = %q, want google.com", output.Details["query"])
	}
}

func TestTransformToKafkaOutput_Serializable(t *testing.T) {
	event := makeConnEvent("10.0.0.1", "8.8.8.8", 50000, 80)
	output := transformToKafkaOutput(event)

	// Must serialize to JSON without error
	jsonData, err := json.Marshal(output)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	if len(jsonData) < 100 {
		t.Errorf("JSON output too small: %d bytes", len(jsonData))
	}

	// Must deserialize back
	var roundtrip KafkaOutputEvent
	if err := json.Unmarshal(jsonData, &roundtrip); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	if roundtrip.SrcIP != "10.0.0.1" {
		t.Errorf("Roundtrip SrcIP = %q, want 10.0.0.1", roundtrip.SrcIP)
	}
	if roundtrip.DstPort != 80 {
		t.Errorf("Roundtrip DstPort = %d, want 80", roundtrip.DstPort)
	}

	t.Logf("✅ JSON roundtrip: %d bytes", len(jsonData))
}

func TestTransformToKafkaOutput_EmptyFields(t *testing.T) {
	event := &EnrichedEvent{
		NormalizedEvent: &NormalizedEvent{
			LogType:    "conn",
			ZeekFields: map[string]interface{}{},
		},
	}

	output := transformToKafkaOutput(event)

	if output.LogType != "conn" {
		t.Errorf("LogType = %q, want conn", output.LogType)
	}
	if output.Details == nil {
		t.Error("Details should not be nil")
	}
}
