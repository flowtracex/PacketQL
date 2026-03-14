package core

import (
	"testing"
)

func TestNormalize_ConnLog(t *testing.T) {
	rules := map[string]NormalizationRule{
		"conn": {
			Source: "zeek",
			Promote: map[string]string{
				"ts":       "event_time",
				"id.orig_h": "src_ip",
				"id.resp_h": "dst_ip",
				"id.orig_p": "src_port",
				"id.resp_p": "dst_port",
				"uid":       "flow_id",
				"proto":     "protocol",
				"conn_state": "conn_state",
			},
			Static: map[string]string{
				"event_type":  "network_connection",
				"event_class": "network",
			},
			Enrich: &EnrichConfig{Time: true, Network: true},
		},
	}

	normalizer := NewNormalizer(rules)

	zeekLog := &ZeekLog{
		LogType: "conn",
		Data: map[string]interface{}{
			"ts":         1700000000.123,
			"id.orig_h":  "192.168.1.100",
			"id.resp_h":  "8.8.8.8",
			"id.orig_p":  float64(50000),
			"id.resp_p":  float64(443),
			"uid":        "CYfWP91bIN6TIPM0e",
			"proto":      "tcp",
			"conn_state": "SF",
			"orig_bytes": float64(1234),
		},
		Raw: `{"ts":1700000000.123}`,
	}

	event, err := normalizer.Normalize(zeekLog)
	if err != nil {
		t.Fatalf("Normalize() error: %v", err)
	}

	if event.LogType != "conn" {
		t.Errorf("LogType = %q, want conn", event.LogType)
	}
	if event.SrcIP != "192.168.1.100" {
		t.Errorf("SrcIP = %q, want 192.168.1.100", event.SrcIP)
	}
	if event.DstIP != "8.8.8.8" {
		t.Errorf("DstIP = %q, want 8.8.8.8", event.DstIP)
	}
	if event.DstPort != 443 {
		t.Errorf("DstPort = %d, want 443", event.DstPort)
	}
	if event.EventType != "network_connection" {
		t.Errorf("EventType = %q, want network_connection", event.EventType)
	}
	if !event.EnrichTime {
		t.Error("EnrichTime should be true")
	}
	if !event.EnrichNetwork {
		t.Error("EnrichNetwork should be true")
	}
	// Verify ZeekFields preserved
	if event.ZeekFields["orig_bytes"] != float64(1234) {
		t.Errorf("ZeekFields[orig_bytes] = %v, want 1234", event.ZeekFields["orig_bytes"])
	}
}

func TestNormalize_UnknownLogType(t *testing.T) {
	normalizer := NewNormalizer(map[string]NormalizationRule{})

	zeekLog := &ZeekLog{
		LogType: "unknown_type",
		Data:    map[string]interface{}{},
	}

	_, err := normalizer.Normalize(zeekLog)
	if err == nil {
		t.Error("Normalize() should return error for unknown log type")
	}
}

func TestNormalize_MissingOptionalFields(t *testing.T) {
	rules := map[string]NormalizationRule{
		"dns": {
			Source: "zeek",
			Promote: map[string]string{
				"ts":       "event_time",
				"id.orig_h": "src_ip",
				"id.resp_h": "dst_ip",
			},
			Static: map[string]string{
				"event_type": "dns_query",
			},
		},
	}

	normalizer := NewNormalizer(rules)

	// Minimal log — missing most fields
	zeekLog := &ZeekLog{
		LogType: "dns",
		Data: map[string]interface{}{
			"ts":        1700000000.0,
			"id.orig_h": "10.0.0.1",
		},
	}

	event, err := normalizer.Normalize(zeekLog)
	if err != nil {
		t.Fatalf("Normalize() error: %v", err)
	}

	if event.SrcIP != "10.0.0.1" {
		t.Errorf("SrcIP = %q, want 10.0.0.1", event.SrcIP)
	}
	// DstIP should be empty (not in data)
	if event.DstIP != "" {
		t.Errorf("DstIP = %q, want empty", event.DstIP)
	}
}
