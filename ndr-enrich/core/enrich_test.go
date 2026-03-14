package core

import (
	"testing"
)

func TestIsPrivateIP_RFC1918(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"192.168.1.1", true},
		{"192.168.0.100", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"172.32.0.1", false},  // Just outside 172.16/12
		{"", false},
		{"not-an-ip", false},
		{"::1", false},  // IPv6 loopback — not handled as private
	}

	for _, tt := range tests {
		got := isPrivateIP(tt.ip)
		if got != tt.want {
			t.Errorf("isPrivateIP(%q) = %v, want %v", tt.ip, got, tt.want)
		}
	}
}

func TestDeriveDirection(t *testing.T) {
	tests := []struct {
		srcPrivate bool
		dstPrivate bool
		want       string
	}{
		{true, false, "outbound"},   // private → public
		{false, true, "inbound"},    // public → private
		{true, true, "internal"},    // private → private
		{false, false, "external"},  // public → public
	}

	for _, tt := range tests {
		got := deriveDirection(tt.srcPrivate, tt.dstPrivate)
		if got != tt.want {
			t.Errorf("deriveDirection(%v, %v) = %q, want %q",
				tt.srcPrivate, tt.dstPrivate, got, tt.want)
		}
	}
}

func TestPortToService(t *testing.T) {
	tests := []struct {
		port int32
		want string
	}{
		{80, "http"},
		{443, "https"},
		{22, "ssh"},
		{53, "dns"},
		{25, "smtp"},
		{3306, "mysql"},
		{3389, "rdp"},
		{8080, "http-proxy"},
		{12345, "unknown"},
		{0, "unknown"},
	}

	for _, tt := range tests {
		got := portToService(tt.port)
		if got != tt.want {
			t.Errorf("portToService(%d) = %q, want %q", tt.port, got, tt.want)
		}
	}
}

func TestProtocolToService(t *testing.T) {
	tests := []struct {
		protocol string
		want     string
	}{
		{"tcp", "tcp"},
		{"udp", "udp"},
		{"icmp", "icmp"},
		{"quic", "quic"},  // Unknown protocol returned as-is
	}

	for _, tt := range tests {
		got := protocolToService(tt.protocol)
		if got != tt.want {
			t.Errorf("protocolToService(%q) = %q, want %q", tt.protocol, got, tt.want)
		}
	}
}

func TestEnrich_TimeEnrichment(t *testing.T) {
	enricher := NewEnricher()

	event := &NormalizedEvent{
		EventTime:     1700000000000, // Nov 14, 2023 ~22:13 UTC
		EnrichTime:    true,
		EnrichNetwork: false,
		LogType:       "conn",
		ZeekFields:    map[string]interface{}{},
	}

	enriched := enricher.Enrich(event)

	if enriched.EventYear != 2023 {
		t.Errorf("EventYear = %d, want 2023", enriched.EventYear)
	}
	if enriched.EventMonth != 11 {
		t.Errorf("EventMonth = %d, want 11", enriched.EventMonth)
	}
}

func TestEnrich_NetworkEnrichment(t *testing.T) {
	enricher := NewEnricher()

	event := &NormalizedEvent{
		SrcIP:         "192.168.1.100",
		DstIP:         "8.8.8.8",
		DstPort:       443,
		EnrichTime:    false,
		EnrichNetwork: true,
		LogType:       "conn",
		ZeekFields:    map[string]interface{}{},
	}

	enriched := enricher.Enrich(event)

	if !enriched.SrcIPIsPrivate {
		t.Error("SrcIPIsPrivate should be true for 192.168.1.100")
	}
	if enriched.DstIPIsPrivate {
		t.Error("DstIPIsPrivate should be false for 8.8.8.8")
	}
	if enriched.Direction != "outbound" {
		t.Errorf("Direction = %q, want outbound", enriched.Direction)
	}
	if enriched.Service != "https" {
		t.Errorf("Service = %q, want https", enriched.Service)
	}
}

func TestEnrich_NoEnrichmentFlags(t *testing.T) {
	enricher := NewEnricher()

	event := &NormalizedEvent{
		SrcIP:         "192.168.1.100",
		DstIP:         "8.8.8.8",
		EventTime:     1700000000000,
		EnrichTime:    false,
		EnrichNetwork: false,
		LogType:       "conn",
		ZeekFields:    map[string]interface{}{},
	}

	enriched := enricher.Enrich(event)

	if enriched.EventYear != 0 {
		t.Errorf("EventYear = %d, want 0 (time enrichment disabled)", enriched.EventYear)
	}
	if enriched.Direction != "" {
		t.Errorf("Direction = %q, want empty (network enrichment disabled)", enriched.Direction)
	}
}
