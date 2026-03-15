package core

import (
	"testing"
)

// TestIdentityResolver tests use nil state store (pure in-memory mode)

func newTestResolver() *IdentityResolver {
	return NewIdentityResolver(IdentityResolverConfig{
		DefaultLeaseTTL: 3600,
	}, nil) // nil state store = in-memory only
}

func TestProcessDHCP_NewDevice(t *testing.T) {
	ir := newTestResolver()

	ir.ProcessDHCP("AA:BB:CC:DD:EE:FF", "10.1.1.50", "laptop-01", 3600)

	// Verify IP→MAC mapping
	ir.mu.RLock()
	mac, ok := ir.ipToMAC["10.1.1.50"]
	ir.mu.RUnlock()

	if !ok || mac != "AA:BB:CC:DD:EE:FF" {
		t.Errorf("ipToMAC[10.1.1.50] = %q, want AA:BB:CC:DD:EE:FF", mac)
	}

	// Verify MAC→asset_id was created
	ir.mu.RLock()
	assetID, ok := ir.macToAsset["AA:BB:CC:DD:EE:FF"]
	ir.mu.RUnlock()

	if !ok || assetID == "" {
		t.Error("macToAsset[AA:BB:CC:DD:EE:FF] should have an asset_id")
	}

	// Verify hostname→asset_id
	ir.mu.RLock()
	hostnameAsset, ok := ir.hostnameToAsset["laptop-01"]
	ir.mu.RUnlock()

	if !ok || hostnameAsset != assetID {
		t.Errorf("hostnameToAsset[laptop-01] = %q, want %q", hostnameAsset, assetID)
	}
}

func TestProcessDHCP_IPChange_SameMAC(t *testing.T) {
	ir := newTestResolver()

	// Register initial IP
	ir.ProcessDHCP("AA:BB:CC:DD:EE:FF", "10.1.1.50", "laptop-01", 3600)

	ir.mu.RLock()
	originalAssetID := ir.macToAsset["AA:BB:CC:DD:EE:FF"]
	ir.mu.RUnlock()

	// DHCP renews with new IP
	ir.ProcessDHCP("AA:BB:CC:DD:EE:FF", "10.1.1.75", "laptop-01", 3600)

	ir.mu.RLock()
	newAssetID := ir.macToAsset["AA:BB:CC:DD:EE:FF"]
	newMAC := ir.ipToMAC["10.1.1.75"]
	ir.mu.RUnlock()

	// Same MAC → same asset_id
	if newAssetID != originalAssetID {
		t.Errorf("asset_id changed on IP renewal: %q → %q", originalAssetID, newAssetID)
	}

	// New IP should map to same MAC
	if newMAC != "AA:BB:CC:DD:EE:FF" {
		t.Errorf("ipToMAC[10.1.1.75] = %q, want AA:BB:CC:DD:EE:FF", newMAC)
	}
}

func TestProcessDHCP_IPConflict(t *testing.T) {
	ir := newTestResolver()

	// Device A gets 10.1.1.50
	ir.ProcessDHCP("AA:AA:AA:AA:AA:AA", "10.1.1.50", "device-a", 3600)

	ir.mu.RLock()
	assetA := ir.macToAsset["AA:AA:AA:AA:AA:AA"]
	ir.mu.RUnlock()

	// Device B takes over 10.1.1.50 (IP conflict)
	ir.ProcessDHCP("BB:BB:BB:BB:BB:BB", "10.1.1.50", "device-b", 3600)

	ir.mu.RLock()
	assetB := ir.macToAsset["BB:BB:BB:BB:BB:BB"]
	currentMAC := ir.ipToMAC["10.1.1.50"]
	ir.mu.RUnlock()

	// IP should now point to Device B's MAC
	if currentMAC != "BB:BB:BB:BB:BB:BB" {
		t.Errorf("ipToMAC[10.1.1.50] = %q, want BB:BB:BB:BB:BB:BB", currentMAC)
	}

	// Device A and B should have different asset_ids
	if assetA == assetB {
		t.Error("Device A and B should have different asset_ids")
	}

	// Verify conflict was counted
	ir.mu.RLock()
	conflicts := ir.conflicts
	ir.mu.RUnlock()

	if conflicts != 1 {
		t.Errorf("conflicts = %d, want 1", conflicts)
	}
}

func TestResolveIP_Known(t *testing.T) {
	ir := newTestResolver()

	// Register via DHCP
	ir.ProcessDHCP("AA:BB:CC:DD:EE:FF", "10.1.1.50", "laptop-01", 3600)

	// Resolve
	identity := ir.ResolveIP("10.1.1.50")

	if identity == nil {
		t.Fatal("ResolveIP(10.1.1.50) returned nil")
	}
	if identity.AssetID == "" {
		t.Error("identity.AssetID should not be empty")
	}
	if identity.MAC != "AA:BB:CC:DD:EE:FF" {
		t.Errorf("identity.MAC = %q, want AA:BB:CC:DD:EE:FF", identity.MAC)
	}
	if identity.Hostname != "laptop-01" {
		t.Errorf("identity.Hostname = %q, want laptop-01", identity.Hostname)
	}
}

func TestResolveIP_Unknown(t *testing.T) {
	ir := newTestResolver()

	identity := ir.ResolveIP("10.99.99.99")
	if identity != nil {
		t.Errorf("ResolveIP(unknown) should return nil, got %+v", identity)
	}
}

func TestResolveIP_Empty(t *testing.T) {
	ir := newTestResolver()

	identity := ir.ResolveIP("")
	if identity != nil {
		t.Error("ResolveIP('') should return nil")
	}
}

func TestHostnameFallback_MACRandomization(t *testing.T) {
	ir := newTestResolver()

	// First connection with randomized MAC (locally administered bit set)
	// 02:xx is locally administered (bit 1 of first octet = 1)
	ir.ProcessDHCP("02:AA:BB:CC:DD:01", "10.1.1.50", "iphone-john", 3600)

	ir.mu.RLock()
	originalAssetID := ir.macToAsset["02:AA:BB:CC:DD:01"]
	ir.mu.RUnlock()

	// Second connection with DIFFERENT randomized MAC but SAME hostname
	ir.ProcessDHCP("06:AA:BB:CC:DD:02", "10.1.1.75", "iphone-john", 3600)

	ir.mu.RLock()
	newAssetID := ir.macToAsset["06:AA:BB:CC:DD:02"]
	ir.mu.RUnlock()

	// Should reuse the same asset_id because hostname matched
	if newAssetID != originalAssetID {
		t.Errorf("hostname fallback failed: different asset_ids %q vs %q", originalAssetID, newAssetID)
	}
}

func TestIsLocallyAdministeredMAC(t *testing.T) {
	tests := []struct {
		mac  string
		want bool
	}{
		{"02:AA:BB:CC:DD:EE", true},  // Bit 1 set
		{"06:AA:BB:CC:DD:EE", true},  // Bit 1 set
		{"0A:AA:BB:CC:DD:EE", true},  // Bit 1 set
		{"0E:AA:BB:CC:DD:EE", true},  // Bit 1 set
		{"00:AA:BB:CC:DD:EE", false}, // Bit 1 not set (global/universal)
		{"04:AA:BB:CC:DD:EE", false}, // Bit 1 not set
		{"AA:BB:CC:DD:EE:FF", true},  // 0xAA = 10101010, bit 1 = 1
		{"00:50:56:AA:BB:CC", false}, // VMware OUI (globally assigned)
		{"", false},
		{"X", false},
	}

	for _, tt := range tests {
		got := isLocallyAdministeredMAC(tt.mac)
		if got != tt.want {
			t.Errorf("isLocallyAdministeredMAC(%q) = %v, want %v", tt.mac, got, tt.want)
		}
	}
}

func TestProcessEnrichedEvent_DHCP(t *testing.T) {
	ir := newTestResolver()

	event := &EnrichedEvent{
		NormalizedEvent: &NormalizedEvent{
			LogType: "dhcp",
			ZeekFields: map[string]interface{}{
				"mac":           "AA:BB:CC:DD:EE:FF",
				"assigned_addr": "10.1.1.50",
				"host_name":     "workstation-01",
				"lease_time":    float64(7200),
			},
		},
	}

	ir.ProcessEnrichedEvent(event)

	// Verify registration happened
	identity := ir.ResolveIP("10.1.1.50")
	if identity == nil {
		t.Fatal("ResolveIP after DHCP event should not return nil")
	}
	if identity.MAC != "AA:BB:CC:DD:EE:FF" {
		t.Errorf("MAC = %q, want AA:BB:CC:DD:EE:FF", identity.MAC)
	}
}

func TestProcessEnrichedEvent_NonDHCP_NoOp(t *testing.T) {
	ir := newTestResolver()

	event := &EnrichedEvent{
		NormalizedEvent: &NormalizedEvent{
			LogType:    "conn",
			SrcIP:      "10.1.1.50",
			DstIP:      "8.8.8.8",
			ZeekFields: map[string]interface{}{},
		},
	}

	ir.ProcessEnrichedEvent(event)

	// Should not register anything
	identity := ir.ResolveIP("10.1.1.50")
	if identity != nil {
		t.Error("Non-DHCP event should not register identity")
	}
}

func TestUpdateAssetType(t *testing.T) {
	ir := newTestResolver()

	ir.ProcessDHCP("AA:BB:CC:DD:EE:FF", "10.1.1.50", "server-01", 3600)

	identity := ir.ResolveIP("10.1.1.50")
	if identity == nil {
		t.Fatal("identity should exist")
	}

	ir.UpdateAssetType(identity.AssetID, "server")

	// Re-resolve and check
	identity2 := ir.ResolveIP("10.1.1.50")
	if identity2.AssetType != "server" {
		t.Errorf("AssetType = %q, want server", identity2.AssetType)
	}
}

func TestGetMetrics(t *testing.T) {
	ir := newTestResolver()

	// Register and resolve
	ir.ProcessDHCP("AA:BB:CC:DD:EE:FF", "10.1.1.50", "test", 3600)
	ir.ResolveIP("10.1.1.50")   // hit
	ir.ResolveIP("10.99.99.99") // miss

	hits, misses, dhcpEvents, conflicts := ir.GetMetrics()

	if dhcpEvents != 1 {
		t.Errorf("dhcpEvents = %d, want 1", dhcpEvents)
	}
	if hits != 1 {
		t.Errorf("hits = %d, want 1", hits)
	}
	if misses != 1 {
		t.Errorf("misses = %d, want 1", misses)
	}
	if conflicts != 0 {
		t.Errorf("conflicts = %d, want 0", conflicts)
	}
}

func TestMultipleIPs_SameDevice(t *testing.T) {
	ir := newTestResolver()

	// Same MAC gets two different IPs (multi-homed or DHCP renewal)
	ir.ProcessDHCP("AA:BB:CC:DD:EE:FF", "10.1.1.50", "server-01", 3600)
	ir.ProcessDHCP("AA:BB:CC:DD:EE:FF", "10.2.2.50", "server-01", 3600)

	id1 := ir.ResolveIP("10.1.1.50")
	id2 := ir.ResolveIP("10.2.2.50")

	if id1 == nil || id2 == nil {
		t.Fatal("both IPs should resolve")
	}

	if id1.AssetID != id2.AssetID {
		t.Errorf("same MAC should give same asset_id: %q vs %q", id1.AssetID, id2.AssetID)
	}
}

func TestGetOrCreateAssetIDForIP_InternalFallback(t *testing.T) {
	ir := newTestResolver()

	id1 := ir.GetOrCreateAssetIDForIP("10.10.10.5")
	id2 := ir.GetOrCreateAssetIDForIP("10.10.10.5")
	if id1 == "" || id2 == "" {
		t.Fatal("expected non-empty asset ids")
	}
	if id1 != id2 {
		t.Fatalf("expected stable id for same ip, got %q and %q", id1, id2)
	}

	id3 := ir.GetOrCreateAssetIDForIP("10.10.10.6")
	if id3 == "" || id3 == id1 {
		t.Fatalf("expected distinct id for different ip, got id3=%q id1=%q", id3, id1)
	}
}

func TestGetOrCreateAssetIDForIP_RejectsNonTrackable(t *testing.T) {
	ir := newTestResolver()

	for _, ip := range []string{"8.8.8.8", "255.255.255.255", "127.0.0.1", ""} {
		if got := ir.GetOrCreateAssetIDForIP(ip); got != "" {
			t.Fatalf("expected empty asset id for %q, got %q", ip, got)
		}
	}
}
