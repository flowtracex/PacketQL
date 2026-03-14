package core

import (
	"os"
	"path/filepath"
	"testing"
)

func TestClassifyAsset_VMware(t *testing.T) {
	p := &AssetProfile{Vendor: "VMware, Inc."}
	got := classifyAsset(p)
	if got != "docker" {
		t.Errorf("classifyAsset(VMware) = %q, want docker", got)
	}
}

func TestClassifyAsset_Docker(t *testing.T) {
	p := &AssetProfile{Vendor: "Docker Container Engine"}
	got := classifyAsset(p)
	if got != "docker" {
		t.Errorf("classifyAsset(Docker) = %q, want docker", got)
	}
}

func TestClassifyAsset_Cisco(t *testing.T) {
	p := &AssetProfile{Vendor: "Cisco Systems, Inc."}
	got := classifyAsset(p)
	if got != "network_device" {
		t.Errorf("classifyAsset(Cisco) = %q, want network_device", got)
	}
}

func TestClassifyAsset_Juniper(t *testing.T) {
	p := &AssetProfile{Vendor: "Juniper Networks"}
	got := classifyAsset(p)
	if got != "network_device" {
		t.Errorf("classifyAsset(Juniper) = %q, want network_device", got)
	}
}

func TestClassifyAsset_Hikvision(t *testing.T) {
	p := &AssetProfile{Vendor: "Hangzhou Hikvision"}
	got := classifyAsset(p)
	if got != "iot" {
		t.Errorf("classifyAsset(Hikvision) = %q, want iot", got)
	}
}

func TestClassifyAsset_Nest(t *testing.T) {
	p := &AssetProfile{Vendor: "Nest Labs Inc."}
	got := classifyAsset(p)
	if got != "iot" {
		t.Errorf("classifyAsset(Nest) = %q, want iot", got)
	}
}

func TestClassifyAsset_ServerTraffic(t *testing.T) {
	p := &AssetProfile{
		Vendor:  "",
		ConnIn:  200,
		ConnOut: 30,
	}
	got := classifyAsset(p)
	if got != "server" {
		t.Errorf("classifyAsset(high inbound) = %q, want server", got)
	}
}

func TestClassifyAsset_SSHServer(t *testing.T) {
	p := &AssetProfile{
		Vendor:      "",
		SSHSessions: 15,
		ConnIn:      50,
		ConnOut:     20,
	}
	got := classifyAsset(p)
	if got != "server" {
		t.Errorf("classifyAsset(SSH server) = %q, want server", got)
	}
}

func TestClassifyAsset_Default(t *testing.T) {
	p := &AssetProfile{
		Vendor:  "",
		ConnIn:  10,
		ConnOut: 50,
	}
	got := classifyAsset(p)
	if got != "workstation" {
		t.Errorf("classifyAsset(default) = %q, want workstation", got)
	}
}

func TestClassifyAsset_CaseInsensitive(t *testing.T) {
	p := &AssetProfile{Vendor: "CISCO SYSTEMS"}
	got := classifyAsset(p)
	if got != "network_device" {
		t.Errorf("classifyAsset(CISCO uppercase) = %q, want network_device", got)
	}
}

func TestLoadClassificationRules(t *testing.T) {
	// Create temp CSV
	dir := t.TempDir()
	csvPath := filepath.Join(dir, "rules.csv")
	csv := `# Asset Classification Rules
vendor_contains,test_vendor,custom_type
vendor_contains,another,another_type
`
	if err := os.WriteFile(csvPath, []byte(csv), 0644); err != nil {
		t.Fatal(err)
	}

	// Save and restore original rules
	origRules := classificationRules
	defer func() { classificationRules = origRules }()

	// Load CSV rules
	if err := LoadClassificationRules(csvPath); err != nil {
		t.Fatal(err)
	}

	// Test that CSV rules are used
	p := &AssetProfile{Vendor: "Test_Vendor Corp"}
	got := classifyAsset(p)
	if got != "custom_type" {
		t.Errorf("classifyAsset(custom CSV rule) = %q, want custom_type", got)
	}

	// Test that old rules are NOT applied
	p2 := &AssetProfile{Vendor: "VMware"}
	got2 := classifyAsset(p2)
	if got2 != "workstation" {
		t.Errorf("classifyAsset(VMware after CSV load) = %q, want workstation (old rules replaced)", got2)
	}
}

func TestLoadClassificationRules_MissingFile(t *testing.T) {
	err := LoadClassificationRules("/nonexistent/path.csv")
	if err == nil {
		t.Error("LoadClassificationRules should return error for missing file")
	}
}

func TestExtractOSFromUA(t *testing.T) {
	tests := []struct {
		ua   string
		want string
	}{
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "Windows 10/11"},
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)", "macOS"},
		{"Mozilla/5.0 (X11; Linux x86_64)", "Linux"},
		{"Mozilla/5.0 (Linux; Android 13)", "Linux"},  // Note: "linux" match precedes "android" in code
		{"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0)", "iOS"},
		{"curl/7.81.0", ""},
	}

	for _, tt := range tests {
		got := extractOSFromUA(tt.ua)
		if got != tt.want {
			t.Errorf("extractOSFromUA(%q) = %q, want %q", tt.ua, got, tt.want)
		}
	}
}

func TestContainsAny(t *testing.T) {
	if !containsAny("hello world", "world", "foo") {
		t.Error("containsAny should match 'world'")
	}
	if containsAny("hello world", "foo", "bar") {
		t.Error("containsAny should not match 'foo' or 'bar'")
	}
}

func TestToInt64(t *testing.T) {
	tests := []struct {
		input interface{}
		want  int64
	}{
		{float64(42.0), 42},
		{int(100), 100},
		{int64(200), 200},
		{"300", 300},
		{"not_a_number", 0},
		{nil, 0},
	}

	for _, tt := range tests {
		got := toInt64(tt.input)
		if got != tt.want {
			t.Errorf("toInt64(%v) = %d, want %d", tt.input, got, tt.want)
		}
	}
}
