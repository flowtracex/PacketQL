package core

import "testing"

func TestIsTrackableAssetIP(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"192.168.1.10", true},
		{"10.1.2.3", true},
		{"172.16.9.8", true},
		{"8.8.8.8", false},
		{"255.255.255.255", false},
		{"255.255.255.2", false},
		{"0.0.0.1", false},
		{"224.0.0.5", false},
		{"169.254.1.2", false},
		{"127.0.0.1", false},
		{"", false},
		{"not-an-ip", false},
	}

	for _, tt := range tests {
		got := isTrackableAssetIP(tt.ip)
		if got != tt.want {
			t.Errorf("isTrackableAssetIP(%q) = %v, want %v", tt.ip, got, tt.want)
		}
	}
}
