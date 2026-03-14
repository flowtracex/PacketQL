package core

import (
	"net/netip"
	"strings"
)

// isTrackableAssetIP returns true only for internal, unicast IPv4 addresses.
// Asset inventory should not include public IPs, multicast, loopback, link-local,
// unspecified, reserved, or broadcast-like addresses.
func isTrackableAssetIP(ip string) bool {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return false
	}

	addr, err := netip.ParseAddr(ip)
	if err != nil || !addr.Is4() {
		return false
	}

	if addr.IsLoopback() || addr.IsMulticast() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsUnspecified() {
		return false
	}

	octets := addr.As4()

	// Reject 0.0.0.0/8 and 240.0.0.0/4 (includes 255.255.255.255 broadcast range).
	if octets[0] == 0 || octets[0] >= 240 {
		return false
	}

	// Asset inventory is internal-only.
	return isPrivateIP(ip)
}
