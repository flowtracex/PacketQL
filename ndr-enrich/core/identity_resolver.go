package core

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// IdentityResolverConfig holds configuration for the identity resolver
type IdentityResolverConfig struct {
	DefaultLeaseTTL int `json:"default_lease_ttl_seconds"` // Default TTL for IP→MAC mappings (seconds)
}

// AssetIdentity represents a resolved asset identity
type AssetIdentity struct {
	AssetID   string
	AssetType string
	Hostname  string
	MAC       string
}

// IdentityResolver provides stable UUID-based asset identity resolution.
// It maintains an IP→MAC→asset_id lookup chain:
//   - DHCP events register IP→MAC and MAC→asset_id mappings
//   - Non-DHCP events look up src_ip → MAC → asset_id
//   - MAC is the primary anchor; hostname is the fallback for randomized MACs
//
// In-memory caches (ipToMAC, macToAsset, hostnameToAsset) are backed by the local state store
// for persistence. The hot-path ResolveIP() reads from cache with store fallback.
type IdentityResolver struct {
	store  *StateStore
	config IdentityResolverConfig

	// In-memory caches (hot path — avoid state store round-trips per event)
	ipToMAC         map[string]string         // IP → MAC
	ipToAsset       map[string]string         // IP → asset_id fallback (for non-DHCP internal hosts)
	macToAsset      map[string]string         // MAC → asset_id
	hostnameToAsset map[string]string         // hostname → asset_id (fallback)
	assetProfiles   map[string]*AssetIdentity // asset_id → identity summary
	mu              sync.RWMutex

	// Metrics
	resolveHits   int64
	resolveMisses int64
	dhcpEvents    int64
	conflicts     int64
}

// NewIdentityResolver creates a new identity resolver
func NewIdentityResolver(cfg IdentityResolverConfig, stateStore *StateStore) *IdentityResolver {
	if cfg.DefaultLeaseTTL <= 0 {
		cfg.DefaultLeaseTTL = 3600 // 1 hour default
	}

	return &IdentityResolver{
		store:           stateStore,
		config:          cfg,
		ipToMAC:         make(map[string]string, 10000),
		ipToAsset:       make(map[string]string, 10000),
		macToAsset:      make(map[string]string, 10000),
		hostnameToAsset: make(map[string]string, 5000),
		assetProfiles:   make(map[string]*AssetIdentity, 10000),
	}
}

// isLocallyAdministeredMAC checks if a MAC has the locally administered bit set
// (bit 1 of first octet = 1). This indicates MAC randomization (iOS/Android).
// Format expected: "AA:BB:CC:DD:EE:FF"
func isLocallyAdministeredMAC(mac string) bool {
	if len(mac) < 2 {
		return false
	}
	// Parse first hex char pair
	firstByte := mac[:2]
	var b byte
	for i, c := range firstByte {
		var nibble byte
		switch {
		case c >= '0' && c <= '9':
			nibble = byte(c - '0')
		case c >= 'a' && c <= 'f':
			nibble = byte(c-'a') + 10
		case c >= 'A' && c <= 'F':
			nibble = byte(c-'A') + 10
		default:
			return false
		}
		if i == 0 {
			b = nibble << 4
		} else {
			b |= nibble
		}
	}
	// Bit 1 (second-least-significant bit of first octet) = locally administered
	return (b & 0x02) != 0
}

// ProcessDHCP handles a DHCP event, updating IP→MAC and MAC→asset_id mappings.
// This is the core identity registration path.
//
// It handles:
//   - New device: generates UUID, creates MAC→asset_id mapping
//   - IP change: same MAC gets new IP, old IP→MAC mapping removed
//   - IP conflict: different MAC claims same IP, old asset loses that IP
//   - Hostname-based merge: for MAC randomization, uses hostname as fallback anchor
func (ir *IdentityResolver) ProcessDHCP(mac, ip, hostname string, leaseTimeSec int) {
	if mac == "" || ip == "" {
		return
	}

	ir.mu.Lock()
	defer ir.mu.Unlock()

	ir.dhcpEvents++
	logger := GetLogger()

	mac = strings.ToUpper(mac)
	hostname = strings.ToLower(strings.TrimSpace(hostname))

	// --- Step 1: Handle IP conflict (is someone else currently using this IP?) ---
	if oldMAC, exists := ir.ipToMAC[ip]; exists && oldMAC != mac {
		ir.conflicts++
		// Old MAC loses this IP
		if oldAssetID, ok := ir.macToAsset[oldMAC]; ok {
			logger.Info("identity", "ip_conflict_eviction",
				fmt.Sprintf("ip=%s old_mac=%s old_asset=%s new_mac=%s", ip, oldMAC, oldAssetID, mac))
			// Remove IP from old asset's known IPs in the state store
			ir.removeIPFromAsset(oldAssetID, ip)
		}
	}

	// --- Step 2: Register IP→MAC mapping ---
	ir.ipToMAC[ip] = mac

	// Persist to state store with TTL
	if ir.store != nil {
		ttl := leaseTimeSec
		if ttl <= 0 {
			ttl = ir.config.DefaultLeaseTTL
		}
		ctx := context.Background()
		ir.store.SetWithTTL(ctx, fmt.Sprintf("ndr:assets:ip_to_mac:%s", ip), mac, time.Duration(ttl)*time.Second)
	}

	// --- Step 3: Resolve MAC → asset_id ---
	assetID := ir.resolveOrCreateAssetID(mac, hostname)

	// If this IP had a non-DHCP fallback asset_id already, keep that ID stable.
	if fallbackAssetID, ok := ir.ipToAsset[ip]; ok && fallbackAssetID != "" {
		if _, macKnown := ir.macToAsset[mac]; !macKnown {
			ir.macToAsset[mac] = fallbackAssetID
			assetID = fallbackAssetID
			if ir.store != nil {
				ctx := context.Background()
				ir.store.client.Set(ctx, fmt.Sprintf("ndr:assets:mac_to_asset:%s", mac), fallbackAssetID, 0)
			}
		}
	}

	ir.ipToAsset[ip] = assetID
	if ir.store != nil {
		ctx := context.Background()
		ir.store.client.Set(ctx, fmt.Sprintf("ndr:assets:ip_to_asset:%s", ip), assetID, 0)
	}

	// --- Step 4: Update asset profile ---
	identity, exists := ir.assetProfiles[assetID]
	if !exists {
		identity = &AssetIdentity{
			AssetID: assetID,
			MAC:     mac,
		}
		ir.assetProfiles[assetID] = identity
	}
	identity.MAC = mac
	if hostname != "" {
		identity.Hostname = hostname
	}

	// --- Step 5: Add IP to asset's known IPs in state store ---
	if ir.store != nil {
		ctx := context.Background()
		ir.store.SAdd(ctx, fmt.Sprintf("ndr:assets:profile:%s:ips", assetID), ip)
	}

	logger.Info("identity", "dhcp_registered",
		fmt.Sprintf("ip=%s mac=%s asset_id=%s hostname=%s lease=%ds",
			ip, mac, assetID, hostname, leaseTimeSec))
}

// resolveOrCreateAssetID finds or creates an asset_id for a MAC.
// For locally administered (randomized) MACs, falls back to hostname.
// Caller must hold ir.mu lock.
func (ir *IdentityResolver) resolveOrCreateAssetID(mac, hostname string) string {
	// Check MAC→asset_id first (primary anchor)
	if assetID, ok := ir.macToAsset[mac]; ok {
		// Update hostname mapping if we have one
		if hostname != "" {
			ir.hostnameToAsset[hostname] = assetID
			if ir.store != nil {
				ctx := context.Background()
				ir.store.client.Set(ctx, fmt.Sprintf("ndr:assets:hostname_to_asset:%s", hostname), assetID, 0)
			}
		}
		return assetID
	}

	// MAC not seen before — check if it's a randomized MAC with known hostname
	if isLocallyAdministeredMAC(mac) && hostname != "" {
		if assetID, ok := ir.hostnameToAsset[hostname]; ok {
			// Known hostname with randomized MAC — reuse existing asset_id
			ir.macToAsset[mac] = assetID
			if ir.store != nil {
				ctx := context.Background()
				ir.store.client.Set(ctx, fmt.Sprintf("ndr:assets:mac_to_asset:%s", mac), assetID, 0)
			}
			return assetID
		}
	}

	// Brand new device — generate short AST-NNNN asset_id
	var assetID string
	if ir.store != nil {
		ctx := context.Background()
		counter, err := ir.store.client.Incr(ctx, "ndr:assets:counter").Result()
		if err != nil {
			// Fallback to UUID if state store fails
			assetID = uuid.New().String()
		} else {
			assetID = fmt.Sprintf("AST-%04d", counter)
		}
	} else {
		assetID = uuid.New().String()
	}

	// Store MAC→asset_id
	ir.macToAsset[mac] = assetID
	if ir.store != nil {
		ctx := context.Background()
		ir.store.client.Set(ctx, fmt.Sprintf("ndr:assets:mac_to_asset:%s", mac), assetID, 0)
	}

	// Store hostname→asset_id if hostname is known
	if hostname != "" {
		ir.hostnameToAsset[hostname] = assetID
		if ir.store != nil {
			ctx := context.Background()
			ir.store.client.Set(ctx, fmt.Sprintf("ndr:assets:hostname_to_asset:%s", hostname), assetID, 0)
		}
	}

	return assetID
}

// removeIPFromAsset removes an IP from an asset's known IP set in the state store
// Caller must hold ir.mu lock.
func (ir *IdentityResolver) removeIPFromAsset(assetID, ip string) {
	if ir.store != nil {
		ctx := context.Background()
		ir.store.SRem(ctx, fmt.Sprintf("ndr:assets:profile:%s:ips", assetID), ip)
	}
}

// ResolveIP looks up an IP address and returns the associated asset identity.
// This is the hot-path function called for every event.
// Returns nil if the IP has no known identity (external IPs, unknown devices).
func (ir *IdentityResolver) ResolveIP(ip string) *AssetIdentity {
	if ip == "" {
		return nil
	}

	ir.mu.RLock()

	// Step 1: IP → MAC (in-memory cache)
	mac, ok := ir.ipToMAC[ip]
	if !ok {
		// Fallback: IP → asset_id (for non-DHCP internal hosts).
		if assetID, ok := ir.ipToAsset[ip]; ok && assetID != "" {
			identity, exists := ir.assetProfiles[assetID]
			if !exists {
				identity = &AssetIdentity{AssetID: assetID}
				ir.assetProfiles[assetID] = identity
			}
			ir.resolveHits++
			ir.mu.RUnlock()
			return identity
		}
		ir.mu.RUnlock()
		// Try store fallback
		identity := ir.resolveIPFromStore(ip)
		if identity != nil {
			ir.mu.Lock()
			ir.resolveHits++
			ir.mu.Unlock()
		} else {
			ir.mu.Lock()
			ir.resolveMisses++
			ir.mu.Unlock()
		}
		return identity
	}

	// Step 2: MAC → asset_id (in-memory cache)
	assetID, ok := ir.macToAsset[mac]
	if !ok {
		ir.mu.RUnlock()
		ir.mu.Lock()
		ir.resolveMisses++
		ir.mu.Unlock()
		return nil
	}

	// Step 3: Get identity summary
	identity, ok := ir.assetProfiles[assetID]
	if !ok {
		// Asset ID exists but no profile yet — create minimal one
		ir.mu.RUnlock()
		ir.mu.Lock()
		identity = &AssetIdentity{
			AssetID: assetID,
			MAC:     mac,
		}
		ir.assetProfiles[assetID] = identity
		ir.resolveHits++
		ir.mu.Unlock()
		return identity
	}

	ir.resolveHits++
	ir.mu.RUnlock()

	return identity
}

// resolveIPFromStore attempts to resolve an IP via state store when the in-memory cache misses.
// If successful, it populates the in-memory cache for future lookups.
func (ir *IdentityResolver) resolveIPFromStore(ip string) *AssetIdentity {
	if ir.store == nil {
		return nil
	}

	ctx := context.Background()

	// IP → MAC
	mac, err := ir.store.client.Get(ctx, fmt.Sprintf("ndr:assets:ip_to_mac:%s", ip)).Result()
	if err != nil || mac == "" {
		// Fallback: IP → asset_id for unresolved non-DHCP hosts.
		assetID, ferr := ir.store.client.Get(ctx, fmt.Sprintf("ndr:assets:ip_to_asset:%s", ip)).Result()
		if ferr != nil || assetID == "" {
			return nil
		}

		ir.mu.Lock()
		ir.ipToAsset[ip] = assetID
		identity, exists := ir.assetProfiles[assetID]
		if !exists {
			identity = &AssetIdentity{AssetID: assetID}
			ir.assetProfiles[assetID] = identity
		}
		ir.mu.Unlock()
		return identity
	}

	// MAC → asset_id
	assetID, err := ir.store.client.Get(ctx, fmt.Sprintf("ndr:assets:mac_to_asset:%s", mac)).Result()
	if err != nil || assetID == "" {
		return nil
	}

	// Populate in-memory cache
	ir.mu.Lock()
	ir.ipToMAC[ip] = mac
	ir.ipToAsset[ip] = assetID
	ir.macToAsset[mac] = assetID

	identity, exists := ir.assetProfiles[assetID]
	if !exists {
		identity = &AssetIdentity{
			AssetID: assetID,
			MAC:     mac,
		}
		ir.assetProfiles[assetID] = identity
	}
	ir.mu.Unlock()

	// Try to get asset_type from state store profile
	assetType, err := ir.store.client.HGet(ctx, fmt.Sprintf("ndr:assets:profile:%s", assetID), "asset_type").Result()
	if err == nil && assetType != "" {
		ir.mu.Lock()
		identity.AssetType = assetType
		ir.mu.Unlock()
	}

	return identity
}

// UpdateAssetType sets the asset_type for a given asset_id (called by asset profiler after classification)
func (ir *IdentityResolver) UpdateAssetType(assetID, assetType string) {
	if assetID == "" {
		return
	}
	ir.mu.Lock()
	defer ir.mu.Unlock()

	if identity, ok := ir.assetProfiles[assetID]; ok {
		identity.AssetType = assetType
	}
}

// ProcessEnrichedEvent extracts identity signals from an enriched event.
// For DHCP events, it registers the IP→MAC→asset_id mappings.
// For other events, it does nothing (resolution happens via ResolveIP).
func (ir *IdentityResolver) ProcessEnrichedEvent(event *EnrichedEvent) {
	if event.LogType != "dhcp" {
		return
	}

	// Extract DHCP fields
	mac := ""
	hostname := ""
	assignedIP := ""
	leaseTime := 0

	if m, ok := event.ZeekFields["mac"].(string); ok {
		mac = m
	}
	if h, ok := event.ZeekFields["host_name"].(string); ok {
		hostname = h
	}
	if ip, ok := event.ZeekFields["assigned_addr"].(string); ok {
		assignedIP = ip
	}
	if lt, ok := event.ZeekFields["lease_time"]; ok {
		leaseTime = int(toInt64(lt))
	}

	// Use client_addr as fallback if assigned_addr is empty
	if assignedIP == "" {
		if ip, ok := event.ZeekFields["client_addr"].(string); ok {
			assignedIP = ip
		}
	}

	if mac != "" && assignedIP != "" {
		ir.ProcessDHCP(mac, assignedIP, hostname, leaseTime)
	}
}

// GetAssetIDForIP returns just the asset_id for an IP (convenience for profiler keying)
func (ir *IdentityResolver) GetAssetIDForIP(ip string) string {
	identity := ir.ResolveIP(ip)
	if identity != nil {
		return identity.AssetID
	}
	return ""
}

// GetOrCreateAssetIDForIP returns a stable asset_id for an internal, trackable IP.
// It is used when DHCP/MAC data is missing so Asset IDs still stay system-generated.
func (ir *IdentityResolver) GetOrCreateAssetIDForIP(ip string) string {
	if !isTrackableAssetIP(ip) {
		return ""
	}

	if assetID := ir.GetAssetIDForIP(ip); assetID != "" {
		return assetID
	}

	ir.mu.Lock()
	defer ir.mu.Unlock()

	if assetID, ok := ir.ipToAsset[ip]; ok && assetID != "" {
		return assetID
	}

	var assetID string
	if ir.store != nil {
		ctx := context.Background()
		counter, err := ir.store.client.Incr(ctx, "ndr:assets:counter").Result()
		if err != nil {
			assetID = uuid.New().String()
		} else {
			assetID = fmt.Sprintf("AST-%04d", counter)
		}

		ir.store.client.Set(ctx, fmt.Sprintf("ndr:assets:ip_to_asset:%s", ip), assetID, 0)
		ir.store.SAdd(ctx, fmt.Sprintf("ndr:assets:profile:%s:ips", assetID), ip)
	} else {
		assetID = uuid.New().String()
	}

	ir.ipToAsset[ip] = assetID
	if _, exists := ir.assetProfiles[assetID]; !exists {
		ir.assetProfiles[assetID] = &AssetIdentity{AssetID: assetID}
	}

	return assetID
}

// GetMetrics returns resolver metrics (thread-safe)
func (ir *IdentityResolver) GetMetrics() (hits, misses, dhcpEvents, conflicts int64) {
	ir.mu.RLock()
	defer ir.mu.RUnlock()
	return ir.resolveHits, ir.resolveMisses, ir.dhcpEvents, ir.conflicts
}
