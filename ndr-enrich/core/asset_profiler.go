package core

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// AssetProfilerConfig holds asset profiler settings
type AssetProfilerConfig struct {
	Enabled             bool `json:"enabled"`
	SyncIntervalSeconds int  `json:"sync_interval_seconds"`
	MaxProfiles         int  `json:"max_profiles_in_memory"`
}

// AssetProfile represents a single asset's live profile
type AssetProfile struct {
	IP        string
	MAC       string
	Hostname  string
	AssetType string
	FirstSeen int64 // epoch ms
	LastSeen  int64 // epoch ms

	// Dataset-enriched fields (from Redis lookups)
	Vendor         string // MAC OUI → vendor name (e.g. "Apple, Inc.")
	OSHint         string // DHCP fingerprint or JA3 → OS (e.g. "Windows 11")
	AppFingerprint string // JA3 hash → app name (e.g. "Chrome 120")

	// Aggregate counters
	TotalEvents int64
	BytesOut    int64
	BytesIn     int64

	// Protocol counters
	DNSQueries     int64
	HTTPRequests   int64
	SSLConnections int64
	SSHSessions    int64
	ConnOut        int64
	ConnIn         int64

	// Unique peer tracking (Go-side, flush count to Redis)
	uniqueDstIPs map[string]struct{}
	uniqueSrcIPs map[string]struct{}

	dirty bool
}

// AssetProfiler maintains real-time asset profiles from enriched events
type AssetProfiler struct {
	profiles map[string]*AssetProfile // keyed by asset_id (from identity resolver)
	redis    *RedisClient
	resolver *IdentityResolver
	input    <-chan *EnrichedEvent
	config   AssetProfilerConfig
	mu       sync.RWMutex

	// Metrics
	profileCount  int64
	syncCount     int64
	eventsHandled int64
}

// NewAssetProfiler creates a new asset profiler
func NewAssetProfiler(cfg AssetProfilerConfig, redisClient *RedisClient, resolver *IdentityResolver, input <-chan *EnrichedEvent) *AssetProfiler {
	return &AssetProfiler{
		profiles: make(map[string]*AssetProfile, 10000),
		redis:    redisClient,
		resolver: resolver,
		input:    input,
		config:   cfg,
	}
}

// GetMetrics returns profiler metrics (thread-safe)
func (ap *AssetProfiler) GetMetrics() (profileCount, syncCount, eventsHandled int64) {
	ap.mu.RLock()
	defer ap.mu.RUnlock()
	return int64(len(ap.profiles)), ap.syncCount, ap.eventsHandled
}

// Start begins the profiler goroutine
func (ap *AssetProfiler) Start(ctx context.Context) error {
	logger := GetLogger()
	logger.Info("asset_profiler", "starting", fmt.Sprintf("sync_interval=%ds max_profiles=%d",
		ap.config.SyncIntervalSeconds, ap.config.MaxProfiles))

	syncInterval := time.Duration(ap.config.SyncIntervalSeconds) * time.Second
	if syncInterval <= 0 {
		syncInterval = 5 * time.Second
	}
	ticker := time.NewTicker(syncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// Final sync on shutdown
			ap.syncToRedis(ctx)
			return nil

		case <-ticker.C:
			ap.syncToRedis(ctx)

		case event, ok := <-ap.input:
			if !ok {
				ap.syncToRedis(ctx)
				return nil
			}
			// Process DHCP events for identity registration first
			if ap.resolver != nil {
				ap.resolver.ProcessEnrichedEvent(event)
			}
			ap.processEvent(event)
		}
	}
}

// processEvent updates the asset profile for both src and dst IPs
func (ap *AssetProfiler) processEvent(event *EnrichedEvent) {
	ap.mu.Lock()
	defer ap.mu.Unlock()

	ap.eventsHandled++
	now := time.Now().UnixMilli()

	// Update source IP profile (internal unicast assets only)
	if isTrackableAssetIP(event.SrcIP) {
		srcKey := ap.resolveProfileKey(event.SrcIP)
		if srcKey != "" {
			srcProfile := ap.getOrCreateProfile(srcKey, now)
			srcProfile.LastSeen = now
			srcProfile.TotalEvents++
			srcProfile.dirty = true

			// Set IP on profile (may change over time)
			srcProfile.IP = event.SrcIP

			// Outbound connection from this IP
			srcProfile.ConnOut++

			// Track unique destination
			if isTrackableAssetIP(event.DstIP) {
				if srcProfile.uniqueDstIPs == nil {
					srcProfile.uniqueDstIPs = make(map[string]struct{})
				}
				srcProfile.uniqueDstIPs[event.DstIP] = struct{}{}
			}

			// Protocol counters
			ap.incrementProtocolCounter(srcProfile, event.LogType)

			// Extract bytes from conn logs
			if event.LogType == "conn" {
				if origBytes, ok := event.ZeekFields["orig_bytes"]; ok {
					srcProfile.BytesOut += toInt64(origBytes)
				}
				if respBytes, ok := event.ZeekFields["resp_bytes"]; ok {
					srcProfile.BytesIn += toInt64(respBytes)
				}
			}

			// Extract metadata from richer log types
			ap.extractMetadata(srcProfile, event)
		}
	}

	// Update destination IP profile (internal unicast assets only)
	if isTrackableAssetIP(event.DstIP) {
		dstKey := ap.resolveProfileKey(event.DstIP)
		if dstKey != "" {
			dstProfile := ap.getOrCreateProfile(dstKey, now)
			dstProfile.LastSeen = now
			dstProfile.TotalEvents++
			dstProfile.ConnIn++
			dstProfile.dirty = true

			// Set IP on profile
			dstProfile.IP = event.DstIP

			// Track unique source
			if isTrackableAssetIP(event.SrcIP) {
				if dstProfile.uniqueSrcIPs == nil {
					dstProfile.uniqueSrcIPs = make(map[string]struct{})
				}
				dstProfile.uniqueSrcIPs[event.SrcIP] = struct{}{}
			}
		}
	}
}

// resolveProfileKey returns the profile key for an IP.
// If identity resolver is available, uses asset_id as the key (stable across IP changes).
// Otherwise, falls back to IP-based keying.
func (ap *AssetProfiler) resolveProfileKey(ip string) string {
	if !isTrackableAssetIP(ip) {
		return ""
	}
	if ap.resolver != nil {
		if assetID := ap.resolver.GetOrCreateAssetIDForIP(ip); assetID != "" {
			return assetID
		}
	}
	return ""
}

// getOrCreateProfile returns existing profile or creates a new one
func (ap *AssetProfiler) getOrCreateProfile(key string, nowMs int64) *AssetProfile {
	profile, exists := ap.profiles[key]
	if !exists {
		profile = &AssetProfile{
			AssetType:    "unknown",
			FirstSeen:    nowMs,
			LastSeen:     nowMs,
			uniqueDstIPs: make(map[string]struct{}),
			uniqueSrcIPs: make(map[string]struct{}),
			dirty:        true,
		}
		ap.profiles[key] = profile
	}
	return profile
}

// incrementProtocolCounter increments the right counter based on log type
func (ap *AssetProfiler) incrementProtocolCounter(profile *AssetProfile, logType string) {
	switch logType {
	case "dns":
		profile.DNSQueries++
	case "http":
		profile.HTTPRequests++
	case "ssl":
		profile.SSLConnections++
	case "ssh":
		profile.SSHSessions++
	}
}

// extractMetadata pulls rich metadata from specific log types
func (ap *AssetProfiler) extractMetadata(profile *AssetProfile, event *EnrichedEvent) {
	ctx := context.Background()

	switch event.LogType {
	case "dhcp":
		// DHCP gives us MAC + hostname
		if mac, ok := event.ZeekFields["mac"].(string); ok && mac != "" {
			profile.MAC = mac
			// Look up MAC vendor from OUI dataset in Redis
			if profile.Vendor == "" && len(mac) >= 8 {
				prefix := mac[:8] // "AA:BB:CC"
				vendr, err := ap.redis.client.HGet(ctx, "ndr:ds:oui:"+prefix, "vendor").Result()
				if err == nil && vendr != "" {
					profile.Vendor = vendr
				}
			}
		}
		if hostname, ok := event.ZeekFields["host_name"].(string); ok && hostname != "" {
			profile.Hostname = hostname
		}

	case "ssl":
		// JA3 fingerprint → app identification
		if ja3, ok := event.ZeekFields["ja3"].(string); ok && ja3 != "" && profile.AppFingerprint == "" {
			app, err := ap.redis.client.HGet(ctx, "ndr:ds:ja3:"+ja3, "app").Result()
			if err == nil && app != "" {
				profile.AppFingerprint = app
			}
		}

	case "kerberos":
		// Kerberos gives us hostname via client field
		if client, ok := event.ZeekFields["client"].(string); ok && client != "" && profile.Hostname == "" {
			profile.Hostname = client
		}

	case "ntlm":
		// NTLM gives us hostname via hostname field
		if hostname, ok := event.ZeekFields["hostname"].(string); ok && hostname != "" {
			profile.Hostname = hostname
		}

	case "http":
		// User-Agent can hint at OS
		if ua, ok := event.ZeekFields["user_agent"].(string); ok && ua != "" && profile.OSHint == "" {
			profile.OSHint = extractOSFromUA(ua)
		}
	}
}

// ClassificationRule represents a single vendor → asset_type mapping
type ClassificationRule struct {
	MatchType  string // "vendor_contains" or "traffic_ratio"
	MatchValue string // vendor substring to match
	AssetType  string // resulting asset type
}

// Global classification rules (loaded from CSV or defaults)
var classificationRules []ClassificationRule
var classificationRulesLoaded bool

// defaultClassificationRules are the hardcoded fallback rules
var defaultClassificationRules = []ClassificationRule{
	{"vendor_contains", "vmware", "docker"},
	{"vendor_contains", "docker", "docker"},
	{"vendor_contains", "kubernetes", "docker"},
	{"vendor_contains", "container", "docker"},
	{"vendor_contains", "cisco", "network_device"},
	{"vendor_contains", "juniper", "network_device"},
	{"vendor_contains", "arista", "network_device"},
	{"vendor_contains", "palo alto", "network_device"},
	{"vendor_contains", "fortinet", "network_device"},
	{"vendor_contains", "ubiquiti", "network_device"},
	{"vendor_contains", "hikvision", "iot"},
	{"vendor_contains", "axis", "iot"},
	{"vendor_contains", "dahua", "iot"},
	{"vendor_contains", "honeywell", "iot"},
	{"vendor_contains", "nest", "iot"},
	{"vendor_contains", "ring", "iot"},
}

func init() {
	// Start with defaults; overridden if LoadClassificationRules succeeds
	classificationRules = defaultClassificationRules
}

// LoadClassificationRules reads vendor → asset_type rules from a CSV file.
// Format: match_type,match_value,asset_type (lines starting with # are comments)
func LoadClassificationRules(csvPath string) error {
	data, err := os.ReadFile(csvPath)
	if err != nil {
		return err
	}

	var rules []ClassificationRule
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ",", 3)
		if len(parts) < 3 {
			continue
		}
		rules = append(rules, ClassificationRule{
			MatchType:  strings.TrimSpace(parts[0]),
			MatchValue: strings.TrimSpace(parts[1]),
			AssetType:  strings.TrimSpace(parts[2]),
		})
	}

	if len(rules) > 0 {
		classificationRules = rules
		classificationRulesLoaded = true
	}
	return nil
}

// classifyAsset determines role from observed traffic patterns + vendor hints.
// Uses CSV-loaded rules if available, otherwise falls back to defaults.
func classifyAsset(p *AssetProfile) string {
	vendor := strings.ToLower(p.Vendor)

	// Vendor-based classification (from rules loaded at startup)
	if vendor != "" {
		for _, rule := range classificationRules {
			if rule.MatchType == "vendor_contains" && strings.Contains(vendor, rule.MatchValue) {
				return rule.AssetType
			}
		}
	}

	// Traffic-based classification (always hardcoded — CSV rules are optional)
	if p.ConnIn > p.ConnOut*3 && p.ConnIn > 50 {
		return "server"
	}
	if p.SSHSessions > 10 && p.ConnIn > p.ConnOut {
		return "server"
	}

	return "workstation"
}

// containsAny checks if s contains any of the substrings
func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// extractOSFromUA extracts a simple OS hint from User-Agent string
func extractOSFromUA(ua string) string {
	ual := strings.ToLower(ua)
	switch {
	case strings.Contains(ual, "windows nt 10"):
		return "Windows 10/11"
	case strings.Contains(ual, "windows nt 6.3"):
		return "Windows 8.1"
	case strings.Contains(ual, "windows nt 6.1"):
		return "Windows 7"
	case strings.Contains(ual, "mac os x"):
		return "macOS"
	case strings.Contains(ual, "linux"):
		return "Linux"
	case strings.Contains(ual, "android"):
		return "Android"
	case strings.Contains(ual, "iphone") || strings.Contains(ual, "ipad"):
		return "iOS"
	}
	return ""
}

// syncToRedis batch writes all dirty profiles to Redis
func (ap *AssetProfiler) syncToRedis(ctx context.Context) {
	ap.mu.Lock()

	// Count dirty profiles for early exit
	dirtyCount := 0
	for _, profile := range ap.profiles {
		if profile.dirty {
			dirtyCount++
		}
	}

	if dirtyCount == 0 {
		ap.mu.Unlock()
		return
	}

	logger := GetLogger()

	// Batch write using Redis pipeline
	pipe := ap.redis.Pipeline()

	for profileKey, p := range ap.profiles {
		if !p.dirty {
			continue
		}
		p.dirty = false

		// Use the profile key (asset_id or IP) as the Redis key suffix
		key := fmt.Sprintf("ndr:assets:profile:%s", profileKey)

		// Classify on every sync
		if p.AssetType == "unknown" || p.AssetType == "workstation" {
			p.AssetType = classifyAsset(p)
			// Update identity resolver with the classified type
			if ap.resolver != nil {
				ap.resolver.UpdateAssetType(profileKey, p.AssetType)
			}
		}

		// Main profile hash
		pipe.HSet(ctx, key, map[string]interface{}{
			"ip":               p.IP,
			"mac":              p.MAC,
			"hostname":         p.Hostname,
			"asset_type":       p.AssetType,
			"vendor":           p.Vendor,
			"os_hint":          p.OSHint,
			"app_fingerprint":  p.AppFingerprint,
			"first_seen":       strconv.FormatInt(p.FirstSeen, 10),
			"last_seen":        strconv.FormatInt(p.LastSeen, 10),
			"total_events":     strconv.FormatInt(p.TotalEvents, 10),
			"unique_dst_count": strconv.Itoa(len(p.uniqueDstIPs)),
			"unique_src_count": strconv.Itoa(len(p.uniqueSrcIPs)),
		})

		// Protocol counters hash
		counterKey := fmt.Sprintf("ndr:assets:counters:%s", profileKey)
		pipe.HSet(ctx, counterKey, map[string]interface{}{
			"dns_queries":     strconv.FormatInt(p.DNSQueries, 10),
			"http_requests":   strconv.FormatInt(p.HTTPRequests, 10),
			"ssl_connections": strconv.FormatInt(p.SSLConnections, 10),
			"ssh_sessions":    strconv.FormatInt(p.SSHSessions, 10),
			"conn_out":        strconv.FormatInt(p.ConnOut, 10),
			"conn_in":         strconv.FormatInt(p.ConnIn, 10),
			"bytes_out":       strconv.FormatInt(p.BytesOut, 10),
			"bytes_in":        strconv.FormatInt(p.BytesIn, 10),
		})

		// MAC index
		if p.MAC != "" {
			pipe.Set(ctx, fmt.Sprintf("ndr:assets:mac_index:%s", p.MAC), p.IP, 0)
		}

		// Role set — use profileKey (asset_id) instead of IP
		if p.AssetType != "unknown" {
			pipe.SAdd(ctx, fmt.Sprintf("ndr:assets:role:%s", p.AssetType), profileKey)
		}
	}

	// Execute pipeline
	_, err := pipe.Exec(ctx)
	if err != nil {
		logger.Error("asset_profiler", "redis sync failed", fmt.Sprintf("error=%v profiles=%d", err, dirtyCount))
		ap.mu.Unlock()
		return
	}

	ap.syncCount++
	ap.mu.Unlock()

	logger.Info("asset_profiler", fmt.Sprintf("synced %d profiles to Redis", dirtyCount),
		fmt.Sprintf("total_profiles=%d", dirtyCount))
}

// toInt64 converts an interface{} to int64 safely
func toInt64(v interface{}) int64 {
	switch val := v.(type) {
	case float64:
		return int64(val)
	case int:
		return int64(val)
	case int64:
		return val
	case string:
		if i, err := strconv.ParseInt(val, 10, 64); err == nil {
			return i
		}
	}
	return 0
}
