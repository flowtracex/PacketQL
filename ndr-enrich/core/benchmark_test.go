package core

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"
)

// ── Performance Benchmarks ──────────────────────────────

// BenchmarkNormalize measures normalization throughput
func BenchmarkNormalize(b *testing.B) {
	rules := map[string]NormalizationRule{
		"conn": {
			Source: "zeek",
			Promote: map[string]string{
				"ts":        "event_time",
				"id.orig_h": "src_ip",
				"id.resp_h": "dst_ip",
				"id.orig_p": "src_port",
				"id.resp_p": "dst_port",
				"uid":       "flow_id",
				"proto":     "protocol",
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
			"resp_bytes": float64(5678),
		},
		Raw: `{"ts":1700000000.123}`,
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = normalizer.Normalize(zeekLog)
	}
}

// BenchmarkEnrich measures enrichment throughput
func BenchmarkEnrich(b *testing.B) {
	enricher := NewEnricher()

	event := &NormalizedEvent{
		EventTime:     1700000000000,
		SrcIP:         "192.168.1.100",
		DstIP:         "8.8.8.8",
		SrcPort:       50000,
		DstPort:       443,
		Protocol:      "tcp",
		EnrichTime:    true,
		EnrichNetwork: true,
		LogType:       "conn",
		ZeekFields:    map[string]interface{}{},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = enricher.Enrich(event)
	}
}

// BenchmarkClassifyAsset measures classification throughput
func BenchmarkClassifyAsset(b *testing.B) {
	profile := &AssetProfile{
		Vendor:  "Cisco Systems, Inc.",
		ConnIn:  100,
		ConnOut: 50,
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = classifyAsset(profile)
	}
}

// BenchmarkTransformToKafkaOutput measures Kafka transform throughput
func BenchmarkTransformToKafkaOutput(b *testing.B) {
	event := makeConnEvent("192.168.1.100", "8.8.8.8", 50000, 443)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = transformToKafkaOutput(event)
	}
}

// BenchmarkIsPrivateIP measures IP classification throughput
func BenchmarkIsPrivateIP(b *testing.B) {
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = isPrivateIP("192.168.1.100")
		_ = isPrivateIP("8.8.8.8")
	}
}

// BenchmarkFullPipeline measures normalize+enrich+transform throughput
func BenchmarkFullPipeline(b *testing.B) {
	rules := map[string]NormalizationRule{
		"conn": {
			Source: "zeek",
			Promote: map[string]string{
				"ts":        "event_time",
				"id.orig_h": "src_ip",
				"id.resp_h": "dst_ip",
				"id.orig_p": "src_port",
				"id.resp_p": "dst_port",
				"uid":       "flow_id",
				"proto":     "protocol",
			},
			Static: map[string]string{
				"event_type":  "network_connection",
				"event_class": "network",
			},
			Enrich: &EnrichConfig{Time: true, Network: true},
		},
	}

	normalizer := NewNormalizer(rules)
	enricher := NewEnricher()

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
			"resp_bytes": float64(5678),
		},
		Raw: `{"ts":1700000000.123}`,
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		normalized, err := normalizer.Normalize(zeekLog)
		if err != nil {
			b.Fatal(err)
		}
		enriched := enricher.Enrich(normalized)
		_ = transformToKafkaOutput(enriched)
	}
}

// ── Stress Tests ────────────────────────────────────────

// TestStress_NormalizeEnrich processes 100K events and reports throughput
func TestStress_NormalizeEnrich(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping stress test in short mode")
	}

	rules := map[string]NormalizationRule{
		"conn": {
			Source: "zeek",
			Promote: map[string]string{
				"ts":        "event_time",
				"id.orig_h": "src_ip",
				"id.resp_h": "dst_ip",
				"id.orig_p": "src_port",
				"id.resp_p": "dst_port",
				"uid":       "flow_id",
				"proto":     "protocol",
			},
			Static: map[string]string{
				"event_type":  "network_connection",
				"event_class": "network",
			},
			Enrich: &EnrichConfig{Time: true, Network: true},
		},
	}

	normalizer := NewNormalizer(rules)
	enricher := NewEnricher()

	const eventCount = 100_000
	start := time.Now()

	for i := 0; i < eventCount; i++ {
		zeekLog := &ZeekLog{
			LogType: "conn",
			Data: map[string]interface{}{
				"ts":         1700000000.123 + float64(i),
				"id.orig_h":  fmt.Sprintf("10.0.%d.%d", i/256, i%256),
				"id.resp_h":  "8.8.8.8",
				"id.orig_p":  float64(50000 + i%10000),
				"id.resp_p":  float64(443),
				"uid":        fmt.Sprintf("uid-%d", i),
				"proto":      "tcp",
				"conn_state": "SF",
				"orig_bytes": float64(i * 100),
				"resp_bytes": float64(i * 200),
			},
			Raw: fmt.Sprintf(`{"ts":%f}`, 1700000000.123+float64(i)),
		}

		normalized, err := normalizer.Normalize(zeekLog)
		if err != nil {
			t.Fatalf("normalize event %d: %v", i, err)
		}
		enriched := enricher.Enrich(normalized)
		_ = transformToKafkaOutput(enriched)
	}

	elapsed := time.Since(start)
	eps := float64(eventCount) / elapsed.Seconds()

	t.Logf("✅ Stress test: %d events in %v (%.0f EPS)", eventCount, elapsed, eps)

	// Assert minimum throughput — pipeline should handle 50K+ EPS single-threaded
	if eps < 50000 {
		t.Errorf("Throughput %.0f EPS is below 50,000 EPS threshold", eps)
	}
}

// TestStress_ParquetWrite writes 10K events to Parquet and verifies output
func TestStress_ParquetWrite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping stress test in short mode")
	}

	tmpDir := t.TempDir()
	input := make(chan *EnrichedEvent, 100)
	writer := NewParquetWriter("conn", WriterConfig{
		BasePath:         tmpDir,
		FilePrefix:       "stress",
		FlushBufferMB:    16,
		FlushIntervalSec: 300,
		FlushEventCount:  5000, // Flush every 5K events
	}, input)

	const eventCount = 10_000
	events := make([]interface{}, 0, eventCount)
	for i := 0; i < eventCount; i++ {
		ev := makeConnEvent(
			fmt.Sprintf("10.0.%d.%d", i/256, i%256),
			"8.8.8.8",
			int32(50000+i%10000),
			443,
		)
		converted := writer.convertEvent(ev)
		if converted != nil {
			events = append(events, converted)
		}
	}

	start := time.Now()
	ctx := context.Background()
	writer.writeParquetFile(ctx, events)
	elapsed := time.Since(start)

	// Verify
	parquetFiles := findParquetFiles(t, tmpDir)
	if len(parquetFiles) == 0 {
		t.Fatal("No Parquet files written in stress test")
	}

	stat, _ := os.Stat(parquetFiles[0])
	writeMBps := float64(stat.Size()) / (1024 * 1024) / elapsed.Seconds()

	t.Logf("✅ Parquet stress: %d events → %s (%.2f MB, %.1f MB/s, %v)",
		eventCount, parquetFiles[0], float64(stat.Size())/(1024*1024), writeMBps, elapsed)

	if stat.Size() < 10000 {
		t.Errorf("Parquet file too small for %d events: %d bytes", eventCount, stat.Size())
	}
}

// TestStress_ClassifyAsset classifies 100K profiles and reports throughput
func TestStress_ClassifyAsset(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping stress test in short mode")
	}

	vendors := []string{
		"VMware, Inc.", "Cisco Systems", "Juniper Networks",
		"Hikvision Digital", "Apple, Inc.", "Dell Technologies",
		"", // unknown vendor
	}

	const profileCount = 100_000
	start := time.Now()

	for i := 0; i < profileCount; i++ {
		p := &AssetProfile{
			Vendor:      vendors[i%len(vendors)],
			ConnIn:      int64(i % 200),
			ConnOut:     int64(i % 100),
			SSHSessions: int64(i % 20),
		}
		_ = classifyAsset(p)
	}

	elapsed := time.Since(start)
	ops := float64(profileCount) / elapsed.Seconds()
	t.Logf("✅ Classification stress: %d profiles in %v (%.0f ops/s)", profileCount, elapsed, ops)
}
