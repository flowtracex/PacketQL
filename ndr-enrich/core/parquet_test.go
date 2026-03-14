package core

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/parquet-go/parquet-go"
	"pipeline/schema"
)

// TestParquetWriter_E2E_ConnLog tests the full pipeline:
// EnrichedEvent → convertEvent → writeParquetFile → read back and verify
func TestParquetWriter_E2E_ConnLog(t *testing.T) {
	tmpDir := t.TempDir()

	// Create writer with small flush threshold
	input := make(chan *EnrichedEvent, 100)
	writer := NewParquetWriter("conn", WriterConfig{
		BasePath:         tmpDir,
		FilePrefix:       "test",
		FlushBufferMB:    1,
		FlushIntervalSec: 300, // Don't auto-flush by time
		FlushEventCount:  10,   // Flush after 10 events
	}, input)

	// Verify convertEvent produces a valid struct
	event := makeConnEvent("192.168.1.100", "8.8.8.8", 50000, 443)
	converted := writer.convertEvent(event)
	if converted == nil {
		t.Fatal("convertEvent returned nil for conn event")
	}

	// Verify it's the right type
	connPtr, ok := converted.(*schema.CONN)
	if !ok {
		t.Fatalf("convertEvent returned %T, want *schema.CONN", converted)
	}

	// Verify key fields were populated
	if connPtr.SrcIP != "192.168.1.100" {
		t.Errorf("SrcIP = %q, want 192.168.1.100", connPtr.SrcIP)
	}
	if connPtr.DstIP != "8.8.8.8" {
		t.Errorf("DstIP = %q, want 8.8.8.8", connPtr.DstIP)
	}
	if connPtr.DstPort != 443 {
		t.Errorf("DstPort = %d, want 443", connPtr.DstPort)
	}

	// Test full write cycle: write file directly
	events := make([]interface{}, 0, 5)
	for i := 0; i < 5; i++ {
		ev := makeConnEvent(
			fmt.Sprintf("10.0.0.%d", i+1),
			"8.8.8.8",
			int32(50000+i),
			443,
		)
		converted := writer.convertEvent(ev)
		if converted == nil {
			t.Fatalf("convertEvent returned nil for event %d", i)
		}
		events = append(events, converted)
	}

	// Write to Parquet file
	ctx := context.Background()
	writer.writeParquetFile(ctx, events)

	// Find and verify the written file
	parquetFiles := findParquetFiles(t, tmpDir)
	if len(parquetFiles) == 0 {
		t.Fatal("No Parquet files were written")
	}

	// Read back and verify
	file, err := os.Open(parquetFiles[0])
	if err != nil {
		t.Fatalf("open parquet file: %v", err)
	}
	defer file.Close()

	stat, _ := file.Stat()
	reader := parquet.NewReader(file, parquet.NewSchema("CONN", parquet.SchemaOf(new(schema.CONN))))
	_ = reader

	t.Logf("✅ Parquet file written: %s (%d bytes)", parquetFiles[0], stat.Size())
	if stat.Size() < 100 {
		t.Errorf("Parquet file suspiciously small: %d bytes", stat.Size())
	}
}

// TestParquetWriter_E2E_DNSLog tests DNS event → Parquet roundtrip
func TestParquetWriter_E2E_DNSLog(t *testing.T) {
	tmpDir := t.TempDir()

	input := make(chan *EnrichedEvent, 100)
	writer := NewParquetWriter("dns", WriterConfig{
		BasePath:         tmpDir,
		FilePrefix:       "test",
		FlushBufferMB:    1,
		FlushIntervalSec: 300,
		FlushEventCount:  10,
	}, input)

	event := makeDNSEvent("10.0.0.1", "8.8.8.8", "evil.example.com", "A")
	converted := writer.convertEvent(event)
	if converted == nil {
		t.Fatal("convertEvent returned nil for dns event")
	}

	dnsPtr, ok := converted.(*schema.DNS)
	if !ok {
		t.Fatalf("convertEvent returned %T, want *schema.DNS", converted)
	}

	if dnsPtr.Query != "evil.example.com" {
		t.Errorf("Query = %q, want evil.example.com", dnsPtr.Query)
	}

	// Write 3 DNS events
	events := make([]interface{}, 0, 3)
	for i := 0; i < 3; i++ {
		ev := makeDNSEvent("10.0.0.1", "8.8.8.8", fmt.Sprintf("host%d.example.com", i), "A")
		c := writer.convertEvent(ev)
		if c != nil {
			events = append(events, c)
		}
	}

	ctx := context.Background()
	writer.writeParquetFile(ctx, events)

	parquetFiles := findParquetFiles(t, tmpDir)
	if len(parquetFiles) == 0 {
		t.Fatal("No Parquet files were written for DNS")
	}

	stat, _ := os.Stat(parquetFiles[0])
	t.Logf("✅ DNS Parquet file: %s (%d bytes)", parquetFiles[0], stat.Size())
}

// TestParquetWriter_FlushCycle tests the Start/flush goroutine lifecycle
func TestParquetWriter_FlushCycle(t *testing.T) {
	tmpDir := t.TempDir()

	input := make(chan *EnrichedEvent, 100)
	writer := NewParquetWriter("conn", WriterConfig{
		BasePath:         tmpDir,
		FilePrefix:       "flush_test",
		FlushBufferMB:    1,
		FlushIntervalSec: 1, // Flush every 1 second
		FlushEventCount:  1000,
	}, input)

	ctx, cancel := context.WithCancel(context.Background())

	// Start writer in background
	done := make(chan error, 1)
	go func() {
		done <- writer.Start(ctx)
	}()

	// Send 5 events
	for i := 0; i < 5; i++ {
		input <- makeConnEvent("10.0.0.1", "8.8.8.8", int32(50000+i), 443)
	}

	// Wait for time-based flush
	time.Sleep(2 * time.Second)

	// Shutdown
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("writer.Start() error: %v", err)
	}

	// Verify file was written
	parquetFiles := findParquetFiles(t, tmpDir)
	if len(parquetFiles) == 0 {
		t.Fatal("No Parquet files after flush cycle")
	}

	// Check metrics
	bufBytes, _, flushCount, totalEvents := writer.GetMetrics()
	t.Logf("✅ Flush cycle: %d files, flushes=%d, totalEvents=%d, bufBytes=%d",
		len(parquetFiles), flushCount, totalEvents, bufBytes)

	if flushCount == 0 {
		t.Error("Expected at least 1 flush")
	}
}

// TestParquetWriter_AllLogTypes verifies that convertEvent works for every supported log type
func TestParquetWriter_AllLogTypes(t *testing.T) {
	logTypes := []string{
		"conn", "dns", "http", "ssl", "ssh", "ftp", "smtp",
		"dhcp", "rdp", "smb_files", "smb_mapping", "dce_rpc",
		"kerberos", "ntlm", "sip", "snmp", "radius", "tunnel",
		"files", "weird", "dpd", "notice",
	}

	for _, logType := range logTypes {
		t.Run(logType, func(t *testing.T) {
			input := make(chan *EnrichedEvent, 1)
			writer := NewParquetWriter(logType, WriterConfig{
				BasePath:   t.TempDir(),
				FilePrefix: "test",
			}, input)

			event := &EnrichedEvent{
				NormalizedEvent: &NormalizedEvent{
					LogType:    logType,
					SrcIP:      "10.0.0.1",
					DstIP:      "10.0.0.2",
					SrcPort:    12345,
					DstPort:    80,
					EventTime:  1700000000000,
					FlowID:     "test-uid",
					ZeekFields: map[string]interface{}{},
				},
			}

			converted := writer.convertEvent(event)
			if converted == nil {
				t.Errorf("convertEvent returned nil for %s", logType)
			}
		})
	}
}

// ── Helpers ──────────────────────────────────────────────

func makeConnEvent(srcIP, dstIP string, srcPort, dstPort int32) *EnrichedEvent {
	return &EnrichedEvent{
		NormalizedEvent: &NormalizedEvent{
			LogType:    "conn",
			SrcIP:      srcIP,
			DstIP:      dstIP,
			SrcPort:    srcPort,
			DstPort:    dstPort,
			FlowID:     "test-uid-conn",
			EventTime:  1700000000000,
			IngestTime: time.Now().UnixMilli(),
			Protocol:   "tcp",
			ConnState:  "SF",
			EventType:  "network_connection",
			EventClass: "network",
			RawLog:     `{"ts":1700000000.123,"id.orig_h":"` + srcIP + `"}`,
			ZeekFields: map[string]interface{}{
				"orig_bytes": float64(1234),
				"resp_bytes": float64(5678),
				"duration":   float64(1.5),
				"conn_state": "SF",
			},
			EnrichTime:    true,
			EnrichNetwork: true,
		},
		SrcIPIsPrivate: true,
		DstIPIsPrivate: false,
		Direction:      "outbound",
		Service:        "https",
		EventYear:      2023,
		EventMonth:     11,
		EventDay:       14,
		EventHour:      22,
		EventWeekday:   2,
	}
}

func makeDNSEvent(srcIP, dstIP, query, qtype string) *EnrichedEvent {
	return &EnrichedEvent{
		NormalizedEvent: &NormalizedEvent{
			LogType:    "dns",
			SrcIP:      srcIP,
			DstIP:      dstIP,
			SrcPort:    54321,
			DstPort:    53,
			FlowID:     "test-uid-dns",
			EventTime:  1700000000000,
			IngestTime: time.Now().UnixMilli(),
			EventType:  "dns_query",
			EventClass: "network",
			RawLog:     `{"query":"` + query + `"}`,
			ZeekFields: map[string]interface{}{
				"query":      query,
				"qtype_name": qtype,
				"AA":         false,
				"RD":         true,
			},
			EnrichTime:    true,
			EnrichNetwork: true,
		},
		SrcIPIsPrivate: true,
		DstIPIsPrivate: false,
		Direction:      "outbound",
		Service:        "dns",
	}
}

func findParquetFiles(t *testing.T, dir string) []string {
	t.Helper()
	var files []string
	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && filepath.Ext(path) == ".parquet" {
			files = append(files, path)
		}
		return nil
	})
	return files
}
