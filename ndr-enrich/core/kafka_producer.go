package core

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/compress"
)

// KafkaOutputEvent represents the flat output format for Kafka.
// This matches the Flink ndr_enriched DDL exactly:
//   - Common fields are top-level
//   - Log-type-specific fields go into details MAP<STRING,STRING>
//
// Generated from: ndr-config/schemas/zeek/fields.json + normalization.json
type KafkaOutputEvent struct {
	// Event identity
	Ts        string `json:"ts"`         // ISO8601 timestamp
	FtxID     string `json:"ftx_id"`     // FlowTraceX event ID (system-generated UUID)
	Uid       string `json:"uid"`        // Zeek flow/connection UID (source-specific)
	LogType   string `json:"log_type"`   // conn, dns, ssh, http, ssl, ...
	LogSource string `json:"log_source"` // zeek (extensible)

	// Normalized network fields (promoted from raw Zeek)
	SrcIP   string `json:"src_ip"`
	DstIP   string `json:"dst_ip"`
	SrcPort int32  `json:"src_port"`
	DstPort int32  `json:"dst_port"`
	Proto   string `json:"proto"`   // tcp, udp, icmp
	Service string `json:"service"` // Detected service name

	// Event classification (from normalization.json static section)
	EventType  string `json:"event_type"`  // network_connection, dns, ssh, ...
	EventClass string `json:"event_class"` // network, authentication, application, ...

	// Asset enrichment (set by Go via Redis)
	AssetID   string `json:"asset_id"`
	AssetType string `json:"asset_type"` // workstation, server, docker, iot

	// Threat enrichment (set by Go via Redis)
	SrcIsBlacklisted bool `json:"src_is_blacklisted"`
	DstIsBlacklisted bool `json:"dst_is_blacklisted"`

	// Network enrichment (computed by Go)
	SrcIPIsPrivate bool   `json:"src_ip_is_private"`
	DstIPIsPrivate bool   `json:"dst_ip_is_private"`
	Direction      string `json:"direction"` // outbound, inbound, internal, external

	// GeoIP enrichment (set by Go)
	GeoCountry string `json:"geo_country,omitempty"`
	GeoCity    string `json:"geo_city,omitempty"`
	GeoASN     string `json:"geo_asn,omitempty"`

	// Time enrichment (computed by Go)
	IngestTime   int64 `json:"ingest_time"` // Pipeline ingest time (epoch millis)
	EventYear    int32 `json:"event_year"`
	EventMonth   int32 `json:"event_month"`
	EventDay     int32 `json:"event_day"`
	EventHour    int32 `json:"event_hour"`
	EventWeekday int32 `json:"event_weekday"` // 0=Sunday..6=Saturday

	// Log-type-specific fields (variable per log_type)
	// All values are stringified for MAP<STRING,STRING> compatibility
	Details map[string]string `json:"details"`
}

// promotedFields is the set of Zeek fields that are promoted to top-level.
// These get REMOVED from the details map since they're already top-level.
// From normalization.json "promote" mappings across all log types.
var promotedFields = map[string]bool{
	"ts": true, "uid": true, "ftx_id": true,
	"id.orig_h": true, "id.resp_h": true,
	"id.orig_p": true, "id.resp_p": true,
	"proto": true, "service": true,
}

// transformToKafkaOutput converts an EnrichedEvent to flat KafkaOutputEvent format.
// Top-level fields come from NormalizedEvent + EnrichedEvent.
// All remaining Zeek fields go into details MAP as strings.
func transformToKafkaOutput(event *EnrichedEvent) *KafkaOutputEvent {
	// Format timestamp as ISO8601
	ts := ""
	if event.EventTime > 0 {
		t := time.Unix(event.EventTime/1000, (event.EventTime%1000)*int64(time.Millisecond))
		ts = t.UTC().Format(time.RFC3339)
	}

	output := &KafkaOutputEvent{
		// Identity
		Ts:        ts,
		FtxID:     uuid.New().String(),
		Uid:       event.FlowID,
		LogType:   event.LogType,
		LogSource: "zeek",

		// Normalized network
		SrcIP:   event.SrcIP,
		DstIP:   event.DstIP,
		SrcPort: event.SrcPort,
		DstPort: event.DstPort,
		Proto:   event.Protocol,

		// Classification
		EventType:  event.EventType,
		EventClass: event.EventClass,

		// Asset enrichment (from identity resolver via Redis)
		AssetID:   "",
		AssetType: "",

		// Threat (TODO: populated when Redis threat lookup is integrated)
		SrcIsBlacklisted: false,
		DstIsBlacklisted: false,

		// Network enrichment
		SrcIPIsPrivate: event.SrcIPIsPrivate,
		DstIPIsPrivate: event.DstIPIsPrivate,
		Direction:      event.Direction,

		// Time enrichment
		IngestTime:   event.IngestTime,
		EventYear:    event.EventYear,
		EventMonth:   event.EventMonth,
		EventDay:     event.EventDay,
		EventHour:    event.EventHour,
		EventWeekday: event.EventWeekday,

		// Details map
		Details: make(map[string]string),
	}

	// Use raw "service" field if available, otherwise use enriched Service
	if rawService, ok := event.ZeekFields["service"]; ok {
		if serviceStr, ok := rawService.(string); ok {
			output.Service = serviceStr
		}
	} else {
		output.Service = event.Service
	}

	// Pack all non-promoted Zeek fields into details MAP as strings
	if event.ZeekFields != nil {
		for k, v := range event.ZeekFields {
			// Skip fields that are promoted to top-level
			if promotedFields[k] {
				continue
			}
			// Convert value to string
			output.Details[k] = fmt.Sprintf("%v", v)
		}
	}

	return output
}

// KafkaProducerConfig holds Kafka producer configuration
type KafkaProducerConfig struct {
	Brokers     []string
	Topic       string
	Compression string // "none", "gzip", "snappy", "lz4", "zstd"
}

// KafkaProducer writes enriched events to Kafka
type KafkaProducer struct {
	config     KafkaProducerConfig
	writer     *kafka.Writer
	resolver   *IdentityResolver
	input      <-chan *EnrichedEvent
	errorChan  chan error
	mu         sync.Mutex
	sentCount  int64 // Total events sent (for health monitoring)
	errorCount int64 // Total errors (for health monitoring)
}

// NewKafkaProducer creates a new Kafka producer
func NewKafkaProducer(cfg KafkaProducerConfig, resolver *IdentityResolver, input <-chan *EnrichedEvent) (*KafkaProducer, error) {
	// Configure compression
	var compression compress.Compression
	switch cfg.Compression {
	case "gzip":
		compression = compress.Gzip
	case "snappy":
		compression = compress.Snappy
	case "lz4":
		compression = compress.Lz4
	case "zstd":
		compression = compress.Zstd
	default:
		compression = compress.None // No compression
	}

	writer := &kafka.Writer{
		Addr:         kafka.TCP(cfg.Brokers...),
		Topic:        cfg.Topic,
		Balancer:     &kafka.LeastBytes{},
		Compression:  compression,
		BatchSize:    100,   // Batch messages for efficiency
		BatchTimeout: 10e6,  // 10ms
		Async:        false, // Synchronous writes for reliability
	}

	return &KafkaProducer{
		config:    cfg,
		writer:    writer,
		resolver:  resolver,
		input:     input,
		errorChan: make(chan error, 100),
	}, nil
}

// Start begins the producer goroutine
func (kp *KafkaProducer) Start(ctx context.Context) error {
	logger := GetLogger()
	logger.Info("startup", "kafka producer started",
		fmt.Sprintf("topic=%s brokers=%v compression=%s", kp.config.Topic, kp.config.Brokers, kp.config.Compression))

	for {
		select {
		case <-ctx.Done():
			// Close writer on shutdown
			if err := kp.writer.Close(); err != nil {
				logger.Error("kafka", "producer close failed", fmt.Sprintf("error=%v", err))
			}
			return nil

		case event, ok := <-kp.input:
			if !ok {
				// Channel closed
				if err := kp.writer.Close(); err != nil {
					logger.Error("kafka", "producer close failed", fmt.Sprintf("error=%v", err))
				}
				return nil
			}

			// Transform to Kafka output format (with identity resolution)
			kafkaEvent := transformToKafkaOutput(event)

			// Enrich with stable asset identity from resolver (internal, trackable IPs only).
			if kp.resolver != nil && isTrackableAssetIP(event.SrcIP) {
				kafkaEvent.AssetID = kp.resolver.GetOrCreateAssetIDForIP(event.SrcIP)
				if identity := kp.resolver.ResolveIP(event.SrcIP); identity != nil {
					kafkaEvent.AssetType = identity.AssetType
				}
			}

			// Serialize to JSON
			jsonData, err := json.Marshal(kafkaEvent)
			if err != nil {
				atomic.AddInt64(&kp.errorCount, 1)
				kp.errorChan <- fmt.Errorf("serialize event failed: %w", err)
				continue
			}

			// Write to Kafka
			msg := kafka.Message{
				Key:   []byte(event.LogType), // Use log_type as key for partitioning
				Value: jsonData,
			}

			if err := kp.writer.WriteMessages(ctx, msg); err != nil {
				atomic.AddInt64(&kp.errorCount, 1)
				kp.errorChan <- fmt.Errorf("kafka write failed: %w", err)
				continue
			}

			atomic.AddInt64(&kp.sentCount, 1)
		}
	}
}

// Errors returns the error channel
func (kp *KafkaProducer) Errors() <-chan error {
	return kp.errorChan
}

// GetMetrics returns producer metrics (thread-safe)
func (kp *KafkaProducer) GetMetrics() (sentCount, errorCount int64) {
	return atomic.LoadInt64(&kp.sentCount), atomic.LoadInt64(&kp.errorCount)
}
