package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"pipeline/core"
)

// Config represents the application configuration
type Config struct {
	Kafka struct {
		Brokers       []string `json:"brokers"`
		Topic         string   `json:"topic"`
		GroupID       string   `json:"group_id"`
		MaxPollRecords int    `json:"max_poll_records"`
	} `json:"kafka"`
	Output struct {
		Parquet struct {
			Enabled   bool   `json:"enabled"`
			BasePath  string `json:"base_path"`
			FilePrefix string `json:"file_prefix"`
		} `json:"parquet"`
		Kafka struct {
			Enabled     bool     `json:"enabled"`
			Brokers     []string `json:"brokers"`
			Topic       string   `json:"topic"`
			Compression string   `json:"compression"`
		} `json:"kafka"`
	} `json:"output"`
	AssetProfiler core.AssetProfilerConfig `json:"asset_profiler"`
	Write struct {
		FlushBufferMB      int `json:"flush_buffer_mb"`
		FlushIntervalSec   int `json:"flush_interval_seconds"`
		FlushEventCount   int `json:"flush_event_count"`
	} `json:"write"`
	Log struct {
		Path string `json:"path"`
	} `json:"log"`
	NormalizationPath       string `json:"normalization_path"`
	ClassificationRulesPath string `json:"classification_rules_path"`
}

// PipelineState holds global pipeline metrics
type PipelineState struct {
	processedEvents int64
	errorCount      int64
	writers         []*core.ParquetWriter
	assetProfiler   *core.AssetProfiler
	mu              sync.RWMutex
}

// loadEnvFile reads a simple key=value .env file into os.Environ
func loadEnvFile(path string) {
	f, err := os.Open(path)
	if err != nil {
		return // .env is optional
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			if _, exists := os.LookupEnv(key); !exists {
				os.Setenv(key, val)
			}
		}
	}
}

func main() {
	// Load local .env if present (project-root first, then legacy path).
	loadEnvFile("/opt/tools/pcapql/.env")
	loadEnvFile("/opt/ndr/.env")

	// Parse command-line arguments
	defaultConfig := "/opt/tools/pcapql/ndr-enrich/config/config.json"
	if cfgDir := os.Getenv("NDR_CONFIG_DIR"); cfgDir != "" {
		defaultConfig = filepath.Join(cfgDir, "..", "ndr-enrich", "config", "config.json")
	}
	var configPath string
	flag.StringVar(&configPath, "config", defaultConfig, "Path to config.json file")
	flag.Parse()

	if configPath == "" {
		fmt.Fprintf(os.Stderr, "Error: --config flag is required\n")
		fmt.Fprintf(os.Stderr, "Usage: %s --config <path/to/config.json>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Example: %s --config /opt/ndr/ndr-enrich/config/config.json\n", os.Args[0])
		os.Exit(1)
	}

	logger := core.GetLogger()

	// Startup logs
	logger.Info("startup", "pipeline initializing", fmt.Sprintf("config_path=%s", configPath))

	// Load configuration
	configData, err := os.ReadFile(configPath)
	if err != nil {
		logger.Fatal("startup", "read config failed", fmt.Sprintf("path=%s error=%v", configPath, err))
	}

	var config Config
	if err := json.Unmarshal(configData, &config); err != nil {
		logger.Fatal("startup", "parse config failed", fmt.Sprintf("error=%v", err))
	}

	// Get config directory to resolve relative paths
	configDir := filepath.Dir(configPath)

	// Load normalization rules (from config path or relative to config file)
	normPath := config.NormalizationPath
	if normPath == "" {
		normPath = filepath.Join(configDir, "normalization.json")
	}
	normData, err := os.ReadFile(normPath)
	if err != nil {
		logger.Fatal("startup", "read normalization failed", fmt.Sprintf("path=%s error=%v", normPath, err))
	}

	normalizationRules, err := core.LoadNormalizationRules(normData)
	if err != nil {
		logger.Fatal("startup", "load normalization failed", fmt.Sprintf("error=%v", err))
	}

	// Load classification rules if path specified
	if config.ClassificationRulesPath != "" {
		if err := core.LoadClassificationRules(config.ClassificationRulesPath); err != nil {
			logger.Warn("startup", "classification rules not loaded (using defaults)", fmt.Sprintf("path=%s error=%v", config.ClassificationRulesPath, err))
		} else {
			logger.Info("startup", "classification rules loaded", fmt.Sprintf("path=%s", config.ClassificationRulesPath))
		}
	}

	// Configure logger to write to log path from config
	if config.Log.Path != "" {
		if err := logger.SetLogPath(config.Log.Path); err != nil {
			logger.Fatal("startup", "configure log path failed", fmt.Sprintf("path=%s error=%v", config.Log.Path, err))
		}
		logger.Info("startup", "log path configured", fmt.Sprintf("path=%s", config.Log.Path))
	}

	// Get all log types
	logTypes := make([]string, 0, len(normalizationRules))
	for logType := range normalizationRules {
		logTypes = append(logTypes, logType)
	}

	// Startup configuration logs
	logger.Info("startup", "configuration loaded",
		fmt.Sprintf("kafka_topic=%s kafka_group=%s brokers=%v log_types=%d",
			config.Kafka.Topic, config.Kafka.GroupID, config.Kafka.Brokers, len(logTypes)))

	// Log output configuration
	outputsEnabled := []string{}
	if config.Output.Parquet.Enabled {
		outputsEnabled = append(outputsEnabled, "parquet")
		logger.Info("startup", "parquet output enabled",
			fmt.Sprintf("base_path=%s file_prefix=%s", config.Output.Parquet.BasePath, config.Output.Parquet.FilePrefix))
	}
	if config.Output.Kafka.Enabled {
		outputsEnabled = append(outputsEnabled, "kafka")
		logger.Info("startup", "kafka output enabled",
			fmt.Sprintf("topic=%s brokers=%v compression=%s", config.Output.Kafka.Topic, config.Output.Kafka.Brokers, config.Output.Kafka.Compression))
	}
	if config.AssetProfiler.Enabled {
		outputsEnabled = append(outputsEnabled, "asset_profiler")
		logger.Info("startup", "asset profiler enabled",
			fmt.Sprintf("sync_interval=%ds max_profiles=%d", config.AssetProfiler.SyncIntervalSeconds, config.AssetProfiler.MaxProfiles))
	}
	if len(outputsEnabled) == 0 {
		logger.Fatal("startup", "no outputs enabled", "at least one output (parquet, kafka, or asset_profiler) must be enabled")
	}

	logger.Info("startup", "buffer configuration",
		fmt.Sprintf("flush_size_mb=%d flush_interval_sec=%d flush_event_count=%d",
			config.Write.FlushBufferMB, config.Write.FlushIntervalSec, config.Write.FlushEventCount))

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Create components
	consumer, err := core.NewConsumer(core.KafkaConfig{
		Brokers:       config.Kafka.Brokers,
		Topic:         config.Kafka.Topic,
		GroupID:       config.Kafka.GroupID,
		MaxPollRecords: config.Kafka.MaxPollRecords,
	})
	if err != nil {
		logger.Fatal("startup", "create consumer failed", fmt.Sprintf("error=%v", err))
	}

	normalizer := core.NewNormalizer(normalizationRules)
	enricher := core.NewEnricher()

	// Pipeline state for health monitoring
	state := &PipelineState{}

	// Create fan-out for multiple outputs
	fanOut := core.NewFanOut()

	// Setup Parquet output (if enabled)
	var pipelineFlow *core.PipelineFlow
	var pipelineFlowInput chan *core.EnrichedEvent
	if config.Output.Parquet.Enabled {
		pipelineFlow = core.NewPipelineFlow(logTypes, 10000)
		pipelineFlowInput = make(chan *core.EnrichedEvent, 10000)
		fanOut.AddOutput(pipelineFlowInput)
	}

	// Setup local state store + identity resolver (needed by Kafka output and asset profiler)
	var stateStore *core.StateStore
	var identityResolver *core.IdentityResolver
	if config.AssetProfiler.Enabled {
		stateStore, err = core.NewStateStore(core.StateStoreConfig{})
		if err != nil {
			logger.Fatal("startup", "state store initialization failed", fmt.Sprintf("error=%v", err))
		}
		logger.Info("startup", "local state store ready", "in-memory asset state enabled")

		// Create identity resolver (uses the same local state store)
		identityResolver = core.NewIdentityResolver(core.IdentityResolverConfig{
			DefaultLeaseTTL: 3600, // 1 hour default
		}, stateStore)
		logger.Info("startup", "identity resolver created", "mac-anchored asset_id generation enabled")
	}

	// Setup Kafka output (if enabled)
	var kafkaProducer *core.KafkaProducer
	var kafkaInput chan *core.EnrichedEvent
	if config.Output.Kafka.Enabled {
		kafkaInput = make(chan *core.EnrichedEvent, 10000)
		fanOut.AddOutput(kafkaInput)
		
		producer, err := core.NewKafkaProducer(core.KafkaProducerConfig{
			Brokers:     config.Output.Kafka.Brokers,
			Topic:       config.Output.Kafka.Topic,
			Compression: config.Output.Kafka.Compression,
		}, identityResolver, kafkaInput)
		if err != nil {
			logger.Fatal("startup", "create kafka producer failed", fmt.Sprintf("error=%v", err))
		}
		kafkaProducer = producer
	}

	// Setup asset profiler (if enabled — uses local state + resolver created above)
	var assetProfiler *core.AssetProfiler
	if config.AssetProfiler.Enabled {
		assetProfilerInput := make(chan *core.EnrichedEvent, 10000)
		fanOut.AddOutput(assetProfilerInput)

		assetProfiler = core.NewAssetProfiler(config.AssetProfiler, stateStore, identityResolver, assetProfilerInput)
		state.assetProfiler = assetProfiler
	}

	var wg sync.WaitGroup

	// Start Kafka consumer
	wg.Add(1)
	go func() {
		defer wg.Done()
		consumer.Start(ctx)
	}()

	// Centralized error handler
	wg.Add(1)
	go func() {
		defer wg.Done()
		errorCount := int64(0)
		for {
			select {
			case <-ctx.Done():
				return
			case err, ok := <-consumer.Errors():
				if !ok {
					return
				}
				atomic.AddInt64(&errorCount, 1)
				atomic.AddInt64(&state.errorCount, 1)
				// Log first 10 errors, then throttle
				if errorCount <= 10 {
					logger.Error("kafka", "read error", fmt.Sprintf("error=%v", err))
				} else if errorCount == 11 {
					logger.Warn("kafka", "many errors detected", "throttling error logs")
				}
			}
		}
	}()

	// Start normalization and enrichment pipeline (no logging in hot loop)
	normalizedChan := make(chan *core.NormalizedEvent, 1000)
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(normalizedChan)
		for {
			select {
			case <-ctx.Done():
				return
			case zeekLog, ok := <-consumer.Output():
				if !ok {
					return
				}
				atomic.AddInt64(&state.processedEvents, 1)
				// Normalize (silent skip if no rule)
				normalized, err := normalizer.Normalize(zeekLog)
				if err != nil {
					continue
				}
				normalizedChan <- normalized
			}
		}
	}()

	// Start enrichment (no logging in hot loop)
	enrichedChan := make(chan *core.EnrichedEvent, 1000)
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(enrichedChan)
		for {
			select {
			case <-ctx.Done():
				return
			case normalized, ok := <-normalizedChan:
				if !ok {
					return
				}
				enriched := enricher.Enrich(normalized)
				enrichedChan <- enriched
			}
		}
	}()

	// Start fan-out (distributes to all enabled outputs)
	wg.Add(1)
	go func() {
		defer wg.Done()
		fanOut.Start(ctx, enrichedChan)
	}()

	// Start Parquet output (if enabled)
	if config.Output.Parquet.Enabled {
		writerConfig := core.WriterConfig{
			BasePath:         config.Output.Parquet.BasePath,
			FilePrefix:       config.Output.Parquet.FilePrefix,
			FlushBufferMB:    config.Write.FlushBufferMB,
			FlushIntervalSec: config.Write.FlushIntervalSec,
			FlushEventCount:  config.Write.FlushEventCount,
		}

		// Start pipeline flow router
		wg.Add(1)
		go func() {
			defer wg.Done()
			pipelineFlow.Start(ctx, pipelineFlowInput)
		}()

		// Start Parquet writers (one per log type)
		state.mu.Lock()
		for _, logType := range logTypes {
			logType := logType
			writer := core.NewParquetWriter(logType, writerConfig, pipelineFlow.GetRoute(logType))
			state.writers = append(state.writers, writer)
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := writer.Start(ctx); err != nil {
					logger.Error("parquet", fmt.Sprintf("writer failed log_type=%s", logType), fmt.Sprintf("error=%v", err))
				}
			}()
		}
		state.mu.Unlock()
	}

	// Start Kafka producer (if enabled)
	if config.Output.Kafka.Enabled {
		// Start Kafka producer error handler
		wg.Add(1)
		go func() {
			defer wg.Done()
			errorCount := int64(0)
			for {
				select {
				case <-ctx.Done():
					return
				case err, ok := <-kafkaProducer.Errors():
					if !ok {
						return
					}
					atomic.AddInt64(&errorCount, 1)
					atomic.AddInt64(&state.errorCount, 1)
					// Log first 10 errors, then throttle
					if errorCount <= 10 {
						logger.Error("kafka", "producer write error", fmt.Sprintf("error=%v", err))
					} else if errorCount == 11 {
						logger.Warn("kafka", "many producer errors detected", "throttling error logs")
					}
				}
			}
		}()

		// Start Kafka producer
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := kafkaProducer.Start(ctx); err != nil {
				logger.Error("kafka", "producer failed", fmt.Sprintf("error=%v", err))
			}
		}()
	}

	// Start Asset Profiler (if enabled)
	if config.AssetProfiler.Enabled && assetProfiler != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := assetProfiler.Start(ctx); err != nil {
				logger.Error("asset_profiler", "profiler failed", fmt.Sprintf("error=%v", err))
			}
		}()
	}

	logger.Info("startup", "pipeline started", fmt.Sprintf("log_types=%d outputs=%v", len(logTypes), outputsEnabled))

	// Health monitoring ticker (every 30 seconds)
	healthTicker := time.NewTicker(30 * time.Second)
	defer healthTicker.Stop()

	wg.Add(1)
	go func() {
		defer wg.Done()
		lastEventCount := int64(0)
		lastTime := time.Now()
		for {
			select {
			case <-ctx.Done():
				return
			case <-healthTicker.C:
				// Collect health metrics
				rss, heap := core.GetMemoryStats()
				currentEvents := atomic.LoadInt64(&state.processedEvents)
				errorCount := atomic.LoadInt64(&state.errorCount)
				
				// Calculate throughput
				now := time.Now()
				elapsed := now.Sub(lastTime).Seconds()
				eventsDelta := currentEvents - lastEventCount
				throughput := int64(0)
				if elapsed > 0 {
					throughput = int64(float64(eventsDelta) / elapsed)
				}
				lastEventCount = currentEvents
				lastTime = now

				// Collect buffer metrics from all writers
				state.mu.RLock()
				totalBufferBytes := int64(0)
				totalBufferLimit := int64(0)
				totalFlushCount := int64(0)
				totalWriterEvents := int64(0)
				for _, writer := range state.writers {
					bufBytes, bufLimit, flushCount, writerEvents := writer.GetMetrics()
					totalBufferBytes += bufBytes
					totalBufferLimit += bufLimit
					totalFlushCount += flushCount
					totalWriterEvents += writerEvents
				}
				state.mu.RUnlock()

				bufferPercent := 0
				if totalBufferLimit > 0 {
					bufferPercent = int((totalBufferBytes * 100) / totalBufferLimit)
				}

				// Collect asset profiler metrics
				var profileCount, profilerSyncs, profilerEvents int64
				if state.assetProfiler != nil {
					profileCount, profilerSyncs, profilerEvents = state.assetProfiler.GetMetrics()
				}

				// Log health snapshot
				memoryMB := float64(rss) / (1024 * 1024)
				bufferMB := float64(totalBufferBytes) / (1024 * 1024)
				logger.Info("health",
					fmt.Sprintf("memory=%.0fMB buffer=%.1fMB buffer_pct=%d%% eps=%d flushes=%d errors=%d profiles=%d",
						memoryMB, bufferMB, bufferPercent, throughput, totalFlushCount, errorCount, profileCount),
					fmt.Sprintf("heap=%dMB events=%d profiler_syncs=%d profiler_events=%d",
						heap/(1024*1024), currentEvents, profilerSyncs, profilerEvents))

				// Warn on high buffer usage
				if bufferPercent > 80 {
					logger.Warn("health", "buffer usage high", fmt.Sprintf("buffer_pct=%d%%", bufferPercent))
				}
			}
		}
	}()

	// Wait for shutdown signal
	<-sigChan
	logger.Info("shutdown", "shutdown signal received", "")

	// Cancel context to stop all goroutines
	cancel()

	// Wait for all goroutines to finish
	wg.Wait()

	// Close local state store
	if stateStore != nil {
		stateStore.Close()
	}

	logger.Info("shutdown", "pipeline stopped", "")
}
