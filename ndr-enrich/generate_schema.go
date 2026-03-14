package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Schema definitions
type SchemaDef struct {
	LogType string            `json:"log_type"`
	Fields  map[string]string `json:"fields"`
}

type SchemaFile struct {
	Schemas map[string]SchemaDef `json:"-"`
}

// Normalization definitions
type NormalizationRule struct {
	Source  string            `json:"source"`
	Promote map[string]string `json:"promote"`
	Static  map[string]string `json:"static"`
	Enrich  *EnrichConfig     `json:"enrich"`
}

type EnrichConfig struct {
	Time    bool `json:"time"`
	Network bool `json:"network"`
}

type NormalizationFile struct {
	Rules map[string]NormalizationRule `json:"-"`
}

func main() {
	// Resolve config directory
	configDir := os.Getenv("NDR_CONFIG_DIR")
	if configDir == "" {
		configDir = filepath.Join("..", "ndr-config")
	}
	schemaDir := filepath.Join(configDir, "schemas", "zeek")

	// Read schema
	schemaPath := filepath.Join(schemaDir, "fields.json")
	schemaData, err := os.ReadFile(schemaPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading %s: %v\n", schemaPath, err)
		os.Exit(1)
	}

	var schemaRaw map[string]interface{}
	if err := json.Unmarshal(schemaData, &schemaRaw); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing %s: %v\n", schemaPath, err)
		os.Exit(1)
	}

	// Read normalization
	normPath := filepath.Join(schemaDir, "normalization.json")
	normData, err := os.ReadFile(normPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading %s: %v\n", normPath, err)
		os.Exit(1)
	}

	var normRules map[string]NormalizationRule
	if err := json.Unmarshal(normData, &normRules); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing %s: %v\n", normPath, err)
		os.Exit(1)
	}

	// Generate events.go (Parquet structs)
	output := generateEventsGo(schemaRaw, normRules)
	if err := os.WriteFile("schema/events.go", []byte(output), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing schema/events.go: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("✅ Generated schema/events.go")

	// Generate Flink DDL (ndr_enriched table only)
	flinkDir := filepath.Join("..", "ndr-flink")
	flinkDDL := generateFlinkDDL(schemaRaw, normRules)
	ddlPath := filepath.Join(flinkDir, "signals", "schema_ndr_enriched.sql")
	if err := os.MkdirAll(filepath.Dir(ddlPath), 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating %s: %v\n", filepath.Dir(ddlPath), err)
		os.Exit(1)
	}
	if err := os.WriteFile(ddlPath, []byte(flinkDDL), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing %s: %v\n", ddlPath, err)
		os.Exit(1)
	}
	fmt.Printf("✅ Generated %s\n", ddlPath)

	// Generate enrichment-schema.json
	enrichSchema := generateEnrichmentSchema(schemaRaw, normRules)
	// Some deployments keep this file at ndr-flink root (no config/ dir).
	enrichPath := filepath.Join(flinkDir, "config", "enrichment-schema.json")
	if _, err := os.Stat(filepath.Join(flinkDir, "config")); err != nil {
		enrichPath = filepath.Join(flinkDir, "enrichment-schema.json")
	}
	if err := os.MkdirAll(filepath.Dir(enrichPath), 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating %s: %v\n", filepath.Dir(enrichPath), err)
		os.Exit(1)
	}
	if err := os.WriteFile(enrichPath, []byte(enrichSchema), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing %s: %v\n", enrichPath, err)
		os.Exit(1)
	}
	fmt.Printf("✅ Generated %s\n", enrichPath)
}

func generateEventsGo(schemaRaw map[string]interface{}, normRules map[string]NormalizationRule) string {
	var buf strings.Builder

	// Header
	buf.WriteString("package schema\n\n")
	buf.WriteString("import (\n")
	buf.WriteString("\t\"time\"\n")
	buf.WriteString(")\n\n")

	// Generate struct for each log type in normalization.json
	logTypes := make([]string, 0, len(normRules))
	for logType := range normRules {
		logTypes = append(logTypes, logType)
	}
	sort.Strings(logTypes)

	for _, logType := range logTypes {
		rule := normRules[logType]
		sourceKey := rule.Source // e.g., "zeek_dns", "zeek_conn"

		// Find schema for this source
		schemaDef, ok := schemaRaw[sourceKey]
		if !ok {
			continue // Skip if schema not found
		}

		schemaMap, ok := schemaDef.(map[string]interface{})
		if !ok {
			continue
		}

		fieldsMap, ok := schemaMap["fields"].(map[string]interface{})
		if !ok {
			continue
		}

		// Get promoted field names (to exclude from raw)
		// Key is the normalized field name (e.g., "service", "direction")
		promotedFields := make(map[string]bool)
		for _, normField := range rule.Promote {
			promotedFields[normField] = true
		}

		// Get raw field names that are promoted (to exclude from raw section)
		promotedRawFields := make(map[string]bool)
		for rawField := range rule.Promote {
			promotedRawFields[rawField] = true
		}

		// Generate struct
		structName := strings.ToUpper(logType)
		buf.WriteString(fmt.Sprintf("// %s represents a normalized %s event following the three-layer model:\n", structName, logType))
		buf.WriteString("// 1) Conditional enrichment (controlled per log type via normalization.json enrich flags)\n")
		buf.WriteString("// 2) Normalized/promoted fields (from normalization.json mapping)\n")
		buf.WriteString("// 3) Unmapped raw fields (from schema.json, NOT in normalization.json)\n")
		buf.WriteString("// 4) raw_log (complete original JSON)\n")
		buf.WriteString(fmt.Sprintf("type %s struct {\n", structName))

		// System-wide FlowTraceX ID (always present, generated by Go pipeline)
		buf.WriteString("\tFtxID            string `parquet:\"ftx_id\"`\n")

		// Enrichment fields (conditional)
		hasTimeEnrich := rule.Enrich != nil && rule.Enrich.Time
		hasNetworkEnrich := rule.Enrich != nil && rule.Enrich.Network

		buf.WriteString("\n\t// =========================\n")
		buf.WriteString("\t// CONDITIONAL ENRICHMENT (Layer 3)\n")
		buf.WriteString("\t// Applied based on normalization.json enrich flags (time, network)\n")
		buf.WriteString("\t// Fields may be zero/empty if enrichment is disabled for this log type\n")
		buf.WriteString("\t// =========================\n")

		if hasTimeEnrich {
			buf.WriteString("\tIngestTime       int64  `parquet:\"ingest_time\"`\n")
			buf.WriteString("\tEventYear        int32  `parquet:\"event_year\"`\n")
			buf.WriteString("\tEventMonth       int32  `parquet:\"event_month\"`\n")
			buf.WriteString("\tEventDay         int32  `parquet:\"event_day\"`\n")
			buf.WriteString("\tEventHour        int32  `parquet:\"event_hour\"`\n")
			buf.WriteString("\tEventWeekday     int32  `parquet:\"event_weekday\"`\n")
		}

		// Static fields (always present)
		buf.WriteString("\tEventType        string `parquet:\"event_type\"`\n")
		buf.WriteString("\tEventClass       string `parquet:\"event_class\"`\n")

		if hasNetworkEnrich {
			buf.WriteString("\tSrcIPIsPrivate   bool   `parquet:\"src_ip_is_private\"`\n")
			buf.WriteString("\tDstIPIsPrivate   bool   `parquet:\"dst_ip_is_private\"`\n")
			// Only add Direction if it's not already promoted
			if !promotedFields["direction"] {
				buf.WriteString("\tDirection        string `parquet:\"direction\"`\n")
			}
			// Only add Service enrichment if it's not already promoted
			if !promotedFields["service"] {
				buf.WriteString("\tService          string `parquet:\"service\"`\n")
			}
		}

		// Promoted fields
		buf.WriteString("\n\t// =========================\n")
		buf.WriteString("\t// NORMALIZED (PROMOTED) FIELDS (Layer 2)\n")
		buf.WriteString("\t// From normalization.json mapping - these replace raw fields\n")
		buf.WriteString("\t// DO NOT include raw versions\n")
		buf.WriteString("\t// =========================\n")

		// Sort promoted fields for consistent output
		promotedPairs := make([]struct {
			rawField  string
			normField string
		}, 0, len(rule.Promote))
		for rawField, normField := range rule.Promote {
			promotedPairs = append(promotedPairs, struct {
				rawField  string
				normField string
			}{rawField, normField})
		}
		sort.Slice(promotedPairs, func(i, j int) bool {
			return promotedPairs[i].normField < promotedPairs[j].normField
		})

		for _, pair := range promotedPairs {
			goFieldName := toGoFieldName(pair.normField)
			parquetName := pair.normField
			goType := getGoTypeForPromotedField(pair.normField, fieldsMap[pair.rawField])
			comment := fmt.Sprintf("// Promoted from: %s", pair.rawField)
			buf.WriteString(fmt.Sprintf("\t%s %s `parquet:\"%s\"` %s\n", goFieldName, goType, parquetName, comment))
		}

		// Raw fields (unmapped)
		buf.WriteString("\n\t// =========================\n")
		buf.WriteString("\t// RAW FIELDS (UNMAPPED) (Layer 1)\n")
		buf.WriteString("\t// From schema.json, but NOT in normalization.json mapping\n")
		buf.WriteString("\t// These are raw fields that were NOT promoted\n")
		buf.WriteString("\t// =========================\n")

		// Get all raw fields, exclude promoted ones
		rawFieldNames := make([]string, 0)
		for fieldName := range fieldsMap {
			if !promotedRawFields[fieldName] {
				rawFieldNames = append(rawFieldNames, fieldName)
			}
		}
		sort.Strings(rawFieldNames)

		// Enrichment field names that might conflict with raw fields
		enrichmentGoNames := map[string]bool{
			"Service":   true,
			"Direction": true,
		}

		for _, fieldName := range rawFieldNames {
			fieldType, ok := fieldsMap[fieldName].(string)
			if !ok {
				continue
			}
			goFieldName := toGoFieldName(fieldName)
			parquetName := sanitizeParquetName(fieldName)

			// If raw field name conflicts with enrichment field, rename it
			if enrichmentGoNames[goFieldName] {
				goFieldName = "Zeek" + goFieldName // e.g., "Service" -> "ZeekService"
			}

			goType := getGoTypeForRawField(fieldName, fieldType)
			buf.WriteString(fmt.Sprintf("\t%s %s `parquet:\"%s\"` // Not mapped\n", goFieldName, goType, parquetName))
		}

		// Raw log
		buf.WriteString("\n\t// =========================\n")
		buf.WriteString("\t// FULL RAW LOG (complete original JSON)\n")
		buf.WriteString("\t// =========================\n")
		buf.WriteString("\tRawLog string `parquet:\"raw_log\"`\n")

		buf.WriteString("}\n\n")
	}

	// ToParquetTime helper
	buf.WriteString("// ToParquetTime converts Go time to milliseconds since epoch\n")
	buf.WriteString("func ToParquetTime(t time.Time) int64 {\n")
	buf.WriteString("\treturn t.UnixNano() / int64(time.Millisecond)\n")
	buf.WriteString("}\n")

	return buf.String()
}

func toGoFieldName(fieldName string) string {
	// Convert field names like "event_time" -> "EventTime", "id.orig_h" -> "IdOrigH"
	// Special handling for "IP" and "ID" at the END of compound names: "src_ip" -> "SrcIP", "flow_id" -> "FlowID"
	// But "id" at the start should be "Id": "id.orig_p" -> "IdOrigP"
	normalized := strings.ReplaceAll(fieldName, ".", "_")
	parts := strings.Split(normalized, "_")
	var result strings.Builder
	for i, part := range parts {
		if len(part) > 0 {
			upperPart := strings.ToUpper(part)
			// Handle "IP" and "ID" specially - uppercase when at the END of compound names
			if (upperPart == "IP" || upperPart == "ID") && i == len(parts)-1 && len(parts) > 1 {
				// Last part and it's IP/ID in a compound name
				result.WriteString(upperPart)
			} else {
				// Normal conversion: "id" -> "Id", "orig" -> "Orig", "src" -> "Src"
				result.WriteString(strings.ToUpper(part[:1]))
				if len(part) > 1 {
					result.WriteString(part[1:])
				}
			}
		}
	}
	return result.String()
}

func sanitizeParquetName(fieldName string) string {
	// Convert field names like "id.orig_h" -> "id_orig_h" for Parquet
	return strings.ReplaceAll(fieldName, ".", "_")
}

func getGoType(zeekType string) string {
	switch zeekType {
	case "float":
		return "float64"
	case "int":
		return "int32" // Most int fields are int32
	case "string":
		return "string"
	case "bool":
		return "bool"
	default:
		return "string" // Default to string for unknown types
	}
}

// getGoTypeForRawField returns the appropriate Go type for raw fields
// Some fields like orig_bytes, resp_bytes should be int64
func getGoTypeForRawField(fieldName, zeekType string) string {
	// Fields that should be int64
	int64Fields := map[string]bool{
		"orig_bytes":    true,
		"resp_bytes":    true,
		"missed_bytes":  true,
		"orig_pkts":     true,
		"orig_ip_bytes": true,
		"resp_pkts":     true,
		"resp_ip_bytes": true,
	}

	if int64Fields[fieldName] && zeekType == "int" {
		return "int64"
	}

	return getGoType(zeekType)
}

func getGoTypeForPromotedField(normField string, rawFieldType interface{}) string {
	// Special handling for promoted fields
	switch normField {
	case "event_time":
		return "int64" // Always int64 for timestamps
	case "src_port", "dst_port":
		return "int32"
	case "src_ip", "dst_ip", "flow_id", "protocol", "conn_state", "service":
		return "string"
	default:
		// Try to infer from raw field type
		if rawFieldType != nil {
			if typeStr, ok := rawFieldType.(string); ok {
				switch typeStr {
				case "float":
					return "int64" // event_time is converted from float to int64
				case "int":
					return "int32"
				default:
					return "string"
				}
			}
		}
		return "string"
	}
}

// ============================================================================
// Flink DDL Generator
// ============================================================================

func generateFlinkDDL(schemaRaw map[string]interface{}, normRules map[string]NormalizationRule) string {
	var buf strings.Builder

	buf.WriteString(`-- ============================================================================
-- NDR Platform - Flink SQL: ndr_enriched table
-- ============================================================================
-- AUTO-GENERATED by generate_schema.go — DO NOT EDIT MANUALLY
-- Source: ndr-config/schemas/zeek/fields.json + normalization.json
--
-- This defines the input table that reads enriched events from Kafka.
-- The Go enrichment pipeline (ndr-enrich) produces flat JSON matching this DDL.
-- ============================================================================

CREATE TABLE IF NOT EXISTS ndr_enriched (
    -- Event identity
    ts                  TIMESTAMP(3),           -- Event time from Zeek
    ftx_id              STRING,                 -- FlowTraceX event ID (system-generated UUID)
    uid                 STRING,                 -- Zeek flow/connection UID (source-specific)
    log_type            STRING,                 -- 'conn','dns','ssh','http','ssl',...
    log_source          STRING,                 -- 'zeek' (extensible to syslog, netflow)

    -- Normalized network fields
    src_ip              STRING,
    dst_ip              STRING,
    src_port            INT,
    dst_port            INT,
    proto               STRING,                 -- 'tcp','udp','icmp'
    service             STRING,                 -- Detected/mapped service name

    -- Event classification (set by Go from normalization.json)
    event_type          STRING,                 -- e.g. 'network_connection','dns','ssh'
    event_class         STRING,                 -- e.g. 'network','authentication','application'

    -- Asset enrichment (set by Go via Redis)
    asset_id            STRING,
    asset_type          STRING,                 -- workstation, server, docker, iot, network_device

    -- Threat enrichment (set by Go via Redis)
    src_is_blacklisted  BOOLEAN,
    dst_is_blacklisted  BOOLEAN,
    src_reputation      STRING,
    dst_reputation      STRING,

    -- Network enrichment (computed by Go)
    src_ip_is_private   BOOLEAN,                -- RFC1918 private range check
    dst_ip_is_private   BOOLEAN,
    direction           STRING,                 -- internal, outbound, inbound, external

    -- GeoIP enrichment (set by Go via SQLite)
    geo_country         STRING,                 -- ISO 3166-1 alpha-2
    geo_city            STRING,
    geo_asn             STRING,                 -- e.g. AS15169

    -- Time decomposition (computed by Go)
    ingest_time         BIGINT,                 -- Pipeline ingest time (epoch millis)
    event_year          INT,
    event_month         INT,
    event_day           INT,
    event_hour          INT,
    event_weekday       INT,                    -- 0=Sunday..6=Saturday

`)

	// Build details comment showing what goes into the MAP per log type
	buf.WriteString("    -- Log-specific fields (variable per log_type)\n")

	// Collect details per log type
	logTypes := make([]string, 0, len(normRules))
	for lt := range normRules {
		logTypes = append(logTypes, lt)
	}
	sort.Strings(logTypes)

	for _, lt := range logTypes {
		rule := normRules[lt]
		schemaDef, ok := schemaRaw[rule.Source]
		if !ok {
			continue
		}
		schemaMap, ok := schemaDef.(map[string]interface{})
		if !ok {
			continue
		}
		fieldsMap, ok := schemaMap["fields"].(map[string]interface{})
		if !ok {
			continue
		}

		// Get promoted raw field names
		promotedRaw := make(map[string]bool)
		for rawField := range rule.Promote {
			promotedRaw[rawField] = true
		}

		// Collect non-promoted fields
		var detailFields []string
		for f := range fieldsMap {
			if !promotedRaw[f] {
				detailFields = append(detailFields, f)
			}
		}
		sort.Strings(detailFields)

		if len(detailFields) > 5 {
			buf.WriteString(fmt.Sprintf("    --   %s: %s, ...\n", lt, strings.Join(detailFields[:5], ", ")))
		} else if len(detailFields) > 0 {
			buf.WriteString(fmt.Sprintf("    --   %s: %s\n", lt, strings.Join(detailFields, ", ")))
		}
	}

	buf.WriteString(`    details             MAP<STRING, STRING>,

    -- Processing time (Flink-generated)
    proc_time AS PROCTIME()
) WITH (
    'connector' = 'kafka',
    'topic' = '${TOPIC_PREFIX}.enriched',
    'properties.bootstrap.servers' = '${KAFKA_BOOTSTRAP_SERVERS}',
    'properties.group.id' = '${FLINK_JOB_GROUP_ID}',
    'format' = 'json',
    'scan.startup.mode' = 'latest-offset',
    'json.ignore-parse-errors' = 'false'
);
`)

	return buf.String()
}

// ============================================================================
// Enrichment Schema Generator
// ============================================================================

func generateEnrichmentSchema(schemaRaw map[string]interface{}, normRules map[string]NormalizationRule) string {
	// Build the enrichment schema structure
	type FieldDef struct {
		Type        string `json:"type"`
		Required    bool   `json:"required"`
		Description string `json:"description"`
	}

	type EnrichmentSchema struct {
		Version          string              `json:"version"`
		Producer         string              `json:"producer"`
		Consumer         string              `json:"consumer"`
		Fields           map[string]FieldDef `json:"fields"`
		DetailsByLogType map[string][]string `json:"details_by_log_type"`
	}

	schema := EnrichmentSchema{
		Version:  "2.1",
		Producer: "go_pipeline",
		Consumer: "flink_sql_engine",
		Fields: map[string]FieldDef{
			"ts":                 {Type: "STRING", Required: true, Description: "Event timestamp (ISO8601)"},
			"ftx_id":             {Type: "STRING", Required: true, Description: "FlowTraceX event ID (system-generated UUID)"},
			"uid":                {Type: "STRING", Required: false, Description: "Zeek connection UID (source-specific)"},
			"log_type":           {Type: "STRING", Required: true, Description: "Log type (conn, dns, ssh, ...)"},
			"log_source":         {Type: "STRING", Required: true, Description: "Log source identifier (zeek)"},
			"src_ip":             {Type: "STRING", Required: true, Description: "Source IP address"},
			"dst_ip":             {Type: "STRING", Required: true, Description: "Destination IP address"},
			"src_port":           {Type: "INT", Required: false, Description: "Source port number"},
			"dst_port":           {Type: "INT", Required: false, Description: "Destination port number"},
			"proto":              {Type: "STRING", Required: false, Description: "Transport protocol"},
			"service":            {Type: "STRING", Required: false, Description: "Detected service name"},
			"event_type":         {Type: "STRING", Required: false, Description: "Classified event type"},
			"event_class":        {Type: "STRING", Required: false, Description: "Broad event category"},
			"asset_id":           {Type: "STRING", Required: false, Description: "Asset identifier"},
			"asset_type":         {Type: "STRING", Required: false, Description: "Asset type"},
			"src_is_blacklisted": {Type: "BOOLEAN", Required: false, Description: "Source IP in threat intel blacklist"},
			"dst_is_blacklisted": {Type: "BOOLEAN", Required: false, Description: "Dest IP in threat intel blacklist"},
			"src_ip_is_private":  {Type: "BOOLEAN", Required: false, Description: "Source IP is RFC1918 private"},
			"dst_ip_is_private":  {Type: "BOOLEAN", Required: false, Description: "Dest IP is RFC1918 private"},
			"direction":          {Type: "STRING", Required: false, Description: "Traffic direction"},
			"geo_country":        {Type: "STRING", Required: false, Description: "GeoIP country"},
			"geo_city":           {Type: "STRING", Required: false, Description: "GeoIP city"},
			"geo_asn":            {Type: "STRING", Required: false, Description: "GeoIP ASN"},
			"ingest_time":        {Type: "BIGINT", Required: false, Description: "Pipeline ingest time (epoch ms)"},
			"event_year":         {Type: "INT", Required: false, Description: "Event year"},
			"event_month":        {Type: "INT", Required: false, Description: "Event month"},
			"event_day":          {Type: "INT", Required: false, Description: "Event day"},
			"event_hour":         {Type: "INT", Required: false, Description: "Event hour"},
			"event_weekday":      {Type: "INT", Required: false, Description: "Day of week (0=Sunday)"},
			"details":            {Type: "MAP<STRING,STRING>", Required: true, Description: "Log-type-specific detail fields"},
		},
		DetailsByLogType: make(map[string][]string),
	}

	// Build details_by_log_type from fields.json + normalization.json
	logTypes := make([]string, 0, len(normRules))
	for lt := range normRules {
		logTypes = append(logTypes, lt)
	}
	sort.Strings(logTypes)

	for _, lt := range logTypes {
		rule := normRules[lt]
		schemaDef, ok := schemaRaw[rule.Source]
		if !ok {
			continue
		}
		schemaMap, ok := schemaDef.(map[string]interface{})
		if !ok {
			continue
		}
		fieldsMap, ok := schemaMap["fields"].(map[string]interface{})
		if !ok {
			continue
		}

		// Get promoted raw field names
		promotedRaw := make(map[string]bool)
		for rawField := range rule.Promote {
			promotedRaw[rawField] = true
		}

		// Collect non-promoted fields as details
		var detailFields []string
		for f := range fieldsMap {
			if !promotedRaw[f] {
				detailFields = append(detailFields, f)
			}
		}
		sort.Strings(detailFields)
		schema.DetailsByLogType[lt] = detailFields
	}

	// Marshal to pretty JSON
	jsonBytes, err := json.MarshalIndent(schema, "", "  ")
	if err != nil {
		return fmt.Sprintf("ERROR: %v", err)
	}
	return string(jsonBytes) + "\n"
}
