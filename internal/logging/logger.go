package logging

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"breachmap/internal/domain"
)

// Re-export LogLevel for convenience
type LogLevel = domain.LogLevel

const (
	LogLevelDebug = domain.LogLevelDebug
	LogLevelInfo  = domain.LogLevelInfo
	LogLevelWarn  = domain.LogLevelWarn
	LogLevelError = domain.LogLevelError
)

// StructuredLogEntry represents a structured log entry
type StructuredLogEntry struct {
	Timestamp time.Time              `json:"timestamp"`
	Level     LogLevel               `json:"level"`
	Message   string                 `json:"message"`
	Operation string                 `json:"operation,omitempty"`
	Region    string                 `json:"region,omitempty"`
	Resource  string                 `json:"resource,omitempty"`
	Error     string                 `json:"error,omitempty"`
	Metrics   map[string]interface{} `json:"metrics,omitempty"`
	Context   map[string]interface{} `json:"context,omitempty"`
}

// StructuredLogger provides structured logging capabilities
type StructuredLogger struct {
	enabled  bool
	minLevel LogLevel
}

var structuredLogger = &StructuredLogger{
	enabled:  true,
	minLevel: LogLevelInfo,
}

// SetLogLevel sets the minimum log level
func SetLogLevel(level LogLevel) {
	structuredLogger.minLevel = level
}

func logLevelPriority(level LogLevel) int {
	switch level {
	case LogLevelDebug:
		return 0
	case LogLevelInfo:
		return 1
	case LogLevelWarn:
		return 2
	case LogLevelError:
		return 3
	default:
		return 1
	}
}

func logStructured(level LogLevel, message string, fields ...map[string]interface{}) {
	if logLevelPriority(level) < logLevelPriority(structuredLogger.minLevel) {
		return
	}

	if !structuredLogger.enabled {
		log.Printf("[%s] %s", level, message)
		return
	}

	entry := StructuredLogEntry{
		Timestamp: time.Now(),
		Level:     level,
		Message:   message,
	}

	if len(fields) > 0 {
		entry.Context = make(map[string]interface{})
		for _, field := range fields {
			for k, v := range field {
				switch k {
				case "operation":
					entry.Operation = fmt.Sprintf("%v", v)
				case "region":
					entry.Region = fmt.Sprintf("%v", v)
				case "resource":
					entry.Resource = fmt.Sprintf("%v", v)
				case "error":
					entry.Error = fmt.Sprintf("%v", v)
				case "metrics":
					if m, ok := v.(map[string]interface{}); ok {
						entry.Metrics = m
					}
				default:
					entry.Context[k] = v
				}
			}
		}
	}

	jsonBytes, err := json.Marshal(entry)
	if err != nil {
		log.Printf("[%s] %s", level, message)
		return
	}

	log.Println(string(jsonBytes))
}

// LogDebug logs a debug message
func LogDebug(message string, fields ...map[string]interface{}) {
	logStructured(LogLevelDebug, message, fields...)
}

// LogInfo logs an info message
func LogInfo(message string, fields ...map[string]interface{}) {
	logStructured(LogLevelInfo, message, fields...)
}

// LogWarn logs a warning message
func LogWarn(message string, fields ...map[string]interface{}) {
	logStructured(LogLevelWarn, message, fields...)
}

// LogError logs an error message
func LogError(message string, err error, fields ...map[string]interface{}) {
	errorFields := []map[string]interface{}{
		{"error": err.Error()},
	}
	errorFields = append(errorFields, fields...)
	logStructured(LogLevelError, message, errorFields...)
}

// LogOperationStart logs the start of an operation
func LogOperationStart(operation string, fields ...map[string]interface{}) {
	opFields := []map[string]interface{}{
		{"operation": operation},
	}
	opFields = append(opFields, fields...)
	LogInfo(fmt.Sprintf("Starting operation: %s", operation), opFields...)
}

// LogOperationEnd logs the end of an operation
func LogOperationEnd(operation string, duration time.Duration, success bool, itemsProcessed, itemsFound int, err error) {
	fields := []map[string]interface{}{
		{
			"operation":       operation,
			"duration_ms":     duration.Milliseconds(),
			"success":         success,
			"items_processed": itemsProcessed,
			"items_found":     itemsFound,
		},
	}
	if err != nil {
		fields = append(fields, map[string]interface{}{"error": err.Error()})
	}
	if success {
		LogInfo(fmt.Sprintf("Completed operation: %s", operation), fields...)
	} else {
		LogError(fmt.Sprintf("Failed operation: %s", operation), err, fields...)
	}
}

// LogAPICall logs an API call
func LogAPICall(apiName string, success bool, duration time.Duration, err error) {
	fields := []map[string]interface{}{
		{
			"api_name":    apiName,
			"success":     success,
			"duration_ms": duration.Milliseconds(),
		},
	}
	if err != nil {
		fields = append(fields, map[string]interface{}{"error": err.Error()})
	}
	if success {
		LogDebug(fmt.Sprintf("API call: %s", apiName), fields...)
	} else {
		LogWarn(fmt.Sprintf("API call failed: %s", apiName), fields...)
	}
}

// LogRegionOperation logs a region-specific operation
func LogRegionOperation(region string, operation string, success bool, resourcesFound int, err error) {
	fields := []map[string]interface{}{
		{
			"region":          region,
			"operation":       operation,
			"success":         success,
			"resources_found": resourcesFound,
		},
	}
	if err != nil {
		fields = append(fields, map[string]interface{}{"error": err.Error()})
	}
	if success {
		LogInfo(fmt.Sprintf("Region operation: %s in %s", operation, region), fields...)
	} else {
		LogWarn(fmt.Sprintf("Region operation failed: %s in %s", operation, region), fields...)
	}
}
