package logging

import (
	"fmt"
	"sync"
	"time"
)

// Metrics tracks API calls, success rates, and region failures
type Metrics struct {
	StartTime     time.Time                   `json:"start_time"`
	EndTime       time.Time                   `json:"end_time"`
	Duration      string                      `json:"duration"`
	APICalls      map[string]APICallMetrics   `json:"api_calls"`
	Regions       map[string]RegionMetrics    `json:"regions"`
	Operations    map[string]OperationMetrics `json:"operations"`
	TotalAPICalls int                         `json:"total_api_calls"`
	TotalSuccess  int                         `json:"total_success"`
	TotalFailures int                         `json:"total_failures"`
	mu            sync.RWMutex
}

// APICallMetrics tracks metrics for a specific API call
type APICallMetrics struct {
	Count       int      `json:"count"`
	Success     int      `json:"success"`
	Failures    int      `json:"failures"`
	SuccessRate float64  `json:"success_rate"`
	Errors      []string `json:"errors,omitempty"`
}

// RegionMetrics tracks metrics for a specific region
type RegionMetrics struct {
	APICalls       int      `json:"api_calls"`
	Success        int      `json:"success"`
	Failures       int      `json:"failures"`
	SuccessRate    float64  `json:"success_rate"`
	ResourcesFound int      `json:"resources_found"`
	Errors         []string `json:"errors,omitempty"`
}

// OperationMetrics tracks metrics for high-level operations
type OperationMetrics struct {
	Duration       time.Duration `json:"duration"`
	Success        bool          `json:"success"`
	Error          string        `json:"error,omitempty"`
	ItemsProcessed int           `json:"items_processed"`
	ItemsFound     int           `json:"items_found"`
}

var globalMetrics *Metrics
var metricsOnce sync.Once

// GetMetrics returns the global metrics instance (singleton)
func GetMetrics() *Metrics {
	metricsOnce.Do(func() {
		globalMetrics = &Metrics{
			StartTime:  time.Now(),
			APICalls:   make(map[string]APICallMetrics),
			Regions:    make(map[string]RegionMetrics),
			Operations: make(map[string]OperationMetrics),
		}
	})
	return globalMetrics
}

// RecordAPICall records an API call with success/failure
func (m *Metrics) RecordAPICall(apiName string, success bool, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.TotalAPICalls++
	if success {
		m.TotalSuccess++
	} else {
		m.TotalFailures++
	}

	metrics := m.APICalls[apiName]
	metrics.Count++
	if success {
		metrics.Success++
	} else {
		metrics.Failures++
		if err != nil && len(metrics.Errors) < 10 {
			metrics.Errors = append(metrics.Errors, err.Error())
		}
	}
	if metrics.Count > 0 {
		metrics.SuccessRate = float64(metrics.Success) / float64(metrics.Count) * 100
	}
	m.APICalls[apiName] = metrics
}

// RecordRegionOperation records an operation in a specific region
func (m *Metrics) RecordRegionOperation(region string, success bool, resourcesFound int, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	metrics := m.Regions[region]
	metrics.APICalls++
	if success {
		metrics.Success++
		metrics.ResourcesFound += resourcesFound
	} else {
		metrics.Failures++
		if err != nil && len(metrics.Errors) < 5 {
			metrics.Errors = append(metrics.Errors, fmt.Sprintf("%s: %v", region, err))
		}
	}
	if metrics.APICalls > 0 {
		metrics.SuccessRate = float64(metrics.Success) / float64(metrics.APICalls) * 100
	}
	m.Regions[region] = metrics
}

// RecordOperation records a high-level operation
func (m *Metrics) RecordOperation(operationName string, duration time.Duration, success bool, itemsProcessed, itemsFound int, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	opMetrics := OperationMetrics{
		Duration:       duration,
		Success:        success,
		ItemsProcessed: itemsProcessed,
		ItemsFound:     itemsFound,
	}
	if err != nil {
		opMetrics.Error = err.Error()
	}
	m.Operations[operationName] = opMetrics
}
