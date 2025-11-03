package logging

import (
	"time"
)

// Convenience functions for global logging

// Debug logs a debug message using the global logger
func Debug(msg string) {
	GetGlobalLogger().Debug(msg)
}

// Debugf logs a formatted debug message using the global logger
func Debugf(format string, args ...interface{}) {
	GetGlobalLogger().Debugf(format, args...)
}

// Info logs an info message using the global logger
func Info(msg string) {
	GetGlobalLogger().Info(msg)
}

// Infof logs a formatted info message using the global logger
func Infof(format string, args ...interface{}) {
	GetGlobalLogger().Infof(format, args...)
}

// Warn logs a warning message using the global logger
func Warn(msg string) {
	GetGlobalLogger().Warn(msg)
}

// Warnf logs a formatted warning message using the global logger
func Warnf(format string, args ...interface{}) {
	GetGlobalLogger().Warnf(format, args...)
}

// Error logs an error message using the global logger
func Error(msg string) {
	GetGlobalLogger().Error(msg)
}

// Errorf logs a formatted error message using the global logger
func Errorf(format string, args ...interface{}) {
	GetGlobalLogger().Errorf(format, args...)
}

// WithField creates a logger with a field using the global logger
func WithField(key string, value interface{}) *Logger {
	return GetGlobalLogger().WithField(key, value)
}

// WithFields creates a logger with fields using the global logger
func WithFields(fields map[string]interface{}) *Logger {
	return GetGlobalLogger().WithFields(fields)
}

// WithError creates a logger with an error using the global logger
func WithError(err error) *Logger {
	return GetGlobalLogger().WithError(err)
}

// Component-specific logging helpers

// LogProbeStart logs the start of a probe operation
func LogProbeStart(component, target string, probeType string) {
	GetLogger(component).WithFields(map[string]interface{}{
		"target":     target,
		"probe_type": probeType,
		"action":     "start",
	}).Info("Starting probe operation")
}

// LogProbeResult logs the result of a probe operation
func LogProbeResult(component string, success bool, duration time.Duration, details map[string]interface{}) {
	logger := GetLogger(component).WithFields(map[string]interface{}{
		"success":  success,
		"duration": duration.String(),
		"action":   "result",
	})

	if details != nil {
		logger = logger.WithFields(details)
	}

	if success {
		logger.Info("Probe operation completed successfully")
	} else {
		logger.Warn("Probe operation failed")
	}
}

// LogNetworkOperation logs a network operation
func LogNetworkOperation(component, operation string, details map[string]interface{}) {
	logger := GetLogger(component).WithFields(map[string]interface{}{
		"operation": operation,
		"type":      "network",
	})

	if details != nil {
		logger = logger.WithFields(details)
	}

	logger.Debug("Network operation")
}

// LogError logs an error with context
func LogError(component string, err error, context map[string]interface{}) {
	logger := GetLogger(component).WithError(err)

	if context != nil {
		logger = logger.WithFields(context)
	}

	logger.Error("Operation failed")
}

// LogMTUDiscovery logs MTU discovery events
func LogMTUDiscovery(target string, currentMTU, minMTU, maxMTU int, iteration int) {
	GetLogger("mtu").WithFields(map[string]interface{}{
		"target":      target,
		"current_mtu": currentMTU,
		"min_mtu":     minMTU,
		"max_mtu":     maxMTU,
		"iteration":   iteration,
	}).Debug("MTU discovery iteration")
}

// LogMSSDetection logs MSS detection events
func LogMSSDetection(target string, port int, mode string, mss int) {
	GetLogger("mss").WithFields(map[string]interface{}{
		"target": target,
		"port":   port,
		"mode":   mode,
		"mss":    mss,
	}).Debug("MSS detection operation")
}

// LogTCPConnection logs TCP connection events
func LogTCPConnection(component, action string, localAddr, remoteAddr string, success bool) {
	logger := GetLogger(component).WithFields(map[string]interface{}{
		"action":      action,
		"local_addr":  localAddr,
		"remote_addr": remoteAddr,
		"success":     success,
		"type":        "tcp_connection",
	})

	if success {
		logger.Debug("TCP connection operation successful")
	} else {
		logger.Warn("TCP connection operation failed")
	}
}

// LogPacketOperation logs packet send/receive operations
func LogPacketOperation(component, operation string, packetType string, size int, success bool) {
	GetLogger(component).WithFields(map[string]interface{}{
		"operation":   operation,
		"packet_type": packetType,
		"size":        size,
		"success":     success,
	}).Debug("Packet operation")
}

// LogConfigurationChange logs configuration changes
func LogConfigurationChange(component, setting string, oldValue, newValue interface{}) {
	GetLogger(component).WithFields(map[string]interface{}{
		"setting":   setting,
		"old_value": oldValue,
		"new_value": newValue,
		"action":    "config_change",
	}).Info("Configuration changed")
}

// LogPerformanceMetric logs performance metrics
func LogPerformanceMetric(component, metric string, value interface{}, unit string) {
	GetLogger(component).WithFields(map[string]interface{}{
		"metric": metric,
		"value":  value,
		"unit":   unit,
		"type":   "performance",
	}).Debug("Performance metric")
}

// LogRetryAttempt logs retry attempts
func LogRetryAttempt(component string, attempt, maxAttempts int, delay time.Duration, reason string) {
	GetLogger(component).WithFields(map[string]interface{}{
		"attempt":      attempt,
		"max_attempts": maxAttempts,
		"delay":        delay.String(),
		"reason":       reason,
		"action":       "retry",
	}).Debug("Retry attempt")
}

// LogResourceUsage logs resource usage information
func LogResourceUsage(component string, resourceType string, usage interface{}) {
	GetLogger(component).WithFields(map[string]interface{}{
		"resource_type": resourceType,
		"usage":         usage,
		"type":          "resource",
	}).Debug("Resource usage")
}

// LogSecurityEvent logs security-related events
func LogSecurityEvent(component, event string, details map[string]interface{}) {
	logger := GetLogger(component).WithFields(map[string]interface{}{
		"event": event,
		"type":  "security",
	})

	if details != nil {
		logger = logger.WithFields(details)
	}

	logger.Warn("Security event")
}

// LogSystemInfo logs system information
func LogSystemInfo(component string, info map[string]interface{}) {
	GetLogger(component).WithFields(info).WithField("type", "system_info").Info("System information")
}

// Structured logging for specific operations

// ProbeLogger provides structured logging for probe operations
type ProbeLogger struct {
	logger    *Logger
	target    string
	probeType string
	startTime time.Time
}

// NewProbeLogger creates a new probe logger
func NewProbeLogger(component, target, probeType string) *ProbeLogger {
	return &ProbeLogger{
		logger:    GetLogger(component),
		target:    target,
		probeType: probeType,
		startTime: time.Now(),
	}
}

// LogStart logs the start of the probe
func (pl *ProbeLogger) LogStart() {
	pl.logger.WithFields(map[string]interface{}{
		"target":     pl.target,
		"probe_type": pl.probeType,
		"action":     "start",
	}).Info("Starting probe operation")
}

// LogProgress logs probe progress
func (pl *ProbeLogger) LogProgress(progress string, details map[string]interface{}) {
	logger := pl.logger.WithFields(map[string]interface{}{
		"target":     pl.target,
		"probe_type": pl.probeType,
		"action":     "progress",
		"progress":   progress,
	})

	if details != nil {
		logger = logger.WithFields(details)
	}

	logger.Debug("Probe progress")
}

// LogResult logs the final result
func (pl *ProbeLogger) LogResult(success bool, result interface{}, err error) {
	duration := time.Since(pl.startTime)

	logger := pl.logger.WithFields(map[string]interface{}{
		"target":     pl.target,
		"probe_type": pl.probeType,
		"action":     "result",
		"success":    success,
		"duration":   duration.String(),
	})

	if result != nil {
		logger = logger.WithField("result", result)
	}

	if err != nil {
		logger = logger.WithError(err)
	}

	if success {
		logger.Info("Probe operation completed successfully")
	} else {
		logger.Error("Probe operation failed")
	}
}

// NetworkLogger provides structured logging for network operations
type NetworkLogger struct {
	logger    *Logger
	operation string
	startTime time.Time
}

// NewNetworkLogger creates a new network logger
func NewNetworkLogger(component, operation string) *NetworkLogger {
	return &NetworkLogger{
		logger:    GetLogger(component),
		operation: operation,
		startTime: time.Now(),
	}
}

// LogAttempt logs a network operation attempt
func (nl *NetworkLogger) LogAttempt(details map[string]interface{}) {
	logger := nl.logger.WithFields(map[string]interface{}{
		"operation": nl.operation,
		"action":    "attempt",
		"type":      "network",
	})

	if details != nil {
		logger = logger.WithFields(details)
	}

	logger.Debug("Network operation attempt")
}

// LogSuccess logs a successful network operation
func (nl *NetworkLogger) LogSuccess(details map[string]interface{}) {
	duration := time.Since(nl.startTime)

	logger := nl.logger.WithFields(map[string]interface{}{
		"operation": nl.operation,
		"action":    "success",
		"type":      "network",
		"duration":  duration.String(),
	})

	if details != nil {
		logger = logger.WithFields(details)
	}

	logger.Debug("Network operation successful")
}

// LogFailure logs a failed network operation
func (nl *NetworkLogger) LogFailure(err error, details map[string]interface{}) {
	duration := time.Since(nl.startTime)

	logger := nl.logger.WithFields(map[string]interface{}{
		"operation": nl.operation,
		"action":    "failure",
		"type":      "network",
		"duration":  duration.String(),
	}).WithError(err)

	if details != nil {
		logger = logger.WithFields(details)
	}

	logger.Warn("Network operation failed")
}
