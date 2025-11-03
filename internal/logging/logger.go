package logging

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// LogLevel represents the severity level of a log message
type LogLevel int

const (
	// DebugLevel logs are typically voluminous, and are usually disabled in production
	DebugLevel LogLevel = iota
	// InfoLevel is the default logging priority
	InfoLevel
	// WarnLevel logs are more important than Info, but don't need individual human review
	WarnLevel
	// ErrorLevel logs are high-priority. If an application is running smoothly, it shouldn't generate any error-level logs
	ErrorLevel
)

// String returns the string representation of the log level
func (l LogLevel) String() string {
	switch l {
	case DebugLevel:
		return "DEBUG"
	case InfoLevel:
		return "INFO"
	case WarnLevel:
		return "WARN"
	case ErrorLevel:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}

// ParseLogLevel parses a string into a LogLevel
func ParseLogLevel(level string) (LogLevel, error) {
	switch strings.ToUpper(level) {
	case "DEBUG":
		return DebugLevel, nil
	case "INFO":
		return InfoLevel, nil
	case "WARN", "WARNING":
		return WarnLevel, nil
	case "ERROR":
		return ErrorLevel, nil
	default:
		return InfoLevel, fmt.Errorf("invalid log level: %s", level)
	}
}

// LogEntry represents a single log entry
type LogEntry struct {
	Timestamp time.Time              `json:"timestamp"`
	Level     LogLevel               `json:"level"`
	Message   string                 `json:"message"`
	Fields    map[string]interface{} `json:"fields,omitempty"`
	Component string                 `json:"component,omitempty"`
	Error     string                 `json:"error,omitempty"`
}

// Logger provides structured logging functionality
type Logger struct {
	mu         sync.RWMutex
	level      LogLevel
	output     io.Writer
	fileOutput io.Writer
	verbose    bool
	component  string
	fields     map[string]interface{}

	// Internal loggers for different outputs
	consoleLogger *log.Logger
	fileLogger    *log.Logger
}

// LoggerConfig contains configuration for creating a logger
type LoggerConfig struct {
	Level     LogLevel
	Output    io.Writer
	FilePath  string
	Verbose   bool
	Component string
	Fields    map[string]interface{}
}

// NewLogger creates a new logger with the given configuration
func NewLogger(config LoggerConfig) (*Logger, error) {
	logger := &Logger{
		level:     config.Level,
		output:    config.Output,
		verbose:   config.Verbose,
		component: config.Component,
		fields:    make(map[string]interface{}),
	}

	// Set default output if none provided
	if logger.output == nil {
		logger.output = os.Stdout
	}

	// Create console logger
	logger.consoleLogger = log.New(logger.output, "", 0)

	// Set up file output if specified
	if config.FilePath != "" {
		if err := logger.setupFileOutput(config.FilePath); err != nil {
			return nil, fmt.Errorf("failed to setup file output: %w", err)
		}
	}

	// Copy initial fields
	if config.Fields != nil {
		for k, v := range config.Fields {
			logger.fields[k] = v
		}
	}

	return logger, nil
}

// setupFileOutput sets up file logging
func (l *Logger) setupFileOutput(filePath string) error {
	// Create directory if it doesn't exist
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create log directory: %w", err)
	}

	// Open log file
	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}

	l.fileOutput = file
	l.fileLogger = log.New(file, "", 0)

	return nil
}

// WithField adds a field to the logger context
func (l *Logger) WithField(key string, value interface{}) *Logger {
	l.mu.RLock()

	// Create new logger without copying mutex
	newLogger := &Logger{
		level:         l.level,
		output:        l.output,
		fileOutput:    l.fileOutput,
		verbose:       l.verbose,
		component:     l.component,
		fields:        make(map[string]interface{}),
		consoleLogger: l.consoleLogger,
		fileLogger:    l.fileLogger,
	}

	// Copy existing fields
	for k, v := range l.fields {
		newLogger.fields[k] = v
	}

	// Add new field
	newLogger.fields[key] = value

	l.mu.RUnlock()
	return newLogger
}

// WithFields adds multiple fields to the logger context
func (l *Logger) WithFields(fields map[string]interface{}) *Logger {
	l.mu.RLock()

	// Create new logger without copying mutex
	newLogger := &Logger{
		level:         l.level,
		output:        l.output,
		fileOutput:    l.fileOutput,
		verbose:       l.verbose,
		component:     l.component,
		fields:        make(map[string]interface{}),
		consoleLogger: l.consoleLogger,
		fileLogger:    l.fileLogger,
	}

	// Copy existing fields
	for k, v := range l.fields {
		newLogger.fields[k] = v
	}

	// Add new fields
	for k, v := range fields {
		newLogger.fields[k] = v
	}

	l.mu.RUnlock()
	return newLogger
}

// WithComponent creates a new logger with a specific component name
func (l *Logger) WithComponent(component string) *Logger {
	l.mu.RLock()

	// Create new logger without copying mutex
	newLogger := &Logger{
		level:         l.level,
		output:        l.output,
		fileOutput:    l.fileOutput,
		verbose:       l.verbose,
		component:     component,
		fields:        make(map[string]interface{}),
		consoleLogger: l.consoleLogger,
		fileLogger:    l.fileLogger,
	}

	// Copy existing fields
	for k, v := range l.fields {
		newLogger.fields[k] = v
	}

	l.mu.RUnlock()
	return newLogger
}

// WithError adds an error to the logger context
func (l *Logger) WithError(err error) *Logger {
	if err == nil {
		return l
	}
	return l.WithField("error", err.Error())
}

// SetLevel sets the minimum log level
func (l *Logger) SetLevel(level LogLevel) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.level = level
}

// GetLevel returns the current log level
func (l *Logger) GetLevel() LogLevel {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.level
}

// IsLevelEnabled returns true if the given level is enabled
func (l *Logger) IsLevelEnabled(level LogLevel) bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return level >= l.level
}

// Debug logs a debug message
func (l *Logger) Debug(msg string) {
	l.log(DebugLevel, msg, nil)
}

// Debugf logs a formatted debug message
func (l *Logger) Debugf(format string, args ...interface{}) {
	l.log(DebugLevel, fmt.Sprintf(format, args...), nil)
}

// Info logs an info message
func (l *Logger) Info(msg string) {
	l.log(InfoLevel, msg, nil)
}

// Infof logs a formatted info message
func (l *Logger) Infof(format string, args ...interface{}) {
	l.log(InfoLevel, fmt.Sprintf(format, args...), nil)
}

// Warn logs a warning message
func (l *Logger) Warn(msg string) {
	l.log(WarnLevel, msg, nil)
}

// Warnf logs a formatted warning message
func (l *Logger) Warnf(format string, args ...interface{}) {
	l.log(WarnLevel, fmt.Sprintf(format, args...), nil)
}

// Error logs an error message
func (l *Logger) Error(msg string) {
	l.log(ErrorLevel, msg, nil)
}

// Errorf logs a formatted error message
func (l *Logger) Errorf(format string, args ...interface{}) {
	l.log(ErrorLevel, fmt.Sprintf(format, args...), nil)
}

// log is the internal logging method
func (l *Logger) log(level LogLevel, message string, err error) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	// Check if level is enabled
	if level < l.level {
		return
	}

	// Create log entry
	entry := LogEntry{
		Timestamp: time.Now(),
		Level:     level,
		Message:   message,
		Component: l.component,
		Fields:    make(map[string]interface{}),
	}

	// Copy fields
	for k, v := range l.fields {
		entry.Fields[k] = v
	}

	// Add error if provided
	if err != nil {
		entry.Error = err.Error()
	}

	// Format and write log entry
	l.writeEntry(entry)
}

// writeEntry writes a log entry to the configured outputs
func (l *Logger) writeEntry(entry LogEntry) {
	// Format for console output
	consoleMsg := l.formatConsoleMessage(entry)

	// Write to console
	if l.consoleLogger != nil {
		l.consoleLogger.Print(consoleMsg)
	}

	// Write to file if configured
	if l.fileLogger != nil {
		fileMsg := l.formatFileMessage(entry)
		l.fileLogger.Print(fileMsg)
	}
}

// formatConsoleMessage formats a log entry for console output
func (l *Logger) formatConsoleMessage(entry LogEntry) string {
	timestamp := entry.Timestamp.Format("15:04:05")

	var parts []string

	// Add timestamp and level
	levelStr := fmt.Sprintf("[%s]", entry.Level.String())
	parts = append(parts, fmt.Sprintf("%s %s", timestamp, levelStr))

	// Add component if present
	if entry.Component != "" {
		parts = append(parts, fmt.Sprintf("[%s]", entry.Component))
	}

	// Add message
	parts = append(parts, entry.Message)

	// Add fields in verbose mode
	if l.verbose && len(entry.Fields) > 0 {
		var fieldParts []string
		for k, v := range entry.Fields {
			fieldParts = append(fieldParts, fmt.Sprintf("%s=%v", k, v))
		}
		if len(fieldParts) > 0 {
			parts = append(parts, fmt.Sprintf("(%s)", strings.Join(fieldParts, ", ")))
		}
	}

	// Add error if present
	if entry.Error != "" {
		parts = append(parts, fmt.Sprintf("error=%s", entry.Error))
	}

	return strings.Join(parts, " ")
}

// formatFileMessage formats a log entry for file output (more detailed)
func (l *Logger) formatFileMessage(entry LogEntry) string {
	timestamp := entry.Timestamp.Format("2006-01-02 15:04:05.000")

	var parts []string

	// Add timestamp and level
	parts = append(parts, fmt.Sprintf("%s [%s]", timestamp, entry.Level.String()))

	// Add component if present
	if entry.Component != "" {
		parts = append(parts, fmt.Sprintf("[%s]", entry.Component))
	}

	// Add message
	parts = append(parts, entry.Message)

	// Add all fields
	if len(entry.Fields) > 0 {
		var fieldParts []string
		for k, v := range entry.Fields {
			fieldParts = append(fieldParts, fmt.Sprintf("%s=%v", k, v))
		}
		parts = append(parts, fmt.Sprintf("fields={%s}", strings.Join(fieldParts, ", ")))
	}

	// Add error if present
	if entry.Error != "" {
		parts = append(parts, fmt.Sprintf("error=%s", entry.Error))
	}

	return strings.Join(parts, " ")
}

// Close closes any file outputs
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.fileOutput != nil {
		if closer, ok := l.fileOutput.(io.Closer); ok {
			return closer.Close()
		}
	}

	return nil
}

// Sync flushes any buffered log entries
func (l *Logger) Sync() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if syncer, ok := l.fileOutput.(interface{ Sync() error }); ok {
		return syncer.Sync()
	}

	return nil
}
