package logging

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// Manager manages global logging configuration and provides logger instances
type Manager struct {
	mu            sync.RWMutex
	defaultLogger *Logger
	loggers       map[string]*Logger
	config        ManagerConfig
}

// ManagerConfig contains configuration for the logging manager
type ManagerConfig struct {
	Level         LogLevel
	Verbose       bool
	FilePath      string
	FileEnabled   bool
	ConsoleOutput io.Writer
}

var (
	globalManager *Manager
	managerOnce   sync.Once
)

// InitializeGlobalLogger initializes the global logging manager
func InitializeGlobalLogger(config ManagerConfig) error {
	var err error
	managerOnce.Do(func() {
		globalManager, err = NewManager(config)
	})
	return err
}

// GetGlobalLogger returns the global default logger
func GetGlobalLogger() *Logger {
	if globalManager == nil {
		// Initialize with default config if not already initialized
		_ = InitializeGlobalLogger(ManagerConfig{
			Level:         InfoLevel,
			Verbose:       false,
			FileEnabled:   false,
			ConsoleOutput: os.Stdout,
		})
	}
	return globalManager.GetDefaultLogger()
}

// GetLogger returns a logger for the specified component
func GetLogger(component string) *Logger {
	if globalManager == nil {
		// Initialize with default config if not already initialized
		_ = InitializeGlobalLogger(ManagerConfig{
			Level:         InfoLevel,
			Verbose:       false,
			FileEnabled:   false,
			ConsoleOutput: os.Stdout,
		})
	}
	return globalManager.GetLogger(component)
}

// SetGlobalLevel sets the log level for all loggers
func SetGlobalLevel(level LogLevel) {
	if globalManager != nil {
		globalManager.SetLevel(level)
	}
}

// CloseGlobalLogger closes the global logging manager
func CloseGlobalLogger() error {
	if globalManager != nil {
		return globalManager.Close()
	}
	return nil
}

// NewManager creates a new logging manager
func NewManager(config ManagerConfig) (*Manager, error) {
	manager := &Manager{
		loggers: make(map[string]*Logger),
		config:  config,
	}

	// Create default logger
	loggerConfig := LoggerConfig{
		Level:     config.Level,
		Output:    config.ConsoleOutput,
		Verbose:   config.Verbose,
		Component: "app",
	}

	// Set up file output if enabled
	if config.FileEnabled && config.FilePath != "" {
		loggerConfig.FilePath = config.FilePath
	}

	defaultLogger, err := NewLogger(loggerConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create default logger: %w", err)
	}

	manager.defaultLogger = defaultLogger
	manager.loggers["default"] = defaultLogger

	return manager, nil
}

// GetDefaultLogger returns the default logger
func (m *Manager) GetDefaultLogger() *Logger {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.defaultLogger
}

// GetLogger returns a logger for the specified component
func (m *Manager) GetLogger(component string) *Logger {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Return existing logger if found
	if logger, exists := m.loggers[component]; exists {
		return logger
	}

	// Create new logger for component
	loggerConfig := LoggerConfig{
		Level:     m.config.Level,
		Output:    m.config.ConsoleOutput,
		Verbose:   m.config.Verbose,
		Component: component,
	}

	// Set up file output if enabled
	if m.config.FileEnabled && m.config.FilePath != "" {
		// Create component-specific log file path
		dir := filepath.Dir(m.config.FilePath)
		ext := filepath.Ext(m.config.FilePath)
		base := filepath.Base(m.config.FilePath)
		baseName := base[:len(base)-len(ext)]

		componentLogPath := filepath.Join(dir, fmt.Sprintf("%s-%s%s", baseName, component, ext))
		loggerConfig.FilePath = componentLogPath
	}

	logger, err := NewLogger(loggerConfig)
	if err != nil {
		// Fall back to default logger if component logger creation fails
		m.defaultLogger.Warnf("Failed to create logger for component %s: %v", component, err)
		return m.defaultLogger
	}

	m.loggers[component] = logger
	return logger
}

// SetLevel sets the log level for all managed loggers
func (m *Manager) SetLevel(level LogLevel) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.config.Level = level

	// Update all existing loggers
	for _, logger := range m.loggers {
		logger.SetLevel(level)
	}
}

// SetVerbose sets verbose mode for all managed loggers
func (m *Manager) SetVerbose(verbose bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.config.Verbose = verbose

	// Note: Existing loggers retain their verbose setting
	// New loggers will use the updated setting
}

// EnableFileLogging enables file logging with the specified path
func (m *Manager) EnableFileLogging(filePath string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.config.FileEnabled = true
	m.config.FilePath = filePath

	// Update existing loggers to add file output
	for component, logger := range m.loggers {
		if logger.fileOutput == nil {
			var componentLogPath string
			if component == "default" {
				componentLogPath = filePath
			} else {
				dir := filepath.Dir(filePath)
				ext := filepath.Ext(filePath)
				base := filepath.Base(filePath)
				baseName := base[:len(base)-len(ext)]
				componentLogPath = filepath.Join(dir, fmt.Sprintf("%s-%s%s", baseName, component, ext))
			}

			if err := logger.setupFileOutput(componentLogPath); err != nil {
				return fmt.Errorf("failed to enable file logging for component %s: %w", component, err)
			}
		}
	}

	return nil
}

// DisableFileLogging disables file logging
func (m *Manager) DisableFileLogging() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.config.FileEnabled = false
	m.config.FilePath = ""

	// Note: Existing loggers retain their file outputs
	// This only affects new loggers
}

// GetConfig returns the current manager configuration
func (m *Manager) GetConfig() ManagerConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.config
}

// ListComponents returns a list of all registered component names
func (m *Manager) ListComponents() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	components := make([]string, 0, len(m.loggers))
	for component := range m.loggers {
		if component != "default" {
			components = append(components, component)
		}
	}

	return components
}

// Close closes all managed loggers
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var lastErr error

	// Close all loggers
	for _, logger := range m.loggers {
		if err := logger.Close(); err != nil {
			lastErr = err
		}
	}

	// Clear loggers map
	m.loggers = make(map[string]*Logger)
	m.defaultLogger = nil

	return lastErr
}

// Sync flushes all managed loggers
func (m *Manager) Sync() error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var lastErr error

	// Sync all loggers
	for _, logger := range m.loggers {
		if err := logger.Sync(); err != nil {
			lastErr = err
		}
	}

	return lastErr
}

// GetStats returns statistics about the logging manager
func (m *Manager) GetStats() ManagerStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return ManagerStats{
		TotalLoggers:       len(m.loggers),
		FileLoggingEnabled: m.config.FileEnabled,
		CurrentLevel:       m.config.Level,
		VerboseMode:        m.config.Verbose,
		Components:         m.ListComponents(),
	}
}

// ManagerStats contains statistics about the logging manager
type ManagerStats struct {
	TotalLoggers       int      `json:"total_loggers"`
	FileLoggingEnabled bool     `json:"file_logging_enabled"`
	CurrentLevel       LogLevel `json:"current_level"`
	VerboseMode        bool     `json:"verbose_mode"`
	Components         []string `json:"components"`
}
