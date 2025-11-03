package logging

import (
	"fmt"
	"os"
)

// ConfigFromMap creates a ManagerConfig from a configuration map
// This avoids circular imports with the config package
func ConfigFromMap(configMap map[string]interface{}) (ManagerConfig, error) {
	config := ManagerConfig{
		Level:         InfoLevel,
		Verbose:       false,
		FileEnabled:   false,
		ConsoleOutput: os.Stdout,
	}

	// Parse log level
	if levelStr, ok := configMap["level"].(string); ok {
		level, err := ParseLogLevel(levelStr)
		if err != nil {
			return config, fmt.Errorf("invalid log level: %w", err)
		}
		config.Level = level
	}

	// Parse verbose flag
	if verbose, ok := configMap["verbose"].(bool); ok {
		config.Verbose = verbose
	}

	// Parse file logging settings
	if fileEnabled, ok := configMap["file_enabled"].(bool); ok {
		config.FileEnabled = fileEnabled
	}

	if filePath, ok := configMap["file_path"].(string); ok {
		config.FilePath = filePath
	}

	return config, nil
}

// DefaultConfig returns a default logging configuration
func DefaultConfig() ManagerConfig {
	return ManagerConfig{
		Level:         InfoLevel,
		Verbose:       false,
		FileEnabled:   false,
		ConsoleOutput: os.Stdout,
	}
}

// DebugConfig returns a debug logging configuration
func DebugConfig() ManagerConfig {
	return ManagerConfig{
		Level:         DebugLevel,
		Verbose:       true,
		FileEnabled:   true,
		FilePath:      "logs/debug.log",
		ConsoleOutput: os.Stdout,
	}
}

// ProductionConfig returns a production logging configuration
func ProductionConfig() ManagerConfig {
	return ManagerConfig{
		Level:         InfoLevel,
		Verbose:       false,
		FileEnabled:   true,
		FilePath:      "logs/ipv6-mtu-discovery.log",
		ConsoleOutput: os.Stdout,
	}
}
