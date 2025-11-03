package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/viper"
)

// Config represents the application configuration
type Config struct {
	Network                 NetworkConfig                 `mapstructure:"network" yaml:"network" json:"network"`
	MTU                     MTUConfig                     `mapstructure:"mtu" yaml:"mtu" json:"mtu"`
	TCP                     TCPConfig                     `mapstructure:"tcp" yaml:"tcp" json:"tcp"`
	MSSVerification         MSSVerificationConfig         `mapstructure:"mss_verification" yaml:"mss_verification" json:"mss_verification"`
	UnreachabilityDetection UnreachabilityDetectionConfig `mapstructure:"unreachability_detection" yaml:"unreachability_detection" json:"unreachability_detection"`
	Logging                 LoggingConfig                 `mapstructure:"logging" yaml:"logging" json:"logging"`
}

// NetworkConfig contains network-related configuration
type NetworkConfig struct {
	TimeoutMS       int `mapstructure:"timeout_ms" yaml:"timeout_ms" json:"timeout_ms"`
	MaxRetries      int `mapstructure:"max_retries" yaml:"max_retries" json:"max_retries"`
	ProbeIntervalMS int `mapstructure:"probe_interval_ms" yaml:"probe_interval_ms" json:"probe_interval_ms"`
}

// MTUConfig contains MTU-related configuration
type MTUConfig struct {
	MinSize int `mapstructure:"min_size" yaml:"min_size" json:"min_size"`
	MaxSize int `mapstructure:"max_size" yaml:"max_size" json:"max_size"`
}

// TCPConfig contains TCP-related configuration
type TCPConfig struct {
	DefaultPort        int `mapstructure:"default_port" yaml:"default_port" json:"default_port"`
	DefaultControlPort int `mapstructure:"default_control_port" yaml:"default_control_port" json:"default_control_port"`
	DefaultTestMSS     int `mapstructure:"default_test_mss" yaml:"default_test_mss" json:"default_test_mss"`
}

// MSSVerificationConfig contains MSS verification-related configuration
type MSSVerificationConfig struct {
	EnableIntegrityCheck bool `mapstructure:"enable_integrity_check" yaml:"enable_integrity_check" json:"enable_integrity_check"`
	SessionTimeoutMS     int  `mapstructure:"session_timeout_ms" yaml:"session_timeout_ms" json:"session_timeout_ms"`
	MaxSessions          int  `mapstructure:"max_sessions" yaml:"max_sessions" json:"max_sessions"`
	ControlPort          int  `mapstructure:"control_port" yaml:"control_port" json:"control_port"`
	TestMSS              int  `mapstructure:"test_mss" yaml:"test_mss" json:"test_mss"`
	RetryAttempts        int  `mapstructure:"retry_attempts" yaml:"retry_attempts" json:"retry_attempts"`
	HandshakeTimeoutMS   int  `mapstructure:"handshake_timeout_ms" yaml:"handshake_timeout_ms" json:"handshake_timeout_ms"`
}

// UnreachabilityDetectionConfig contains target unreachability detection configuration
type UnreachabilityDetectionConfig struct {
	EnablePreValidation         bool    `mapstructure:"enable_pre_validation" yaml:"enable_pre_validation" json:"enable_pre_validation"`
	PreValidationTimeoutMS      int     `mapstructure:"pre_validation_timeout_ms" yaml:"pre_validation_timeout_ms" json:"pre_validation_timeout_ms"`
	PreValidationRetries        int     `mapstructure:"pre_validation_retries" yaml:"pre_validation_retries" json:"pre_validation_retries"`
	ConsecutiveFailureThreshold int     `mapstructure:"consecutive_failure_threshold" yaml:"consecutive_failure_threshold" json:"consecutive_failure_threshold"`
	TotalFailureThreshold       float64 `mapstructure:"total_failure_threshold" yaml:"total_failure_threshold" json:"total_failure_threshold"`
	TimeoutThresholdMS          int     `mapstructure:"timeout_threshold_ms" yaml:"timeout_threshold_ms" json:"timeout_threshold_ms"`
	EnablePatternAnalysis       bool    `mapstructure:"enable_pattern_analysis" yaml:"enable_pattern_analysis" json:"enable_pattern_analysis"`
	MinProbesForAnalysis        int     `mapstructure:"min_probes_for_analysis" yaml:"min_probes_for_analysis" json:"min_probes_for_analysis"`
	ConfidenceThreshold         float64 `mapstructure:"confidence_threshold" yaml:"confidence_threshold" json:"confidence_threshold"`
	CacheTTLSeconds             int     `mapstructure:"cache_ttl_seconds" yaml:"cache_ttl_seconds" json:"cache_ttl_seconds"`
	MaxCacheEntries             int     `mapstructure:"max_cache_entries" yaml:"max_cache_entries" json:"max_cache_entries"`
}

// LoggingConfig contains logging configuration
type LoggingConfig struct {
	Level       string `mapstructure:"level" yaml:"level" json:"level"`
	Verbose     bool   `mapstructure:"verbose" yaml:"verbose" json:"verbose"`
	FileEnabled bool   `mapstructure:"file_enabled" yaml:"file_enabled" json:"file_enabled"`
	FilePath    string `mapstructure:"file_path" yaml:"file_path" json:"file_path"`
	MaxFileSize int64  `mapstructure:"max_file_size" yaml:"max_file_size" json:"max_file_size"` // in bytes
	MaxBackups  int    `mapstructure:"max_backups" yaml:"max_backups" json:"max_backups"`
}

// AppConfig is an alias for Config for backward compatibility
type AppConfig = Config

// Default configuration constants
const (
	DefaultTimeoutMS            = 5000
	DefaultMaxRetries           = 3
	DefaultMinMTUSize           = 68
	DefaultMaxMTUSize           = 1500
	DefaultTCPPort              = 80
	DefaultControlPort          = 8080
	DefaultTestMSS              = 1460 // 故意使用较大的MSS值进行测试
	DefaultProbeInterval        = 100  // ms
	DefaultLogLevel             = "info"
	DefaultVerbose              = false
	DefaultFileEnabled          = false
	DefaultLogFilePath          = "logs/ipv6-mtu-discovery.log"
	DefaultMaxFileSize          = 10 * 1024 * 1024 // 10MB
	DefaultMaxBackups           = 5
	DefaultSessionTimeoutMS     = 30000 // ms
	DefaultMaxSessions          = 10
	DefaultMSSRetryAttempts     = 3
	DefaultHandshakeTimeoutMS   = 5000 // ms
	DefaultEnableIntegrityCheck = false

	// Unreachability detection defaults
	DefaultEnablePreValidation         = true
	DefaultPreValidationTimeoutMS      = 5000
	DefaultPreValidationRetries        = 2
	DefaultConsecutiveFailureThreshold = 3
	DefaultTotalFailureThreshold       = 0.8   // 80% failure rate
	DefaultTimeoutThresholdMS          = 10000 // 10 seconds
	DefaultEnablePatternAnalysis       = true
	DefaultMinProbesForAnalysis        = 5
	DefaultConfidenceThreshold         = 0.7 // 70% confidence
	DefaultCacheTTLSeconds             = 300 // 5 minutes
	DefaultMaxCacheEntries             = 100
)

// GetDefaultConfig returns a configuration with default values
func GetDefaultConfig() *Config {
	return &Config{
		Network: NetworkConfig{
			TimeoutMS:       DefaultTimeoutMS,
			MaxRetries:      DefaultMaxRetries,
			ProbeIntervalMS: DefaultProbeInterval,
		},
		MTU: MTUConfig{
			MinSize: DefaultMinMTUSize,
			MaxSize: DefaultMaxMTUSize,
		},
		TCP: TCPConfig{
			DefaultPort:        DefaultTCPPort,
			DefaultControlPort: DefaultControlPort,
			DefaultTestMSS:     DefaultTestMSS,
		},
		MSSVerification: MSSVerificationConfig{
			EnableIntegrityCheck: DefaultEnableIntegrityCheck,
			SessionTimeoutMS:     DefaultSessionTimeoutMS,
			MaxSessions:          DefaultMaxSessions,
			ControlPort:          DefaultControlPort,
			TestMSS:              DefaultTestMSS,
			RetryAttempts:        DefaultMSSRetryAttempts,
			HandshakeTimeoutMS:   DefaultHandshakeTimeoutMS,
		},
		UnreachabilityDetection: UnreachabilityDetectionConfig{
			EnablePreValidation:         DefaultEnablePreValidation,
			PreValidationTimeoutMS:      DefaultPreValidationTimeoutMS,
			PreValidationRetries:        DefaultPreValidationRetries,
			ConsecutiveFailureThreshold: DefaultConsecutiveFailureThreshold,
			TotalFailureThreshold:       DefaultTotalFailureThreshold,
			TimeoutThresholdMS:          DefaultTimeoutThresholdMS,
			EnablePatternAnalysis:       DefaultEnablePatternAnalysis,
			MinProbesForAnalysis:        DefaultMinProbesForAnalysis,
			ConfidenceThreshold:         DefaultConfidenceThreshold,
			CacheTTLSeconds:             DefaultCacheTTLSeconds,
			MaxCacheEntries:             DefaultMaxCacheEntries,
		},
		Logging: LoggingConfig{
			Level:       DefaultLogLevel,
			Verbose:     DefaultVerbose,
			FileEnabled: DefaultFileEnabled,
			FilePath:    DefaultLogFilePath,
			MaxFileSize: DefaultMaxFileSize,
			MaxBackups:  DefaultMaxBackups,
		},
	}
}

// LoadConfig loads configuration from file or returns default configuration
func LoadConfig(configPath string) (*Config, error) {
	config := GetDefaultConfig()

	if configPath == "" {
		// Try to find config file in common locations
		configPath = findConfigFile()
	}

	if configPath != "" {
		viper.SetConfigFile(configPath)
	} else {
		// Set config name and paths for automatic discovery
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
		viper.AddConfigPath(".")
		viper.AddConfigPath("$HOME/.ipv6-mtu-discovery")
		viper.AddConfigPath("/etc/ipv6-mtu-discovery")
	}

	// Set environment variable prefix
	viper.SetEnvPrefix("IPV6_MTU")
	viper.AutomaticEnv()

	// Set default values
	setDefaultValues()

	// Try to read config file
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
		// Config file not found, use defaults
	}

	// Unmarshal config
	if err := viper.Unmarshal(config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return config, nil
}

// findConfigFile searches for config file in common locations
func findConfigFile() string {
	possiblePaths := []string{
		"config.yaml",
		"config.yml",
		"config.json",
		filepath.Join(os.Getenv("HOME"), ".ipv6-mtu-discovery", "config.yaml"),
		filepath.Join(os.Getenv("HOME"), ".ipv6-mtu-discovery", "config.yml"),
		"/etc/ipv6-mtu-discovery/config.yaml",
		"/etc/ipv6-mtu-discovery/config.yml",
	}

	for _, path := range possiblePaths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	return ""
}

// setDefaultValues sets default values in viper
func setDefaultValues() {
	viper.SetDefault("network.timeout_ms", DefaultTimeoutMS)
	viper.SetDefault("network.max_retries", DefaultMaxRetries)
	viper.SetDefault("network.probe_interval_ms", DefaultProbeInterval)
	viper.SetDefault("mtu.min_size", DefaultMinMTUSize)
	viper.SetDefault("mtu.max_size", DefaultMaxMTUSize)
	viper.SetDefault("tcp.default_port", DefaultTCPPort)
	viper.SetDefault("tcp.default_control_port", DefaultControlPort)
	viper.SetDefault("tcp.default_test_mss", DefaultTestMSS)
	viper.SetDefault("mss_verification.enable_integrity_check", DefaultEnableIntegrityCheck)
	viper.SetDefault("mss_verification.session_timeout_ms", DefaultSessionTimeoutMS)
	viper.SetDefault("mss_verification.max_sessions", DefaultMaxSessions)
	viper.SetDefault("mss_verification.control_port", DefaultControlPort)
	viper.SetDefault("mss_verification.test_mss", DefaultTestMSS)
	viper.SetDefault("mss_verification.retry_attempts", DefaultMSSRetryAttempts)
	viper.SetDefault("mss_verification.handshake_timeout_ms", DefaultHandshakeTimeoutMS)
	viper.SetDefault("logging.level", DefaultLogLevel)
	viper.SetDefault("logging.verbose", DefaultVerbose)
	viper.SetDefault("logging.file_enabled", DefaultFileEnabled)
	viper.SetDefault("logging.file_path", DefaultLogFilePath)
	viper.SetDefault("logging.max_file_size", DefaultMaxFileSize)
	viper.SetDefault("logging.max_backups", DefaultMaxBackups)
	viper.SetDefault("unreachability_detection.enable_pre_validation", DefaultEnablePreValidation)
	viper.SetDefault("unreachability_detection.pre_validation_timeout_ms", DefaultPreValidationTimeoutMS)
	viper.SetDefault("unreachability_detection.pre_validation_retries", DefaultPreValidationRetries)
	viper.SetDefault("unreachability_detection.consecutive_failure_threshold", DefaultConsecutiveFailureThreshold)
	viper.SetDefault("unreachability_detection.total_failure_threshold", DefaultTotalFailureThreshold)
	viper.SetDefault("unreachability_detection.timeout_threshold_ms", DefaultTimeoutThresholdMS)
	viper.SetDefault("unreachability_detection.enable_pattern_analysis", DefaultEnablePatternAnalysis)
	viper.SetDefault("unreachability_detection.min_probes_for_analysis", DefaultMinProbesForAnalysis)
	viper.SetDefault("unreachability_detection.confidence_threshold", DefaultConfidenceThreshold)
	viper.SetDefault("unreachability_detection.cache_ttl_seconds", DefaultCacheTTLSeconds)
	viper.SetDefault("unreachability_detection.max_cache_entries", DefaultMaxCacheEntries)
}

// Validate validates the configuration values
func (c *Config) Validate() error {
	// Validate network configuration
	if c.Network.TimeoutMS <= 0 {
		return fmt.Errorf("network timeout must be positive, got %d", c.Network.TimeoutMS)
	}
	if c.Network.TimeoutMS > 60000 {
		return fmt.Errorf("network timeout too large, maximum 60000ms, got %d", c.Network.TimeoutMS)
	}
	if c.Network.MaxRetries < 0 {
		return fmt.Errorf("max retries cannot be negative, got %d", c.Network.MaxRetries)
	}
	if c.Network.MaxRetries > 10 {
		return fmt.Errorf("max retries too large, maximum 10, got %d", c.Network.MaxRetries)
	}
	if c.Network.ProbeIntervalMS < 0 {
		return fmt.Errorf("probe interval cannot be negative, got %d", c.Network.ProbeIntervalMS)
	}

	// Validate MTU configuration
	if c.MTU.MinSize < 68 {
		return fmt.Errorf("minimum MTU size cannot be less than 68, got %d", c.MTU.MinSize)
	}
	if c.MTU.MaxSize > 9000 {
		return fmt.Errorf("maximum MTU size cannot be greater than 9000, got %d", c.MTU.MaxSize)
	}
	if c.MTU.MinSize >= c.MTU.MaxSize {
		return fmt.Errorf("minimum MTU size (%d) must be less than maximum MTU size (%d)", c.MTU.MinSize, c.MTU.MaxSize)
	}

	// Validate TCP configuration
	if c.TCP.DefaultPort <= 0 || c.TCP.DefaultPort > 65535 {
		return fmt.Errorf("TCP port must be between 1 and 65535, got %d", c.TCP.DefaultPort)
	}
	if c.TCP.DefaultControlPort <= 0 || c.TCP.DefaultControlPort > 65535 {
		return fmt.Errorf("TCP control port must be between 1 and 65535, got %d", c.TCP.DefaultControlPort)
	}
	if c.TCP.DefaultControlPort == c.TCP.DefaultPort {
		return fmt.Errorf("TCP control port (%d) cannot be the same as default port (%d)", c.TCP.DefaultControlPort, c.TCP.DefaultPort)
	}
	if c.TCP.DefaultTestMSS <= 0 || c.TCP.DefaultTestMSS > 9000 {
		return fmt.Errorf("TCP test MSS must be between 1 and 9000, got %d", c.TCP.DefaultTestMSS)
	}

	// Validate MSS verification configuration
	if c.MSSVerification.SessionTimeoutMS <= 0 {
		return fmt.Errorf("MSS verification session timeout must be positive, got %d", c.MSSVerification.SessionTimeoutMS)
	}
	if c.MSSVerification.SessionTimeoutMS > 300000 { // 5 minutes max
		return fmt.Errorf("MSS verification session timeout too large, maximum 300000ms, got %d", c.MSSVerification.SessionTimeoutMS)
	}
	if c.MSSVerification.MaxSessions <= 0 {
		return fmt.Errorf("MSS verification max sessions must be positive, got %d", c.MSSVerification.MaxSessions)
	}
	if c.MSSVerification.MaxSessions > 100 {
		return fmt.Errorf("MSS verification max sessions too large, maximum 100, got %d", c.MSSVerification.MaxSessions)
	}
	if c.MSSVerification.ControlPort <= 0 || c.MSSVerification.ControlPort > 65535 {
		return fmt.Errorf("MSS verification control port must be between 1 and 65535, got %d", c.MSSVerification.ControlPort)
	}
	if c.MSSVerification.TestMSS <= 0 || c.MSSVerification.TestMSS > 9000 {
		return fmt.Errorf("MSS verification test MSS must be between 1 and 9000, got %d", c.MSSVerification.TestMSS)
	}
	if c.MSSVerification.RetryAttempts < 0 || c.MSSVerification.RetryAttempts > 10 {
		return fmt.Errorf("MSS verification retry attempts must be between 0 and 10, got %d", c.MSSVerification.RetryAttempts)
	}
	if c.MSSVerification.HandshakeTimeoutMS <= 0 {
		return fmt.Errorf("MSS verification handshake timeout must be positive, got %d", c.MSSVerification.HandshakeTimeoutMS)
	}
	if c.MSSVerification.HandshakeTimeoutMS > 60000 {
		return fmt.Errorf("MSS verification handshake timeout too large, maximum 60000ms, got %d", c.MSSVerification.HandshakeTimeoutMS)
	}

	// Validate logging configuration
	validLogLevels := map[string]bool{
		"debug": true,
		"info":  true,
		"warn":  true,
		"error": true,
	}
	if !validLogLevels[c.Logging.Level] {
		return fmt.Errorf("invalid log level '%s', must be one of: debug, info, warn, error", c.Logging.Level)
	}
	if c.Logging.FileEnabled && c.Logging.FilePath == "" {
		return fmt.Errorf("log file path is required when file logging is enabled")
	}
	if c.Logging.MaxFileSize <= 0 {
		return fmt.Errorf("max file size must be positive, got %d", c.Logging.MaxFileSize)
	}
	if c.Logging.MaxBackups < 0 {
		return fmt.Errorf("max backups cannot be negative, got %d", c.Logging.MaxBackups)
	}

	// Validate unreachability detection configuration
	if c.UnreachabilityDetection.PreValidationTimeoutMS <= 0 {
		return fmt.Errorf("pre-validation timeout must be positive, got %d", c.UnreachabilityDetection.PreValidationTimeoutMS)
	}
	if c.UnreachabilityDetection.PreValidationTimeoutMS > 60000 {
		return fmt.Errorf("pre-validation timeout too large, maximum 60000ms, got %d", c.UnreachabilityDetection.PreValidationTimeoutMS)
	}
	if c.UnreachabilityDetection.PreValidationRetries < 0 {
		return fmt.Errorf("pre-validation retries cannot be negative, got %d", c.UnreachabilityDetection.PreValidationRetries)
	}
	if c.UnreachabilityDetection.PreValidationRetries > 10 {
		return fmt.Errorf("pre-validation retries too large, maximum 10, got %d", c.UnreachabilityDetection.PreValidationRetries)
	}
	if c.UnreachabilityDetection.ConsecutiveFailureThreshold <= 0 {
		return fmt.Errorf("consecutive failure threshold must be positive, got %d", c.UnreachabilityDetection.ConsecutiveFailureThreshold)
	}
	if c.UnreachabilityDetection.ConsecutiveFailureThreshold > 20 {
		return fmt.Errorf("consecutive failure threshold too large, maximum 20, got %d", c.UnreachabilityDetection.ConsecutiveFailureThreshold)
	}
	if c.UnreachabilityDetection.TotalFailureThreshold < 0.0 || c.UnreachabilityDetection.TotalFailureThreshold > 1.0 {
		return fmt.Errorf("total failure threshold must be between 0.0 and 1.0, got %f", c.UnreachabilityDetection.TotalFailureThreshold)
	}
	if c.UnreachabilityDetection.TimeoutThresholdMS <= 0 {
		return fmt.Errorf("timeout threshold must be positive, got %d", c.UnreachabilityDetection.TimeoutThresholdMS)
	}
	if c.UnreachabilityDetection.TimeoutThresholdMS > 300000 { // 5 minutes max
		return fmt.Errorf("timeout threshold too large, maximum 300000ms, got %d", c.UnreachabilityDetection.TimeoutThresholdMS)
	}
	if c.UnreachabilityDetection.MinProbesForAnalysis <= 0 {
		return fmt.Errorf("minimum probes for analysis must be positive, got %d", c.UnreachabilityDetection.MinProbesForAnalysis)
	}
	if c.UnreachabilityDetection.MinProbesForAnalysis > 100 {
		return fmt.Errorf("minimum probes for analysis too large, maximum 100, got %d", c.UnreachabilityDetection.MinProbesForAnalysis)
	}
	if c.UnreachabilityDetection.ConfidenceThreshold < 0.0 || c.UnreachabilityDetection.ConfidenceThreshold > 1.0 {
		return fmt.Errorf("confidence threshold must be between 0.0 and 1.0, got %f", c.UnreachabilityDetection.ConfidenceThreshold)
	}
	if c.UnreachabilityDetection.CacheTTLSeconds < 0 {
		return fmt.Errorf("cache TTL cannot be negative, got %d", c.UnreachabilityDetection.CacheTTLSeconds)
	}
	if c.UnreachabilityDetection.CacheTTLSeconds > 86400 { // 24 hours max
		return fmt.Errorf("cache TTL too large, maximum 86400 seconds, got %d", c.UnreachabilityDetection.CacheTTLSeconds)
	}
	if c.UnreachabilityDetection.MaxCacheEntries < 0 {
		return fmt.Errorf("max cache entries cannot be negative, got %d", c.UnreachabilityDetection.MaxCacheEntries)
	}
	if c.UnreachabilityDetection.MaxCacheEntries > 10000 {
		return fmt.Errorf("max cache entries too large, maximum 10000, got %d", c.UnreachabilityDetection.MaxCacheEntries)
	}

	return nil
}

// GetTimeout returns the configured timeout as a time.Duration
func (c *Config) GetTimeout() time.Duration {
	return time.Duration(c.Network.TimeoutMS) * time.Millisecond
}

// GetProbeInterval returns the configured probe interval as a time.Duration
func (c *Config) GetProbeInterval() time.Duration {
	return time.Duration(c.Network.ProbeIntervalMS) * time.Millisecond
}

// GetSessionTimeout returns the configured MSS verification session timeout as a time.Duration
func (c *Config) GetSessionTimeout() time.Duration {
	return time.Duration(c.MSSVerification.SessionTimeoutMS) * time.Millisecond
}

// GetHandshakeTimeout returns the configured MSS verification handshake timeout as a time.Duration
func (c *Config) GetHandshakeTimeout() time.Duration {
	return time.Duration(c.MSSVerification.HandshakeTimeoutMS) * time.Millisecond
}

// GetControlPort returns the control port for MSS verification, falling back to TCP default if not set
func (c *Config) GetControlPort() int {
	if c.MSSVerification.ControlPort > 0 {
		return c.MSSVerification.ControlPort
	}
	return c.TCP.DefaultControlPort
}

// GetTestMSS returns the test MSS for MSS verification, falling back to TCP default if not set
func (c *Config) GetTestMSS() int {
	if c.MSSVerification.TestMSS > 0 {
		return c.MSSVerification.TestMSS
	}
	return c.TCP.DefaultTestMSS
}

// GetLoggingManagerConfig converts the logging configuration to a logging manager config
func (c *Config) GetLoggingManagerConfig() (interface{}, error) {
	// Import the logging package types - we'll return a map for now to avoid circular imports
	logLevel := c.Logging.Level

	return map[string]interface{}{
		"level":         logLevel,
		"verbose":       c.Logging.Verbose,
		"file_enabled":  c.Logging.FileEnabled,
		"file_path":     c.Logging.FilePath,
		"max_file_size": c.Logging.MaxFileSize,
		"max_backups":   c.Logging.MaxBackups,
	}, nil
}

// GetPreValidationTimeout returns the configured pre-validation timeout as a time.Duration
func (c *Config) GetPreValidationTimeout() time.Duration {
	return time.Duration(c.UnreachabilityDetection.PreValidationTimeoutMS) * time.Millisecond
}

// GetTimeoutThreshold returns the configured timeout threshold as a time.Duration
func (c *Config) GetTimeoutThreshold() time.Duration {
	return time.Duration(c.UnreachabilityDetection.TimeoutThresholdMS) * time.Millisecond
}

// GetCacheTTL returns the configured cache TTL as a time.Duration
func (c *Config) GetCacheTTL() time.Duration {
	return time.Duration(c.UnreachabilityDetection.CacheTTLSeconds) * time.Second
}

// ApplyUnreachabilityDetectionOverrides applies CLI overrides to unreachability detection config
func (c *Config) ApplyUnreachabilityDetectionOverrides(
	disableDetection bool,
	preValidationTimeout time.Duration,
	preValidationRetries int,
	consecutiveFailureThreshold int,
	totalFailureThreshold float64,
	confidenceThreshold float64,
) {
	// If detection is disabled, turn off all detection features
	if disableDetection {
		c.UnreachabilityDetection.EnablePreValidation = false
		c.UnreachabilityDetection.EnablePatternAnalysis = false
		return
	}

	// Apply CLI overrides if they are non-zero/non-default values
	if preValidationTimeout > 0 {
		c.UnreachabilityDetection.PreValidationTimeoutMS = int(preValidationTimeout.Milliseconds())
	}
	if preValidationRetries >= 0 {
		c.UnreachabilityDetection.PreValidationRetries = preValidationRetries
	}
	if consecutiveFailureThreshold > 0 {
		c.UnreachabilityDetection.ConsecutiveFailureThreshold = consecutiveFailureThreshold
	}
	if totalFailureThreshold > 0.0 {
		c.UnreachabilityDetection.TotalFailureThreshold = totalFailureThreshold
	}
	if confidenceThreshold > 0.0 {
		c.UnreachabilityDetection.ConfidenceThreshold = confidenceThreshold
	}
}

// ToDetectionConfig converts the config to a DetectionConfig-compatible map
// Note: This returns a map to avoid circular imports with the probe package
func (c *Config) ToDetectionConfig() map[string]interface{} {
	return map[string]interface{}{
		"EnablePreValidation":         c.UnreachabilityDetection.EnablePreValidation,
		"PreValidationTimeout":        c.GetPreValidationTimeout(),
		"PreValidationRetries":        c.UnreachabilityDetection.PreValidationRetries,
		"ConsecutiveFailureThreshold": c.UnreachabilityDetection.ConsecutiveFailureThreshold,
		"TotalFailureThreshold":       c.UnreachabilityDetection.TotalFailureThreshold,
		"TimeoutThreshold":            c.GetTimeoutThreshold(),
		"EnablePatternAnalysis":       c.UnreachabilityDetection.EnablePatternAnalysis,
		"MinProbesForAnalysis":        c.UnreachabilityDetection.MinProbesForAnalysis,
		"ConfidenceThreshold":         c.UnreachabilityDetection.ConfidenceThreshold,
	}
}

// GetUnreachabilityDetectionConfig converts config to detection config format
func (c *Config) GetUnreachabilityDetectionConfig() interface{} {
	return map[string]interface{}{
		"enable_pre_validation":         c.UnreachabilityDetection.EnablePreValidation,
		"pre_validation_timeout_ms":     c.UnreachabilityDetection.PreValidationTimeoutMS,
		"pre_validation_retries":        c.UnreachabilityDetection.PreValidationRetries,
		"consecutive_failure_threshold": c.UnreachabilityDetection.ConsecutiveFailureThreshold,
		"total_failure_threshold":       c.UnreachabilityDetection.TotalFailureThreshold,
		"timeout_threshold_ms":          c.UnreachabilityDetection.TimeoutThresholdMS,
		"enable_pattern_analysis":       c.UnreachabilityDetection.EnablePatternAnalysis,
		"min_probes_for_analysis":       c.UnreachabilityDetection.MinProbesForAnalysis,
		"confidence_threshold":          c.UnreachabilityDetection.ConfidenceThreshold,
		"cache_ttl_seconds":             c.UnreachabilityDetection.CacheTTLSeconds,
		"max_cache_entries":             c.UnreachabilityDetection.MaxCacheEntries,
	}
}

// SaveConfig saves the current configuration to a file
func (c *Config) SaveConfig(configPath string) error {
	viper.Set("network", c.Network)
	viper.Set("mtu", c.MTU)
	viper.Set("tcp", c.TCP)
	viper.Set("mss_verification", c.MSSVerification)
	viper.Set("unreachability_detection", c.UnreachabilityDetection)
	viper.Set("logging", c.Logging)

	return viper.WriteConfigAs(configPath)
}
