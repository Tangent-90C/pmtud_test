package config

import (
	"fmt"
	"sync"
	"time"
)

// DetectionConfigManager manages dynamic adjustment of unreachability detection parameters
type DetectionConfigManager struct {
	baseConfig      *UnreachabilityDetectionConfig
	currentConfig   *UnreachabilityDetectionConfig
	mutex           sync.RWMutex
	adjustmentStats *AdjustmentStats
}

// AdjustmentStats tracks statistics for dynamic parameter adjustment
type AdjustmentStats struct {
	TotalAdjustments     int
	TimeoutAdjustments   int
	ThresholdAdjustments int
	LastAdjustmentTime   time.Time
	NetworkConditions    *NetworkConditions
}

// NetworkConditions represents observed network conditions
type NetworkConditions struct {
	AverageRTT       time.Duration
	PacketLossRate   float64
	JitterMS         float64
	LastUpdated      time.Time
	SampleCount      int
	ConsistencyScore float64 // 0.0 to 1.0, higher means more consistent
}

// NewDetectionConfigManager creates a new detection configuration manager
func NewDetectionConfigManager(baseConfig *UnreachabilityDetectionConfig) *DetectionConfigManager {
	if baseConfig == nil {
		config := GetDefaultConfig()
		baseConfig = &config.UnreachabilityDetection
	}

	return &DetectionConfigManager{
		baseConfig:    baseConfig,
		currentConfig: cloneUnreachabilityConfig(baseConfig),
		adjustmentStats: &AdjustmentStats{
			NetworkConditions: &NetworkConditions{
				LastUpdated:      time.Now(),
				ConsistencyScore: 1.0,
			},
		},
	}
}

// GetCurrentConfig returns the current detection configuration
func (dcm *DetectionConfigManager) GetCurrentConfig() *UnreachabilityDetectionConfig {
	dcm.mutex.RLock()
	defer dcm.mutex.RUnlock()
	return cloneUnreachabilityConfig(dcm.currentConfig)
}

// UpdateNetworkConditions updates the observed network conditions and adjusts parameters
func (dcm *DetectionConfigManager) UpdateNetworkConditions(avgRTT time.Duration, packetLossRate float64, jitter float64) {
	dcm.mutex.Lock()
	defer dcm.mutex.Unlock()

	conditions := dcm.adjustmentStats.NetworkConditions

	// Update network conditions with exponential moving average
	alpha := 0.3 // Smoothing factor
	if conditions.SampleCount == 0 {
		conditions.AverageRTT = avgRTT
		conditions.PacketLossRate = packetLossRate
		conditions.JitterMS = jitter
	} else {
		conditions.AverageRTT = time.Duration(float64(conditions.AverageRTT)*(1-alpha) + float64(avgRTT)*alpha)
		conditions.PacketLossRate = conditions.PacketLossRate*(1-alpha) + packetLossRate*alpha
		conditions.JitterMS = conditions.JitterMS*(1-alpha) + jitter*alpha
	}

	conditions.SampleCount++
	conditions.LastUpdated = time.Now()

	// Calculate consistency score based on jitter and loss variation
	conditions.ConsistencyScore = dcm.calculateConsistencyScore(conditions)

	// Adjust parameters based on new conditions
	dcm.adjustParametersForConditions(conditions)
}

// calculateConsistencyScore calculates a consistency score based on network stability
func (dcm *DetectionConfigManager) calculateConsistencyScore(conditions *NetworkConditions) float64 {
	// Base score starts at 1.0 (perfect consistency)
	score := 1.0

	// Reduce score based on jitter (higher jitter = less consistent)
	if conditions.AverageRTT > 0 {
		jitterRatio := conditions.JitterMS / float64(conditions.AverageRTT.Milliseconds())
		if jitterRatio > 0.5 { // More than 50% jitter
			score -= 0.4
		} else if jitterRatio > 0.2 { // More than 20% jitter
			score -= 0.2
		}
	}

	// Reduce score based on packet loss
	if conditions.PacketLossRate > 0.1 { // More than 10% loss
		score -= 0.3
	} else if conditions.PacketLossRate > 0.05 { // More than 5% loss
		score -= 0.15
	}

	// Ensure score is between 0.0 and 1.0
	if score < 0.0 {
		score = 0.0
	}

	return score
}

// adjustParametersForConditions adjusts detection parameters based on network conditions
func (dcm *DetectionConfigManager) adjustParametersForConditions(conditions *NetworkConditions) {
	adjusted := false

	// Adjust timeouts based on RTT
	if conditions.AverageRTT > 0 {
		newTimeout := dcm.calculateOptimalTimeout(conditions.AverageRTT, conditions.ConsistencyScore)
		if newTimeout != dcm.currentConfig.PreValidationTimeoutMS {
			dcm.currentConfig.PreValidationTimeoutMS = newTimeout
			dcm.adjustmentStats.TimeoutAdjustments++
			adjusted = true
		}

		// Adjust timeout threshold
		newThreshold := int(float64(newTimeout) * 2.0)
		if newThreshold != dcm.currentConfig.TimeoutThresholdMS {
			dcm.currentConfig.TimeoutThresholdMS = newThreshold
			adjusted = true
		}
	}

	// Adjust failure thresholds based on packet loss and consistency
	newFailureThreshold := dcm.calculateOptimalFailureThreshold(conditions.PacketLossRate, conditions.ConsistencyScore)
	if newFailureThreshold != dcm.currentConfig.TotalFailureThreshold {
		dcm.currentConfig.TotalFailureThreshold = newFailureThreshold
		dcm.adjustmentStats.ThresholdAdjustments++
		adjusted = true
	}

	// Adjust consecutive failure threshold
	newConsecutiveThreshold := dcm.calculateOptimalConsecutiveThreshold(conditions.PacketLossRate, conditions.ConsistencyScore)
	if newConsecutiveThreshold != dcm.currentConfig.ConsecutiveFailureThreshold {
		dcm.currentConfig.ConsecutiveFailureThreshold = newConsecutiveThreshold
		adjusted = true
	}

	if adjusted {
		dcm.adjustmentStats.TotalAdjustments++
		dcm.adjustmentStats.LastAdjustmentTime = time.Now()
	}
}

// calculateOptimalTimeout calculates optimal timeout based on RTT and network consistency
func (dcm *DetectionConfigManager) calculateOptimalTimeout(avgRTT time.Duration, consistencyScore float64) int {
	// Base timeout is 3x average RTT
	baseTimeout := avgRTT * 3

	// Adjust based on consistency - less consistent networks need longer timeouts
	multiplier := 1.0 + (1.0-consistencyScore)*2.0 // 1.0 to 3.0 multiplier
	adjustedTimeout := time.Duration(float64(baseTimeout) * multiplier)

	// Apply bounds
	minTimeout := 2 * time.Second
	maxTimeout := 30 * time.Second

	if adjustedTimeout < minTimeout {
		adjustedTimeout = minTimeout
	} else if adjustedTimeout > maxTimeout {
		adjustedTimeout = maxTimeout
	}

	return int(adjustedTimeout.Milliseconds())
}

// calculateOptimalFailureThreshold calculates optimal failure threshold
func (dcm *DetectionConfigManager) calculateOptimalFailureThreshold(packetLossRate, consistencyScore float64) float64 {
	// Base threshold from configuration
	baseThreshold := dcm.baseConfig.TotalFailureThreshold

	// Adjust based on packet loss - higher loss requires higher threshold
	adjustment := packetLossRate * 0.5 // Up to 50% adjustment for 100% loss

	// Adjust based on consistency - less consistent networks need higher thresholds
	consistencyAdjustment := (1.0 - consistencyScore) * 0.2 // Up to 20% adjustment

	newThreshold := baseThreshold + adjustment + consistencyAdjustment

	// Apply bounds
	if newThreshold > 0.95 {
		newThreshold = 0.95
	} else if newThreshold < 0.5 {
		newThreshold = 0.5
	}

	return newThreshold
}

// calculateOptimalConsecutiveThreshold calculates optimal consecutive failure threshold
func (dcm *DetectionConfigManager) calculateOptimalConsecutiveThreshold(packetLossRate, consistencyScore float64) int {
	// Base threshold from configuration
	baseThreshold := dcm.baseConfig.ConsecutiveFailureThreshold

	// Adjust based on packet loss and consistency
	if packetLossRate > 0.1 || consistencyScore < 0.5 {
		// Increase threshold for lossy/inconsistent networks
		return baseThreshold + 2
	} else if packetLossRate > 0.05 || consistencyScore < 0.7 {
		return baseThreshold + 1
	}

	return baseThreshold
}

// ResetToDefaults resets the configuration to default values
func (dcm *DetectionConfigManager) ResetToDefaults() {
	dcm.mutex.Lock()
	defer dcm.mutex.Unlock()

	dcm.currentConfig = cloneUnreachabilityConfig(dcm.baseConfig)
	dcm.adjustmentStats = &AdjustmentStats{
		NetworkConditions: &NetworkConditions{
			LastUpdated:      time.Now(),
			ConsistencyScore: 1.0,
		},
	}
}

// GetAdjustmentStats returns statistics about parameter adjustments
func (dcm *DetectionConfigManager) GetAdjustmentStats() *AdjustmentStats {
	dcm.mutex.RLock()
	defer dcm.mutex.RUnlock()

	// Return a copy to avoid race conditions
	return &AdjustmentStats{
		TotalAdjustments:     dcm.adjustmentStats.TotalAdjustments,
		TimeoutAdjustments:   dcm.adjustmentStats.TimeoutAdjustments,
		ThresholdAdjustments: dcm.adjustmentStats.ThresholdAdjustments,
		LastAdjustmentTime:   dcm.adjustmentStats.LastAdjustmentTime,
		NetworkConditions: &NetworkConditions{
			AverageRTT:       dcm.adjustmentStats.NetworkConditions.AverageRTT,
			PacketLossRate:   dcm.adjustmentStats.NetworkConditions.PacketLossRate,
			JitterMS:         dcm.adjustmentStats.NetworkConditions.JitterMS,
			LastUpdated:      dcm.adjustmentStats.NetworkConditions.LastUpdated,
			SampleCount:      dcm.adjustmentStats.NetworkConditions.SampleCount,
			ConsistencyScore: dcm.adjustmentStats.NetworkConditions.ConsistencyScore,
		},
	}
}

// ApplyManualOverrides applies manual configuration overrides
func (dcm *DetectionConfigManager) ApplyManualOverrides(overrides map[string]interface{}) error {
	dcm.mutex.Lock()
	defer dcm.mutex.Unlock()

	for key, value := range overrides {
		switch key {
		case "PreValidationTimeoutMS":
			if val, ok := value.(int); ok && val > 0 && val <= 60000 {
				dcm.currentConfig.PreValidationTimeoutMS = val
			} else {
				return fmt.Errorf("invalid PreValidationTimeoutMS value: %v", value)
			}
		case "PreValidationRetries":
			if val, ok := value.(int); ok && val >= 0 && val <= 10 {
				dcm.currentConfig.PreValidationRetries = val
			} else {
				return fmt.Errorf("invalid PreValidationRetries value: %v", value)
			}
		case "ConsecutiveFailureThreshold":
			if val, ok := value.(int); ok && val > 0 && val <= 20 {
				dcm.currentConfig.ConsecutiveFailureThreshold = val
			} else {
				return fmt.Errorf("invalid ConsecutiveFailureThreshold value: %v", value)
			}
		case "TotalFailureThreshold":
			if val, ok := value.(float64); ok && val >= 0.0 && val <= 1.0 {
				dcm.currentConfig.TotalFailureThreshold = val
			} else {
				return fmt.Errorf("invalid TotalFailureThreshold value: %v", value)
			}
		case "ConfidenceThreshold":
			if val, ok := value.(float64); ok && val >= 0.0 && val <= 1.0 {
				dcm.currentConfig.ConfidenceThreshold = val
			} else {
				return fmt.Errorf("invalid ConfidenceThreshold value: %v", value)
			}
		default:
			return fmt.Errorf("unknown configuration parameter: %s", key)
		}
	}

	return nil
}

// cloneUnreachabilityConfig creates a deep copy of UnreachabilityDetectionConfig
func cloneUnreachabilityConfig(config *UnreachabilityDetectionConfig) *UnreachabilityDetectionConfig {
	return &UnreachabilityDetectionConfig{
		EnablePreValidation:         config.EnablePreValidation,
		PreValidationTimeoutMS:      config.PreValidationTimeoutMS,
		PreValidationRetries:        config.PreValidationRetries,
		ConsecutiveFailureThreshold: config.ConsecutiveFailureThreshold,
		TotalFailureThreshold:       config.TotalFailureThreshold,
		TimeoutThresholdMS:          config.TimeoutThresholdMS,
		EnablePatternAnalysis:       config.EnablePatternAnalysis,
		MinProbesForAnalysis:        config.MinProbesForAnalysis,
		ConfidenceThreshold:         config.ConfidenceThreshold,
		CacheTTLSeconds:             config.CacheTTLSeconds,
		MaxCacheEntries:             config.MaxCacheEntries,
	}
}
