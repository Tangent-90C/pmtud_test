package stats

import (
	"time"
)

// ProbeSession represents a probing session with statistics
type ProbeSession struct {
	StartTime        time.Time
	TotalProbes      int
	SuccessfulProbes int
	TimeoutCount     int
	ErrorCount       int
	Duration         time.Duration
}

// NetworkStats represents network-related statistics
type NetworkStats struct {
	PacketsSent     int
	PacketsReceived int
	ICMPErrors      int
	Timeouts        int
	AvgRTT          time.Duration
	MinRTT          time.Duration
	MaxRTT          time.Duration
}

// NewProbeSession creates a new probe session
func NewProbeSession() *ProbeSession {
	return &ProbeSession{
		StartTime: time.Now(),
	}
}

// NewNetworkStats creates a new network stats instance
func NewNetworkStats() *NetworkStats {
	return &NetworkStats{
		MinRTT: time.Duration(^uint64(0) >> 1), // Max duration
	}
}

// RecordProbe records a probe attempt
func (ps *ProbeSession) RecordProbe(success bool, timeout bool) {
	ps.TotalProbes++
	if success {
		ps.SuccessfulProbes++
	}
	if timeout {
		ps.TimeoutCount++
	} else if !success {
		ps.ErrorCount++
	}
}

// Finish finalizes the session
func (ps *ProbeSession) Finish() {
	ps.Duration = time.Since(ps.StartTime)
}

// RecordPacket records packet statistics
func (ns *NetworkStats) RecordPacket(sent bool, rtt time.Duration) {
	if sent {
		ns.PacketsSent++
	} else {
		ns.PacketsReceived++
		
		// Update RTT statistics
		if rtt > 0 {
			if rtt < ns.MinRTT {
				ns.MinRTT = rtt
			}
			if rtt > ns.MaxRTT {
				ns.MaxRTT = rtt
			}
			
			// Simple average calculation
			if ns.AvgRTT == 0 {
				ns.AvgRTT = rtt
			} else {
				ns.AvgRTT = (ns.AvgRTT + rtt) / 2
			}
		}
	}
}

// RecordError records an error
func (ns *NetworkStats) RecordError(isTimeout bool) {
	if isTimeout {
		ns.Timeouts++
	} else {
		ns.ICMPErrors++
	}
}