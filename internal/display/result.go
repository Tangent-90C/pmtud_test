package display

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	"ipv6-mtu-discovery/internal/network"
	"ipv6-mtu-discovery/internal/probe"
	"ipv6-mtu-discovery/internal/stats"
)

// ResultDisplay handles formatting and displaying probe results
type ResultDisplay struct {
	verbose       bool
	writer        io.Writer
	supportsEmoji bool
}

// NewResultDisplay creates a new result display with specified verbosity and output writer
func NewResultDisplay(verbose bool, writer io.Writer) *ResultDisplay {
	if writer == nil {
		writer = os.Stdout
	}

	return &ResultDisplay{
		verbose:       verbose,
		writer:        writer,
		supportsEmoji: detectEmojiSupport(),
	}
}

// detectEmojiSupport detects if the current terminal/shell supports emoji
func detectEmojiSupport() bool {
	// Check environment variables that indicate emoji support
	term := os.Getenv("TERM")
	termProgram := os.Getenv("TERM_PROGRAM")
	lang := os.Getenv("LANG")

	// Windows Command Prompt typically doesn't support emoji well
	if runtime.GOOS == "windows" {
		// Windows Terminal and newer PowerShell versions support emoji
		if termProgram == "Windows Terminal" ||
			strings.Contains(os.Getenv("WT_SESSION"), "WT") ||
			strings.Contains(os.Getenv("TERM_PROGRAM_VERSION"), "PowerShell") {
			return true
		}
		// Traditional cmd.exe doesn't support emoji well
		return false
	}

	// Most modern Unix terminals support emoji
	if strings.Contains(term, "xterm") ||
		strings.Contains(term, "screen") ||
		strings.Contains(term, "tmux") ||
		term == "alacritty" ||
		term == "kitty" ||
		termProgram == "iTerm.app" ||
		termProgram == "Apple_Terminal" {
		return true
	}

	// Check if locale supports UTF-8 (usually indicates emoji support)
	if strings.Contains(strings.ToUpper(lang), "UTF-8") ||
		strings.Contains(strings.ToUpper(lang), "UTF8") {
		return true
	}

	// Conservative default: assume no emoji support for unknown terminals
	return false
}

// getSuccessIcon returns appropriate success indicator based on emoji support
func (rd *ResultDisplay) getSuccessIcon() string {
	if rd.supportsEmoji {
		return "✅"
	}
	return "[OK]"
}

// getFailIcon returns appropriate failure indicator based on emoji support
func (rd *ResultDisplay) getFailIcon() string {
	if rd.supportsEmoji {
		return "❌"
	}
	return "[FAIL]"
}

// getWarningIcon returns appropriate warning indicator based on emoji support
func (rd *ResultDisplay) getWarningIcon() string {
	if rd.supportsEmoji {
		return "⚠️"
	}
	return "[WARN]"
}

// getInfoIcon returns appropriate info indicator based on emoji support
func (rd *ResultDisplay) getInfoIcon() string {
	if rd.supportsEmoji {
		return "ℹ️"
	}
	return "[INFO]"
}

// getUnreachableIcon returns appropriate unreachable indicator based on emoji support
func (rd *ResultDisplay) getUnreachableIcon() string {
	if rd.supportsEmoji {
		return "🚫"
	}
	return "[UNREACHABLE]"
}

// getDetectionIcon returns appropriate detection indicator based on emoji support
func (rd *ResultDisplay) getDetectionIcon() string {
	if rd.supportsEmoji {
		return "🔍"
	}
	return "[DETECT]"
}

// getDiagnosticIcon returns appropriate diagnostic indicator based on emoji support
func (rd *ResultDisplay) getDiagnosticIcon() string {
	if rd.supportsEmoji {
		return "🔧"
	}
	return "[DIAG]"
}

// getProgressIcon returns appropriate progress indicator based on emoji support
func (rd *ResultDisplay) getProgressIcon() string {
	if rd.supportsEmoji {
		return "🔍"
	}
	return "[TEST]"
}

// getClampingIcon returns appropriate clamping indicator based on emoji support
func (rd *ResultDisplay) getClampingIcon() string {
	if rd.supportsEmoji {
		return "📉"
	}
	return "[CLAMP]"
}

// getTamperingIcon returns appropriate tampering indicator based on emoji support
func (rd *ResultDisplay) getTamperingIcon() string {
	if rd.supportsEmoji {
		return "⚠️"
	}
	return "[TAMPER]"
}

// getCheckIcon returns appropriate check indicator based on emoji support
func (rd *ResultDisplay) getCheckIcon() string {
	if rd.supportsEmoji {
		return "✅"
	}
	return "[OK]"
}

// DisplayMTUResult displays the results of MTU discovery
func (rd *ResultDisplay) DisplayMTUResult(result *probe.MTUResult) {
	if result == nil {
		rd.DisplayError(fmt.Errorf("MTU result is nil"))
		return
	}

	// Display header
	fmt.Fprintln(rd.writer, "=== IPv6 MTU Discovery Results ===")
	fmt.Fprintln(rd.writer)

	// Check for target unreachability first
	if result.IsUnreachable {
		rd.DisplayUnreachabilityResult(result)
		return
	}

	// Display main result
	if result.MTUFound {
		fmt.Fprintf(rd.writer, "%s Path MTU discovered: %d bytes\n", rd.getSuccessIcon(), result.FinalMTU)
	} else {
		fmt.Fprintf(rd.writer, "%s Path MTU discovery failed\n", rd.getFailIcon())
	}

	// Display probe statistics
	fmt.Fprintf(rd.writer, "Probe attempts: %d\n", result.ProbeAttempts)

	// Display unreachability information if applicable
	if result.IsUnreachable {
		fmt.Fprintf(rd.writer, "%s Target unreachable: %s\n", rd.getWarningIcon(), result.UnreachabilityReason)
	}

	// Display PMTUD responses if any
	if len(result.PMTUDResponses) > 0 {
		fmt.Fprintln(rd.writer)
		fmt.Fprintln(rd.writer, "PMTUD Responses:")
		for i, response := range result.PMTUDResponses {
			rd.DisplayPMTUDInfo(&response, i+1)
		}
	}

	// Verbose information
	if rd.verbose {
		rd.displayVerboseMTUInfo(result)
	}

	fmt.Fprintln(rd.writer)
}

// DisplayUnreachabilityResult displays simplified target unreachability results
func (rd *ResultDisplay) DisplayUnreachabilityResult(result *probe.MTUResult) {
	if result == nil || !result.IsUnreachable {
		return
	}

	// Display main unreachability message
	fmt.Fprintf(rd.writer, "%s TARGET UNREACHABLE\n", rd.getUnreachableIcon())
	fmt.Fprintln(rd.writer)

	// Display basic information
	if result.UnreachabilityReason != "" {
		fmt.Fprintf(rd.writer, "Reason: %s\n", result.UnreachabilityReason)
	}

	// Display probe statistics
	fmt.Fprintf(rd.writer, "Probe attempts: %d\n", result.ProbeAttempts)

	// Display simple recommendations
	fmt.Fprintln(rd.writer)
	fmt.Fprintln(rd.writer, "Recommendations:")
	fmt.Fprintln(rd.writer, "  1. Verify target IPv6 address is correct")
	fmt.Fprintln(rd.writer, "  2. Check network connectivity with ping6")
	fmt.Fprintln(rd.writer, "  3. Verify firewall and security settings")

	// Display verbose information
	if rd.verbose {
		rd.displayVerboseUnreachabilityInfo(result)
	}

	fmt.Fprintln(rd.writer)
}

// DisplayUnreachabilityProgress shows progress during unreachability detection
func (rd *ResultDisplay) DisplayUnreachabilityProgress(step string, details string) {
	if rd.verbose {
		fmt.Fprintf(rd.writer, "%s %s: %s\n", rd.getDetectionIcon(), step, details)
	} else {
		fmt.Fprintf(rd.writer, "%s %s... ", rd.getDetectionIcon(), step)
	}
}

// DisplayUnreachabilityProgressResult shows the result of an unreachability detection step
func (rd *ResultDisplay) DisplayUnreachabilityProgressResult(success bool, message string) {
	if success {
		if rd.verbose {
			fmt.Fprintf(rd.writer, "%s %s\n", rd.getSuccessIcon(), message)
		} else {
			fmt.Fprintf(rd.writer, "%s\n", rd.getSuccessIcon())
		}
	} else {
		if rd.verbose {
			fmt.Fprintf(rd.writer, "%s %s\n", rd.getFailIcon(), message)
		} else {
			fmt.Fprintf(rd.writer, "%s\n", rd.getFailIcon())
		}
	}
}

// DisplaySeverityIndicator displays error severity with visual indicators
func (rd *ResultDisplay) DisplaySeverityIndicator(severity string, message string) {
	var icon string
	switch strings.ToLower(severity) {
	case "critical":
		icon = "🔴"
		if !rd.supportsEmoji {
			icon = "[CRITICAL]"
		}
	case "high":
		icon = "🟠"
		if !rd.supportsEmoji {
			icon = "[HIGH]"
		}
	case "medium":
		icon = "🟡"
		if !rd.supportsEmoji {
			icon = "[MEDIUM]"
		}
	case "low":
		icon = "🟢"
		if !rd.supportsEmoji {
			icon = "[LOW]"
		}
	default:
		icon = rd.getInfoIcon()
	}

	fmt.Fprintf(rd.writer, "%s %s: %s\n", icon, severity, message)
}

// displayVerboseUnreachabilityInfo displays simplified unreachability information in verbose mode
func (rd *ResultDisplay) displayVerboseUnreachabilityInfo(result *probe.MTUResult) {
	if !result.IsUnreachable {
		return
	}

	fmt.Fprintln(rd.writer)
	fmt.Fprintln(rd.writer, "Unreachability Details:")
	fmt.Fprintf(rd.writer, "  Target unreachable: %t\n", result.IsUnreachable)
	if result.UnreachabilityReason != "" {
		fmt.Fprintf(rd.writer, "  Reason: %s\n", result.UnreachabilityReason)
	}
	fmt.Fprintf(rd.writer, "  Probe attempts before detection: %d\n", result.ProbeAttempts)
}

// DisplayMSSResult displays the results of MSS detection
func (rd *ResultDisplay) DisplayMSSResult(result *network.MSSResult) {
	if result == nil {
		rd.DisplayError(fmt.Errorf("MSS result is nil"))
		return
	}

	// Display appropriate header based on whether this is integrity verification
	if result.MSSIntegrityCheck {
		fmt.Fprintln(rd.writer, "=== MSS Integrity Verification Results ===")
	} else {
		fmt.Fprintln(rd.writer, "=== TCP MSS Detection Results ===")
	}
	fmt.Fprintln(rd.writer)

	// Display connection status
	if result.ConnectionSuccess {
		fmt.Fprintf(rd.writer, "%s TCP connection successful\n", rd.getSuccessIcon())
	} else {
		fmt.Fprintf(rd.writer, "%s TCP connection failed\n", rd.getFailIcon())
		if result.ErrorMessage != "" {
			fmt.Fprintf(rd.writer, "Error: %s\n", result.ErrorMessage)
		}
		fmt.Fprintln(rd.writer)
		return
	}

	// Display MSS integrity verification specific information
	if result.MSSIntegrityCheck {
		rd.displayMSSIntegrityInfo(result)
	} else {
		// Display standard MSS information
		fmt.Fprintf(rd.writer, "Original MSS: %d bytes\n", result.OriginalMSS)
		fmt.Fprintf(rd.writer, "Negotiated MSS: %d bytes\n", result.ClampedMSS)

		// Display clamping status
		if result.MSSClamped {
			fmt.Fprintf(rd.writer, "%s MSS clamping detected (reduced by %d bytes)\n",
				rd.getSuccessIcon(), result.OriginalMSS-result.ClampedMSS)
			fmt.Fprintf(rd.writer, "Estimated MTU from MSS: %d bytes\n", result.DetectedMTU)
		} else {
			fmt.Fprintf(rd.writer, "%s No MSS clamping detected\n", rd.getFailIcon())
			if result.DetectedMTU > 0 {
				fmt.Fprintf(rd.writer, "Path MTU: %d bytes\n", result.DetectedMTU)
			}
		}
	}

	// Display error message if any
	if result.ErrorMessage != "" && result.ConnectionSuccess {
		fmt.Fprintf(rd.writer, "Warning: %s\n", result.ErrorMessage)
	}

	// Verbose information
	if rd.verbose {
		rd.displayVerboseMSSInfo(result)
	}

	fmt.Fprintln(rd.writer)
}

// DisplayMSSIntegrityResult displays the results of MSS integrity verification
func (rd *ResultDisplay) DisplayMSSIntegrityResult(result *network.MSSResult) {
	if result == nil {
		rd.DisplayError(fmt.Errorf("MSS integrity result is nil"))
		return
	}

	if !result.MSSIntegrityCheck {
		rd.DisplayError(fmt.Errorf("result is not from MSS integrity verification"))
		return
	}

	fmt.Fprintln(rd.writer, "=== MSS Integrity Verification Results ===")
	fmt.Fprintln(rd.writer)

	// Display connection status
	if result.ConnectionSuccess {
		fmt.Fprintf(rd.writer, "%s TCP connection established successfully\n", rd.getSuccessIcon())
	} else {
		fmt.Fprintf(rd.writer, "%s TCP connection failed\n", rd.getFailIcon())
		if result.ErrorMessage != "" {
			fmt.Fprintf(rd.writer, "Error: %s\n", result.ErrorMessage)
		}
		fmt.Fprintln(rd.writer)
		return
	}

	// Display MSS integrity verification results
	rd.displayMSSIntegrityVerificationResults(result)

	// Display error message if any
	if result.ErrorMessage != "" && result.ConnectionSuccess {
		fmt.Fprintf(rd.writer, "%s Warning: %s\n", rd.getWarningIcon(), result.ErrorMessage)
	}

	// Verbose information
	if rd.verbose {
		rd.displayVerboseMSSIntegrityInfo(result)
	}

	fmt.Fprintln(rd.writer)
}

// DisplayProgress shows the current progress of MTU discovery
func (rd *ResultDisplay) DisplayProgress(currentMTU, low, high, attempt int) {
	if !rd.verbose {
		// Show progress even in non-verbose mode, but more concise
		fmt.Fprintf(rd.writer, "%s Testing MTU %d bytes (range: %d-%d)... ",
			rd.getProgressIcon(), currentMTU, low, high)
		return
	}

	// Detailed progress for verbose mode
	fmt.Fprintf(rd.writer, "%s [Attempt %d] Testing MTU %d bytes (range: %d-%d)\n",
		rd.getProgressIcon(), attempt, currentMTU, low, high)
}

// DisplayDetectionProgress shows progress during unreachability detection phases
func (rd *ResultDisplay) DisplayDetectionProgress(phase string, step int, totalSteps int) {
	if rd.verbose {
		fmt.Fprintf(rd.writer, "%s [%d/%d] %s\n", rd.getDetectionIcon(), step, totalSteps, phase)
	} else {
		fmt.Fprintf(rd.writer, "%s %s... ", rd.getDetectionIcon(), phase)
	}
}

// DisplayProgressResult shows the result of a single probe attempt
func (rd *ResultDisplay) DisplayProgressResult(success bool, mtu int, response *probe.PMTUDResponse) {
	if success {
		if rd.verbose {
			fmt.Fprintf(rd.writer, "%s MTU %d bytes: SUCCESS\n", rd.getSuccessIcon(), mtu)
		} else {
			fmt.Fprintf(rd.writer, "%s\n", rd.getSuccessIcon())
		}
	} else {
		if rd.verbose {
			fmt.Fprintf(rd.writer, "%s MTU %d bytes: FAILED", rd.getFailIcon(), mtu)
			if response != nil {
				fmt.Fprintf(rd.writer, " (%s)", response.String())
			}
			fmt.Fprintln(rd.writer)
		} else {
			fmt.Fprintf(rd.writer, "%s\n", rd.getFailIcon())
		}
	}
}

// DisplayMSSVerificationProgress shows the progress of MSS verification process
func (rd *ResultDisplay) DisplayMSSVerificationProgress(step string) {
	fmt.Fprintf(rd.writer, "%s %s\n", rd.getProgressIcon(), step)
}

// DisplayMSSVerificationStep shows a specific step in MSS verification with details
func (rd *ResultDisplay) DisplayMSSVerificationStep(step string, details string) {
	if rd.verbose {
		fmt.Fprintf(rd.writer, "%s %s: %s\n", rd.getProgressIcon(), step, details)
	} else {
		fmt.Fprintf(rd.writer, "%s %s... ", rd.getProgressIcon(), step)
	}
}

// DisplayMSSVerificationStepResult shows the result of a verification step
func (rd *ResultDisplay) DisplayMSSVerificationStepResult(success bool, message string) {
	if success {
		if rd.verbose {
			fmt.Fprintf(rd.writer, "%s %s\n", rd.getSuccessIcon(), message)
		} else {
			fmt.Fprintf(rd.writer, "%s\n", rd.getSuccessIcon())
		}
	} else {
		if rd.verbose {
			fmt.Fprintf(rd.writer, "%s %s\n", rd.getFailIcon(), message)
		} else {
			fmt.Fprintf(rd.writer, "%s\n", rd.getFailIcon())
		}
	}
}

// DisplayMSSTestProgress shows progress for individual MSS test values
func (rd *ResultDisplay) DisplayMSSTestProgress(testMSS int, step string) {
	fmt.Fprintf(rd.writer, "%s Testing MSS %d bytes: %s\n", rd.getProgressIcon(), testMSS, step)
}

// DisplayMSSTestResult shows the result of testing a specific MSS value
func (rd *ResultDisplay) DisplayMSSTestResult(testMSS int, result *network.MSSResult) {
	if result == nil {
		fmt.Fprintf(rd.writer, "%s MSS %d bytes: ERROR (nil result)\n", rd.getFailIcon(), testMSS)
		return
	}

	if !result.ConnectionSuccess {
		fmt.Fprintf(rd.writer, "%s MSS %d bytes: CONNECTION FAILED\n", rd.getFailIcon(), testMSS)
		if rd.verbose && result.ErrorMessage != "" {
			fmt.Fprintf(rd.writer, "    Error: %s\n", result.ErrorMessage)
		}
		return
	}

	// Display result based on what was detected
	status := "OK"
	icon := rd.getSuccessIcon()

	if result.MSSModified {
		status = "TAMPERED"
		icon = rd.getTamperingIcon()
	} else if result.MSSClamped {
		status = "CLAMPED"
		icon = rd.getClampingIcon()
	}

	fmt.Fprintf(rd.writer, "%s MSS %d bytes: %s", icon, testMSS, status)

	if rd.verbose {
		if result.MSSModified {
			fmt.Fprintf(rd.writer, " (delta: %+d)", result.ModificationDelta)
		}
		if result.MSSClamped && result.ClampedMSS > 0 {
			fmt.Fprintf(rd.writer, " (clamped to: %d)", result.ClampedMSS)
		}
	}

	fmt.Fprintln(rd.writer)
}

// DisplayPMTUDInfo displays information about a PMTUD response
func (rd *ResultDisplay) DisplayPMTUDInfo(response *probe.PMTUDResponse, index int) {
	if response == nil {
		return
	}

	prefix := fmt.Sprintf("  [%d] ", index)
	fmt.Fprintf(rd.writer, "%s%s\n", prefix, response.String())

	if rd.verbose {
		// Display additional details in verbose mode
		fmt.Fprintf(rd.writer, "%s    Timestamp: %s\n", prefix,
			response.Timestamp.Format("15:04:05.000"))

		if response.RouterAddr != nil && !response.RouterAddr.IsUnspecified() {
			fmt.Fprintf(rd.writer, "%s    Router: %s\n", prefix, response.RouterAddr.String())
		}

		if response.PacketSize > 0 {
			fmt.Fprintf(rd.writer, "%s    Probe packet size: %d bytes (IPv6 layer)\n", prefix, response.PacketSize)
		}

		if mtu, hasMTU := response.GetMTUInfo(); hasMTU {
			fmt.Fprintf(rd.writer, "%s    Reported MTU: %d bytes\n", prefix, mtu)
		}
	}
}

// DisplayError displays error messages in a consistent format
func (rd *ResultDisplay) DisplayError(err error) {
	if err == nil {
		return
	}

	fmt.Fprintf(rd.writer, "Error: %s\n", err.Error())
}

// DisplayWarning displays warning messages
func (rd *ResultDisplay) DisplayWarning(message string) {
	fmt.Fprintf(rd.writer, "Warning: %s\n", message)
}

// DisplayInfo displays informational messages
func (rd *ResultDisplay) DisplayInfo(message string) {
	fmt.Fprintf(rd.writer, "Info: %s\n", message)
}

// DisplayStartMessage displays the start of a probe operation
func (rd *ResultDisplay) DisplayStartMessage(target string, mode string) {
	fmt.Fprintf(rd.writer, "Starting %s probe to %s\n", mode, target)
	if rd.verbose {
		fmt.Fprintf(rd.writer, "Timestamp: %s\n", time.Now().Format("2006-01-02 15:04:05"))
	}
	fmt.Fprintln(rd.writer)
}

// DisplaySummary displays a summary of the probe session
func (rd *ResultDisplay) DisplaySummary(duration time.Duration, totalProbes int, successRate float64) {
	fmt.Fprintln(rd.writer, "=== Probe Session Summary ===")
	fmt.Fprintf(rd.writer, "Duration: %v\n", duration.Round(time.Millisecond))
	fmt.Fprintf(rd.writer, "Total probes: %d\n", totalProbes)
	fmt.Fprintf(rd.writer, "Success rate: %.1f%%\n", successRate*100)
	fmt.Fprintln(rd.writer)
}

// DisplayProbeStatistics displays detailed probe and network statistics
func (rd *ResultDisplay) DisplayProbeStatistics(probeSession *stats.ProbeSession, networkStats *stats.NetworkStats) {
	if probeSession == nil && networkStats == nil {
		return
	}

	fmt.Fprintln(rd.writer, "=== Detailed Statistics ===")

	// Display probe session statistics
	if probeSession != nil {
		fmt.Fprintln(rd.writer, "Probe Session:")
		fmt.Fprintf(rd.writer, "  Total probes: %d\n", probeSession.TotalProbes)
		fmt.Fprintf(rd.writer, "  Successful probes: %d\n", probeSession.SuccessfulProbes)
		fmt.Fprintf(rd.writer, "  Failed probes: %d\n", probeSession.ErrorCount)
		fmt.Fprintf(rd.writer, "  Timeouts: %d\n", probeSession.TimeoutCount)

		if probeSession.TotalProbes > 0 {
			successRate := float64(probeSession.SuccessfulProbes) / float64(probeSession.TotalProbes) * 100
			fmt.Fprintf(rd.writer, "  Success rate: %.1f%%\n", successRate)
		}

		fmt.Fprintf(rd.writer, "  Session duration: %v\n", probeSession.Duration.Round(time.Millisecond))
		fmt.Fprintf(rd.writer, "  Started at: %s\n", probeSession.StartTime.Format("15:04:05"))
	}

	// Display network statistics
	if networkStats != nil {
		fmt.Fprintln(rd.writer, "Network Statistics:")
		fmt.Fprintf(rd.writer, "  Packets sent: %d\n", networkStats.PacketsSent)
		fmt.Fprintf(rd.writer, "  Packets received: %d\n", networkStats.PacketsReceived)
		fmt.Fprintf(rd.writer, "  ICMP errors: %d\n", networkStats.ICMPErrors)
		fmt.Fprintf(rd.writer, "  Timeouts: %d\n", networkStats.Timeouts)

		// Display RTT statistics if available
		if networkStats.PacketsReceived > 0 && networkStats.AvgRTT > 0 {
			fmt.Fprintln(rd.writer, "Round-Trip Time (RTT):")
			fmt.Fprintf(rd.writer, "    Average: %v\n", networkStats.AvgRTT.Round(time.Microsecond))

			if networkStats.MinRTT < time.Duration(^uint64(0)>>1) { // Check if MinRTT was actually set
				fmt.Fprintf(rd.writer, "    Minimum: %v\n", networkStats.MinRTT.Round(time.Microsecond))
			}

			if networkStats.MaxRTT > 0 {
				fmt.Fprintf(rd.writer, "    Maximum: %v\n", networkStats.MaxRTT.Round(time.Microsecond))
			}

			// Calculate RTT variance and jitter approximation
			if networkStats.MinRTT < time.Duration(^uint64(0)>>1) && networkStats.MaxRTT > 0 {
				jitter := networkStats.MaxRTT - networkStats.MinRTT
				fmt.Fprintf(rd.writer, "    Jitter (max-min): %v\n", jitter.Round(time.Microsecond))
			}
		}

		// Calculate packet loss rate
		totalPackets := networkStats.PacketsSent
		if totalPackets > 0 {
			lossRate := float64(networkStats.Timeouts+networkStats.ICMPErrors) / float64(totalPackets) * 100
			fmt.Fprintf(rd.writer, "  Packet loss rate: %.1f%%\n", lossRate)
		}

		// Display performance metrics
		if probeSession != nil && probeSession.Duration > 0 {
			fmt.Fprintln(rd.writer, "Performance Metrics:")

			// Calculate probes per second
			probesPerSecond := float64(probeSession.TotalProbes) / probeSession.Duration.Seconds()
			fmt.Fprintf(rd.writer, "    Probe rate: %.1f probes/second\n", probesPerSecond)

			// Calculate average probe duration
			if probeSession.TotalProbes > 0 {
				avgProbeTime := probeSession.Duration / time.Duration(probeSession.TotalProbes)
				fmt.Fprintf(rd.writer, "    Average probe time: %v\n", avgProbeTime.Round(time.Millisecond))
			}

			// Calculate efficiency metrics
			if probeSession.TotalProbes > 0 {
				efficiency := float64(probeSession.SuccessfulProbes) / float64(probeSession.TotalProbes) * 100
				fmt.Fprintf(rd.writer, "    Probe efficiency: %.1f%%\n", efficiency)
			}
		}
	}

	fmt.Fprintln(rd.writer)
}

// displayVerboseMTUInfo displays additional MTU information in verbose mode
func (rd *ResultDisplay) displayVerboseMTUInfo(result *probe.MTUResult) {
	fmt.Fprintln(rd.writer)
	fmt.Fprintln(rd.writer, "Detailed Information:")

	// Display reachability information
	if result.ReachabilityChecked {
		fmt.Fprintf(rd.writer, "  Target reachability: ")
		if result.TargetReachable {
			fmt.Fprintf(rd.writer, "%s Reachable\n", rd.getSuccessIcon())
		} else {
			fmt.Fprintf(rd.writer, "%s Unreachable\n", rd.getUnreachableIcon())
			if result.UnreachabilityReason != "" {
				fmt.Fprintf(rd.writer, "  Unreachability reason: %s\n", result.UnreachabilityReason)
			}
		}
	}

	if result.MTUFound {
		fmt.Fprintf(rd.writer, "  Final MTU: %d bytes\n", result.FinalMTU)
		fmt.Fprintf(rd.writer, "  IPv6 payload capacity: %d bytes\n", result.FinalMTU-40)

		// Display TCP MSS - actual tested value or calculated estimate
		if result.TCPMSSTested && result.ActualTCPMSS > 0 {
			fmt.Fprintf(rd.writer, "  TCP MSS (tested): %d bytes\n", result.ActualTCPMSS)
		} else {
			fmt.Fprintf(rd.writer, "  TCP MSS (calculated): %d bytes\n", result.FinalMTU-40-20)
		}
	}

	fmt.Fprintf(rd.writer, "  Total probe attempts: %d\n", result.ProbeAttempts)
	fmt.Fprintf(rd.writer, "  PMTUD responses received: %d\n", len(result.PMTUDResponses))

	// Display early termination information
	if result.EarlyTermination {
		fmt.Fprintf(rd.writer, "  Early termination: %s\n", result.EarlyTerminationReason)
	}

	// Analyze PMTUD responses
	if len(result.PMTUDResponses) > 0 {
		rd.analyzePMTUDResponses(result.PMTUDResponses)
	}

	// Display unreachability detection details
	if result.IsUnreachable {
		rd.displayVerboseUnreachabilityInfo(result)
	}
}

// displayMSSIntegrityInfo displays MSS integrity verification specific information
func (rd *ResultDisplay) displayMSSIntegrityInfo(result *network.MSSResult) {
	fmt.Fprintf(rd.writer, "Client sent MSS: %d bytes\n", result.ClientSentMSS)
	fmt.Fprintf(rd.writer, "Server received MSS: %d bytes\n", result.ServerReceivedMSS)

	// Display integrity status
	if result.MSSModified {
		fmt.Fprintf(rd.writer, "%s MSS TAMPERING DETECTED\n", rd.getTamperingIcon())
		fmt.Fprintf(rd.writer, "Modification delta: %d bytes\n", result.ModificationDelta)

		// Determine severity
		absDelta := result.ModificationDelta
		if absDelta < 0 {
			absDelta = -absDelta
		}

		var severity string
		switch {
		case absDelta <= 20:
			severity = "Low"
		case absDelta <= 100:
			severity = "Medium"
		default:
			severity = "High"
		}
		fmt.Fprintf(rd.writer, "Tampering severity: %s\n", severity)
	} else {
		fmt.Fprintf(rd.writer, "%s No MSS tampering detected\n", rd.getCheckIcon())
	}

	// Display clamping information if present
	if result.MSSClamped && result.ClampedMSS > 0 {
		fmt.Fprintf(rd.writer, "%s MSS clamping detected: %d bytes\n", rd.getClampingIcon(), result.ClampedMSS)
		if result.DetectedMTU > 0 {
			fmt.Fprintf(rd.writer, "Estimated MTU from clamped MSS: %d bytes\n", result.DetectedMTU)
		}
	}
}

// displayMSSIntegrityVerificationResults displays detailed MSS integrity verification results
func (rd *ResultDisplay) displayMSSIntegrityVerificationResults(result *network.MSSResult) {
	// Display MSS comparison table
	fmt.Fprintln(rd.writer, "MSS Value Comparison:")
	headers := []string{"Source", "MSS Value", "Status"}
	rows := [][]string{
		{"Client Sent", fmt.Sprintf("%d bytes", result.ClientSentMSS), "Original"},
		{"Server Received", fmt.Sprintf("%d bytes", result.ServerReceivedMSS), rd.getMSSStatusString(result)},
	}
	rd.DisplayTable(headers, rows)

	// Display integrity verification result
	if result.MSSModified {
		fmt.Fprintf(rd.writer, "%s MSS TAMPERING DETECTED\n", rd.getTamperingIcon())
		rd.displayMSSTamperingDetails(result)
	} else {
		fmt.Fprintf(rd.writer, "%s MSS integrity verified - No tampering detected\n", rd.getCheckIcon())
	}

	// Display clamping information if present
	if result.MSSClamped {
		fmt.Fprintln(rd.writer)
		fmt.Fprintf(rd.writer, "%s MSS clamping also detected\n", rd.getClampingIcon())
		if result.ClampedMSS > 0 {
			fmt.Fprintf(rd.writer, "Clamped MSS value: %d bytes\n", result.ClampedMSS)
		}
		if result.DetectedMTU > 0 {
			fmt.Fprintf(rd.writer, "Estimated MTU from clamped MSS: %d bytes\n", result.DetectedMTU)
		}
	}
}

// displayMSSTamperingDetails displays detailed information about MSS tampering
func (rd *ResultDisplay) displayMSSTamperingDetails(result *network.MSSResult) {
	fmt.Fprintln(rd.writer)
	fmt.Fprintln(rd.writer, "Tampering Analysis:")

	// Calculate modification details
	delta := result.ModificationDelta
	absDelta := delta
	if absDelta < 0 {
		absDelta = -absDelta
	}

	// Display modification direction and magnitude
	if delta > 0 {
		fmt.Fprintf(rd.writer, "  Modification type: MSS value INCREASED by %d bytes\n", delta)
	} else if delta < 0 {
		fmt.Fprintf(rd.writer, "  Modification type: MSS value DECREASED by %d bytes\n", -delta)
	}

	// Display severity assessment
	severity := rd.assessTamperingSeverity(absDelta)
	fmt.Fprintf(rd.writer, "  Tampering severity: %s\n", severity)

	// Display potential implications
	rd.displayTamperingImplications(delta, severity)

	// Display modification percentage
	if result.ClientSentMSS > 0 {
		percentage := float64(absDelta) / float64(result.ClientSentMSS) * 100
		fmt.Fprintf(rd.writer, "  Modification percentage: %.2f%%\n", percentage)
	}
}

// displayTamperingImplications displays potential implications of MSS tampering
func (rd *ResultDisplay) displayTamperingImplications(delta int, severity string) {
	fmt.Fprintln(rd.writer, "  Potential implications:")

	if delta > 0 {
		fmt.Fprintln(rd.writer, "    - Artificially inflated MSS may cause packet fragmentation")
		fmt.Fprintln(rd.writer, "    - Could lead to performance degradation")
		if severity == "High" {
			fmt.Fprintln(rd.writer, "    - May indicate malicious network manipulation")
		}
	} else if delta < 0 {
		fmt.Fprintln(rd.writer, "    - Reduced MSS may limit throughput")
		fmt.Fprintln(rd.writer, "    - Could be legitimate network optimization or malicious throttling")
		if severity == "High" {
			fmt.Fprintln(rd.writer, "    - Significant reduction may indicate traffic shaping or attack")
		}
	}
}

// getMSSStatusString returns a status string for MSS values
func (rd *ResultDisplay) getMSSStatusString(result *network.MSSResult) string {
	if result.MSSModified {
		if result.ModificationDelta > 0 {
			return "Modified (Increased)"
		} else {
			return "Modified (Decreased)"
		}
	}
	return "Unmodified"
}

// assessTamperingSeverity assesses the severity of MSS tampering
func (rd *ResultDisplay) assessTamperingSeverity(absDelta int) string {
	switch {
	case absDelta == 0:
		return "None"
	case absDelta <= 20:
		return "Low"
	case absDelta <= 100:
		return "Medium"
	case absDelta <= 300:
		return "High"
	default:
		return "Critical"
	}
}

// displayVerboseMSSInfo displays additional MSS information in verbose mode
func (rd *ResultDisplay) displayVerboseMSSInfo(result *network.MSSResult) {
	fmt.Fprintln(rd.writer)
	fmt.Fprintln(rd.writer, "Detailed Information:")

	if result.ConnectionSuccess {
		if result.MSSIntegrityCheck {
			// Verbose info for integrity verification
			fmt.Fprintf(rd.writer, "  Client sent MSS: %d bytes\n", result.ClientSentMSS)
			fmt.Fprintf(rd.writer, "  Server received MSS: %d bytes\n", result.ServerReceivedMSS)
			fmt.Fprintf(rd.writer, "  Modification delta: %d bytes\n", result.ModificationDelta)
			fmt.Fprintf(rd.writer, "  MSS modified: %t\n", result.MSSModified)

			if result.MSSClamped {
				fmt.Fprintf(rd.writer, "  Clamped MSS: %d bytes\n", result.ClampedMSS)
			}
		} else {
			// Verbose info for standard MSS detection
			fmt.Fprintf(rd.writer, "  Original MSS: %d bytes\n", result.OriginalMSS)
			fmt.Fprintf(rd.writer, "  Negotiated MSS: %d bytes\n", result.ClampedMSS)

			if result.MSSClamped {
				reduction := result.OriginalMSS - result.ClampedMSS
				fmt.Fprintf(rd.writer, "  MSS reduction: %d bytes\n", reduction)
				fmt.Fprintf(rd.writer, "  Clamping ratio: %.1f%%\n",
					float64(reduction)/float64(result.OriginalMSS)*100)
			}
		}

		if result.DetectedMTU > 0 {
			fmt.Fprintf(rd.writer, "  Estimated path MTU: %d bytes\n", result.DetectedMTU)
			fmt.Fprintf(rd.writer, "  IPv6 header overhead: 40 bytes\n")
			fmt.Fprintf(rd.writer, "  TCP header overhead: 20 bytes\n")
		}
	}
}

// displayVerboseMSSIntegrityInfo displays additional MSS integrity information in verbose mode
func (rd *ResultDisplay) displayVerboseMSSIntegrityInfo(result *network.MSSResult) {
	fmt.Fprintln(rd.writer)
	fmt.Fprintln(rd.writer, "Detailed MSS Integrity Analysis:")

	if result.ConnectionSuccess {
		// Display detailed MSS comparison
		fmt.Fprintf(rd.writer, "  Original MSS (client): %d bytes\n", result.ClientSentMSS)
		fmt.Fprintf(rd.writer, "  Received MSS (server): %d bytes\n", result.ServerReceivedMSS)
		fmt.Fprintf(rd.writer, "  Modification delta: %+d bytes\n", result.ModificationDelta)

		// Calculate and display percentages
		if result.ClientSentMSS > 0 {
			percentage := float64(result.ModificationDelta) / float64(result.ClientSentMSS) * 100
			fmt.Fprintf(rd.writer, "  Modification percentage: %+.2f%%\n", percentage)
		}

		// Display integrity status
		fmt.Fprintf(rd.writer, "  Integrity status: ")
		if result.MSSModified {
			fmt.Fprintf(rd.writer, "COMPROMISED\n")

			// Detailed tampering analysis
			absDelta := result.ModificationDelta
			if absDelta < 0 {
				absDelta = -absDelta
			}

			severity := rd.assessTamperingSeverity(absDelta)
			fmt.Fprintf(rd.writer, "  Tampering severity: %s\n", severity)

			if result.ModificationDelta > 0 {
				fmt.Fprintf(rd.writer, "  Tampering type: MSS inflation (+%d bytes)\n", result.ModificationDelta)
			} else {
				fmt.Fprintf(rd.writer, "  Tampering type: MSS reduction (%d bytes)\n", result.ModificationDelta)
			}
		} else {
			fmt.Fprintf(rd.writer, "INTACT\n")
		}

		// Display clamping information if present
		if result.MSSClamped {
			fmt.Fprintf(rd.writer, "  Clamping detected: YES\n")
			fmt.Fprintf(rd.writer, "  Clamped MSS value: %d bytes\n", result.ClampedMSS)

			if result.ClientSentMSS > 0 && result.ClampedMSS > 0 {
				clampReduction := result.ClientSentMSS - result.ClampedMSS
				clampPercentage := float64(clampReduction) / float64(result.ClientSentMSS) * 100
				fmt.Fprintf(rd.writer, "  Clamping reduction: %d bytes (%.1f%%)\n", clampReduction, clampPercentage)
			}
		} else {
			fmt.Fprintf(rd.writer, "  Clamping detected: NO\n")
		}

		// Display MTU estimation
		if result.DetectedMTU > 0 {
			fmt.Fprintf(rd.writer, "  Estimated path MTU: %d bytes\n", result.DetectedMTU)
			fmt.Fprintf(rd.writer, "  IPv6 payload capacity: %d bytes\n", result.DetectedMTU-40)
			fmt.Fprintf(rd.writer, "  TCP payload capacity: %d bytes\n", result.DetectedMTU-60)
		}

		// Display protocol overhead breakdown
		fmt.Fprintln(rd.writer, "  Protocol overhead breakdown:")
		fmt.Fprintf(rd.writer, "    IPv6 header: 40 bytes\n")
		fmt.Fprintf(rd.writer, "    TCP header (minimum): 20 bytes\n")
		fmt.Fprintf(rd.writer, "    Total overhead: 60 bytes\n")
	}
}

// analyzePMTUDResponses analyzes and displays patterns in PMTUD responses
func (rd *ResultDisplay) analyzePMTUDResponses(responses []probe.PMTUDResponse) {
	fmt.Fprintln(rd.writer)
	fmt.Fprintln(rd.writer, "  PMTUD Response Analysis:")

	// Count response types
	packetTooBigCount := 0
	destUnreachableCount := 0
	timeExceededCount := 0
	uniqueRouters := make(map[string]bool)

	for _, response := range responses {
		if response.IsPacketTooBig() {
			packetTooBigCount++
		} else if response.IsDestinationUnreachable() {
			destUnreachableCount++
		} else if response.IsTimeExceeded() {
			timeExceededCount++
		}

		if response.RouterAddr != nil && !response.RouterAddr.IsUnspecified() {
			uniqueRouters[response.RouterAddr.String()] = true
		}
	}

	fmt.Fprintf(rd.writer, "    Packet Too Big messages: %d\n", packetTooBigCount)
	fmt.Fprintf(rd.writer, "    Destination Unreachable: %d\n", destUnreachableCount)
	fmt.Fprintf(rd.writer, "    Time Exceeded: %d\n", timeExceededCount)
	fmt.Fprintf(rd.writer, "    Unique routers: %d\n", len(uniqueRouters))

	// Display router addresses
	if len(uniqueRouters) > 0 {
		fmt.Fprintln(rd.writer, "    Router addresses:")
		for router := range uniqueRouters {
			fmt.Fprintf(rd.writer, "      %s\n", router)
		}
	}
}

// SetVerbose changes the verbosity level
func (rd *ResultDisplay) SetVerbose(verbose bool) {
	rd.verbose = verbose
}

// SetWriter changes the output writer
func (rd *ResultDisplay) SetWriter(writer io.Writer) {
	if writer != nil {
		rd.writer = writer
	}
}

// IsVerbose returns the current verbosity setting
func (rd *ResultDisplay) IsVerbose() bool {
	return rd.verbose
}

// DisplayTable displays data in a formatted table
func (rd *ResultDisplay) DisplayTable(headers []string, rows [][]string) {
	if len(headers) == 0 || len(rows) == 0 {
		return
	}

	// Calculate column widths
	colWidths := make([]int, len(headers))
	for i, header := range headers {
		colWidths[i] = len(header)
	}

	for _, row := range rows {
		for i, cell := range row {
			if i < len(colWidths) && len(cell) > colWidths[i] {
				colWidths[i] = len(cell)
			}
		}
	}

	// Display header
	rd.displayTableRow(headers, colWidths)
	rd.displayTableSeparator(colWidths)

	// Display rows
	for _, row := range rows {
		rd.displayTableRow(row, colWidths)
	}

	fmt.Fprintln(rd.writer)
}

// displayTableRow displays a single table row
func (rd *ResultDisplay) displayTableRow(cells []string, widths []int) {
	fmt.Fprint(rd.writer, "| ")
	for i, cell := range cells {
		if i < len(widths) {
			fmt.Fprintf(rd.writer, "%-*s | ", widths[i], cell)
		}
	}
	fmt.Fprintln(rd.writer)
}

// displayTableSeparator displays table separator line
func (rd *ResultDisplay) displayTableSeparator(widths []int) {
	fmt.Fprint(rd.writer, "|")
	for _, width := range widths {
		fmt.Fprint(rd.writer, strings.Repeat("-", width+2))
		fmt.Fprint(rd.writer, "|")
	}
	fmt.Fprintln(rd.writer)
}

// DisplayMTUComparison displays a comparison of different MTU values
func (rd *ResultDisplay) DisplayMTUComparison(discoveredMTU int, expectedMTU int) {
	fmt.Fprintln(rd.writer, "=== MTU Comparison ===")

	headers := []string{"Metric", "Discovered", "Expected", "Difference"}
	rows := [][]string{
		{"MTU", fmt.Sprintf("%d", discoveredMTU), fmt.Sprintf("%d", expectedMTU),
			fmt.Sprintf("%+d", discoveredMTU-expectedMTU)},
		{"IPv6 Payload", fmt.Sprintf("%d", discoveredMTU-40), fmt.Sprintf("%d", expectedMTU-40),
			fmt.Sprintf("%+d", (discoveredMTU-40)-(expectedMTU-40))},
		{"TCP MSS", fmt.Sprintf("%d", discoveredMTU-60), fmt.Sprintf("%d", expectedMTU-60),
			fmt.Sprintf("%+d", (discoveredMTU-60)-(expectedMTU-60))},
	}

	rd.DisplayTable(headers, rows)
}

// DisplayNetworkPath displays information about the network path
func (rd *ResultDisplay) DisplayNetworkPath(responses []probe.PMTUDResponse) {
	if len(responses) == 0 {
		return
	}

	fmt.Fprintln(rd.writer, "=== Network Path Information ===")

	// Group responses by router
	routerResponses := make(map[string][]probe.PMTUDResponse)
	for _, response := range responses {
		if response.RouterAddr != nil && !response.RouterAddr.IsUnspecified() {
			addr := response.RouterAddr.String()
			routerResponses[addr] = append(routerResponses[addr], response)
		}
	}

	if len(routerResponses) == 0 {
		fmt.Fprintln(rd.writer, "No router information available")
		return
	}

	fmt.Fprintf(rd.writer, "Detected %d router(s) in path:\n", len(routerResponses))

	i := 1
	for router, resps := range routerResponses {
		fmt.Fprintf(rd.writer, "  %d. %s\n", i, router)

		// Find MTU information from this router
		for _, resp := range resps {
			if mtu, hasMTU := resp.GetMTUInfo(); hasMTU {
				fmt.Fprintf(rd.writer, "     Reported MTU: %d bytes\n", mtu)
				break
			}
		}
		i++
	}

	fmt.Fprintln(rd.writer)
}

// DisplayMSSTamperingAnalysis displays the results of MSS tampering analysis
func (rd *ResultDisplay) DisplayMSSTamperingAnalysis(analysis *network.MSSTamperingAnalysis) {
	if analysis == nil {
		rd.DisplayError(fmt.Errorf("MSS tampering analysis is nil"))
		return
	}

	fmt.Fprintln(rd.writer, "=== MSS Tampering Analysis ===")
	fmt.Fprintln(rd.writer)

	fmt.Fprintf(rd.writer, "Total tests performed: %d\n", analysis.TotalTests)
	fmt.Fprintf(rd.writer, "Successful connections: %d\n", analysis.SuccessfulConnections)
	fmt.Fprintln(rd.writer)

	// Display tampering results
	if analysis.TamperingDetected {
		fmt.Fprintf(rd.writer, "%s MSS TAMPERING DETECTED\n", rd.getTamperingIcon())
		fmt.Fprintf(rd.writer, "Tampering cases: %d/%d (%.1f%%)\n",
			analysis.TamperingCount, analysis.TotalTests, analysis.TamperingPercentage)
	} else {
		fmt.Fprintf(rd.writer, "%s No MSS tampering detected\n", rd.getCheckIcon())
	}

	// Display clamping results
	if analysis.ClampingDetected {
		fmt.Fprintf(rd.writer, "%s MSS clamping detected\n", rd.getClampingIcon())
		fmt.Fprintf(rd.writer, "Clamping cases: %d/%d (%.1f%%)\n",
			analysis.ClampingCount, analysis.TotalTests, analysis.ClampingPercentage)
	} else {
		fmt.Fprintf(rd.writer, "%s No MSS clamping detected\n", rd.getCheckIcon())
	}

	// Display detailed results in verbose mode
	if rd.verbose && len(analysis.TestResults) > 0 {
		fmt.Fprintln(rd.writer)
		fmt.Fprintln(rd.writer, "Detailed Test Results:")

		headers := []string{"Test MSS", "Client Sent", "Server Received", "Delta", "Status"}
		rows := make([][]string, 0, len(analysis.TestResults))

		for _, result := range analysis.TestResults {
			status := "OK"
			if result.MSSModified {
				status = "TAMPERED"
			} else if result.MSSClamped {
				status = "CLAMPED"
			}

			row := []string{
				fmt.Sprintf("%d", result.OriginalMSS),
				fmt.Sprintf("%d", result.ClientSentMSS),
				fmt.Sprintf("%d", result.ServerReceivedMSS),
				fmt.Sprintf("%+d", result.ModificationDelta),
				status,
			}
			rows = append(rows, row)
		}

		rd.DisplayTable(headers, rows)
	}

	fmt.Fprintln(rd.writer)
}

// DisplayMSSComparisonReport displays a detailed comparison report of MSS values
func (rd *ResultDisplay) DisplayMSSComparisonReport(clientMSS, serverMSS int, sessionID string) {
	fmt.Fprintln(rd.writer, "=== MSS Comparison Report ===")
	fmt.Fprintln(rd.writer)

	if sessionID != "" {
		fmt.Fprintf(rd.writer, "Session ID: %s\n", sessionID)
		fmt.Fprintln(rd.writer)
	}

	// Create comparison table
	headers := []string{"Measurement Point", "MSS Value", "Difference", "Status"}

	delta := clientMSS - serverMSS
	var status string
	var icon string

	if delta == 0 {
		status = "Identical"
		icon = rd.getCheckIcon()
	} else if delta > 0 {
		status = "Reduced"
		icon = rd.getTamperingIcon()
	} else {
		status = "Increased"
		icon = rd.getTamperingIcon()
	}

	rows := [][]string{
		{"Client (Sent)", fmt.Sprintf("%d bytes", clientMSS), "Baseline", "Original"},
		{"Server (Received)", fmt.Sprintf("%d bytes", serverMSS), fmt.Sprintf("%+d bytes", -delta), status},
	}

	rd.DisplayTable(headers, rows)

	// Display overall assessment
	fmt.Fprintf(rd.writer, "%s Overall Assessment: ", icon)
	if delta == 0 {
		fmt.Fprintln(rd.writer, "MSS values match - No tampering detected")
	} else {
		fmt.Fprintf(rd.writer, "MSS tampering detected (delta: %+d bytes)\n", delta)

		// Display severity and implications
		absDelta := delta
		if absDelta < 0 {
			absDelta = -absDelta
		}
		severity := rd.assessTamperingSeverity(absDelta)
		fmt.Fprintf(rd.writer, "Tampering severity: %s\n", severity)
	}

	fmt.Fprintln(rd.writer)
}

// DisplayMSSIntegritySessionSummary displays a summary of an MSS integrity verification session
func (rd *ResultDisplay) DisplayMSSIntegritySessionSummary(results []*network.MSSResult, sessionID string) {
	if len(results) == 0 {
		fmt.Fprintln(rd.writer, "No MSS integrity test results to display")
		return
	}

	fmt.Fprintln(rd.writer, "=== MSS Integrity Session Summary ===")
	fmt.Fprintln(rd.writer)

	if sessionID != "" {
		fmt.Fprintf(rd.writer, "Session ID: %s\n", sessionID)
		fmt.Fprintln(rd.writer)
	}

	// Calculate summary statistics
	totalTests := len(results)
	successfulConnections := 0
	tamperingCases := 0
	clampingCases := 0

	for _, result := range results {
		if result.ConnectionSuccess {
			successfulConnections++
		}
		if result.MSSModified {
			tamperingCases++
		}
		if result.MSSClamped {
			clampingCases++
		}
	}

	// Display summary statistics
	fmt.Fprintf(rd.writer, "Total tests: %d\n", totalTests)
	fmt.Fprintf(rd.writer, "Successful connections: %d/%d (%.1f%%)\n",
		successfulConnections, totalTests, float64(successfulConnections)/float64(totalTests)*100)

	if tamperingCases > 0 {
		fmt.Fprintf(rd.writer, "%s Tampering detected: %d/%d tests (%.1f%%)\n",
			rd.getTamperingIcon(), tamperingCases, totalTests, float64(tamperingCases)/float64(totalTests)*100)
	} else {
		fmt.Fprintf(rd.writer, "%s No tampering detected\n", rd.getCheckIcon())
	}

	if clampingCases > 0 {
		fmt.Fprintf(rd.writer, "%s Clamping detected: %d/%d tests (%.1f%%)\n",
			rd.getClampingIcon(), clampingCases, totalTests, float64(clampingCases)/float64(totalTests)*100)
	}

	// Display detailed results if verbose
	if rd.verbose {
		fmt.Fprintln(rd.writer)
		fmt.Fprintln(rd.writer, "Individual Test Results:")

		headers := []string{"Test #", "Test MSS", "Client→Server", "Delta", "Status", "Notes"}
		rows := make([][]string, 0, len(results))

		for i, result := range results {
			status := "Failed"
			notes := ""

			if result.ConnectionSuccess {
				if result.MSSModified {
					status = "Tampered"
					notes = fmt.Sprintf("Severity: %s", rd.assessTamperingSeverity(abs(result.ModificationDelta)))
				} else if result.MSSClamped {
					status = "Clamped"
					notes = fmt.Sprintf("To: %d", result.ClampedMSS)
				} else {
					status = "Clean"
					notes = "No issues"
				}
			} else {
				notes = "Connection failed"
			}

			clientToServer := "N/A"
			delta := "N/A"
			if result.ConnectionSuccess {
				clientToServer = fmt.Sprintf("%d→%d", result.ClientSentMSS, result.ServerReceivedMSS)
				delta = fmt.Sprintf("%+d", result.ModificationDelta)
			}

			row := []string{
				fmt.Sprintf("%d", i+1),
				fmt.Sprintf("%d", result.OriginalMSS),
				clientToServer,
				delta,
				status,
				notes,
			}
			rows = append(rows, row)
		}

		rd.DisplayTable(headers, rows)
	}

	fmt.Fprintln(rd.writer)
}

// DisplayUnreachabilityTrend displays trend analysis of unreachability over time
func (rd *ResultDisplay) DisplayUnreachabilityTrend(sessions []*stats.ProbeSession) {
	if len(sessions) == 0 {
		return
	}

	fmt.Fprintln(rd.writer, "=== Unreachability Trend Analysis ===")
	fmt.Fprintln(rd.writer)

	// Note: This function would need to be updated to work with simplified MTUResult
	// For now, we'll just display a placeholder message
	fmt.Fprintln(rd.writer, "Trend analysis not available with simplified unreachability detection")
	fmt.Fprintln(rd.writer)
}

// abs returns the absolute value of an integer
func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
