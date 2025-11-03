package probe

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
)

// ParsePMTUDResponse parses a PMTUD response message from raw ICMP6 data
func ParsePMTUDResponse(data []byte) (*PMTUDResponse, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("ICMP6 message too short: %d bytes", len(data))
	}

	// Parse the ICMP message using IPv6 ICMP protocol (58)
	message, err := icmp.ParseMessage(58, data) // 58 is IPv6-ICMP protocol number
	if err != nil {
		return nil, fmt.Errorf("failed to parse ICMP6 message: %w", err)
	}

	// Convert message type to int safely
	var msgType int
	if icmpType, ok := message.Type.(ipv6.ICMPType); ok {
		msgType = int(icmpType)
	} else {
		// For other types, we need to handle them differently
		// Let's just use the raw type value from the data
		if len(data) > 0 {
			msgType = int(data[0])
		} else {
			return nil, fmt.Errorf("unable to determine ICMP message type")
		}
	}

	response := &PMTUDResponse{
		Type:      msgType,
		Code:      message.Code,
		Timestamp: time.Now(),
	}

	// Handle different ICMP6 message types
	switch msgType {
	case int(ipv6.ICMPTypePacketTooBig):
		// Parse Packet Too Big message
		if len(data) >= 8 {
			// MTU is in bytes 4-7 of the ICMP6 message
			response.ReportedMTU = int(binary.BigEndian.Uint32(data[4:8]))
		}

	case int(ipv6.ICMPTypeDestinationUnreachable):
		// Handle destination unreachable
		response.ReportedMTU = 0 // No MTU info in this message type

	case int(ipv6.ICMPTypeTimeExceeded):
		// Handle time exceeded
		response.ReportedMTU = 0 // No MTU info in this message type

	case int(ipv6.ICMPTypeEchoReply):
		// Handle echo reply - this indicates successful probe
		response.ReportedMTU = 0 // No MTU info, but this is a success

	case int(ipv6.ICMPTypeEchoRequest):
		// This might be our own echo request being reflected back
		// In some network configurations, we might receive our own packets
		// Treat this as unreachable since we didn't get a proper reply
		return nil, fmt.Errorf("received echo request instead of reply (possible network loop or reflection)")

	default:
		return nil, fmt.Errorf("unexpected ICMP6 message type: %d (%v)", msgType, message.Type)
	}

	return response, nil
}

// ParsePMTUDResponseWithSource parses a PMTUD response and extracts source router address
func ParsePMTUDResponseWithSource(data []byte, srcAddr net.Addr) (*PMTUDResponse, error) {
	response, err := ParsePMTUDResponse(data)
	if err != nil {
		return nil, err
	}

	// Extract router address from source
	if ipAddr, ok := srcAddr.(*net.IPAddr); ok {
		response.RouterAddr = ipAddr.IP
	} else if udpAddr, ok := srcAddr.(*net.UDPAddr); ok {
		response.RouterAddr = udpAddr.IP
	}

	return response, nil
}

// ValidatePMTUDResponse validates that the PMTUD response is reasonable
func ValidatePMTUDResponse(response *PMTUDResponse) error {
	if response == nil {
		return fmt.Errorf("response is nil")
	}

	// Validate MTU value for Packet Too Big messages
	if response.IsPacketTooBig() {
		if response.ReportedMTU < 68 {
			return fmt.Errorf("reported MTU too small: %d (minimum is 68)", response.ReportedMTU)
		}
		if response.ReportedMTU > 65535 {
			return fmt.Errorf("reported MTU too large: %d (maximum is 65535)", response.ReportedMTU)
		}
	}

	return nil
}

// ExtractOriginalPacket extracts the original packet from ICMP6 error message
func ExtractOriginalPacket(data []byte) ([]byte, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("ICMP6 message too short to contain original packet")
	}

	// ICMP6 error messages include the original packet starting at byte 8
	if len(data) > 8 {
		return data[8:], nil
	}

	return nil, fmt.Errorf("no original packet data found")
}
