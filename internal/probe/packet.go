package probe

import (
	"fmt"
	"net"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
)

// ICMP6Packet represents an ICMP6 packet for MTU probing
type ICMP6Packet struct {
	Type        ipv6.ICMPType
	Code        int
	Checksum    int
	Body        icmp.MessageBody
	Data        []byte
	PayloadSize int
	ID          int
	Sequence    int
}

// BuildICMP6Packet constructs an ICMP6 packet with the specified payload size
// This creates an Echo Request packet with the given payload size for MTU probing
func BuildICMP6Packet(payloadSize int) (*ICMP6Packet, error) {
	if payloadSize < 0 {
		return nil, fmt.Errorf("payload size cannot be negative: %d", payloadSize)
	}

	// Create payload data filled with a pattern for easier debugging
	data := make([]byte, payloadSize)
	for i := range data {
		data[i] = byte(i % 256)
	}

	return &ICMP6Packet{
		Type:        ipv6.ICMPTypeEchoRequest,
		Code:        0,
		Data:        data,
		PayloadSize: payloadSize,
		ID:          1, // Fixed ID for simplicity
		Sequence:    1, // Will be incremented for each probe
	}, nil
}

// BuildICMP6PacketWithSequence constructs an ICMP6 packet with specific ID and sequence
func BuildICMP6PacketWithSequence(payloadSize, id, sequence int) (*ICMP6Packet, error) {
	packet, err := BuildICMP6Packet(payloadSize)
	if err != nil {
		return nil, err
	}

	packet.ID = id
	packet.Sequence = sequence
	return packet, nil
}

// Marshal serializes the packet to bytes with proper checksum calculation
func (p *ICMP6Packet) Marshal() ([]byte, error) {
	// Create the ICMP message body
	body := &icmp.Echo{
		ID:   p.ID,
		Seq:  p.Sequence,
		Data: p.Data,
	}

	// Create the ICMP message
	message := &icmp.Message{
		Type: p.Type,
		Code: p.Code,
		Body: body,
	}

	// Marshal the message - the golang.org/x/net/icmp package handles checksum calculation
	data, err := message.Marshal(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ICMP6 packet: %w", err)
	}

	return data, nil
}

// GetTotalSize returns the total size of the packet including headers
func (p *ICMP6Packet) GetTotalSize() int {
	// ICMP6 header is 8 bytes (Type(1) + Code(1) + Checksum(2) + ID(2) + Sequence(2))
	// Plus the payload data
	return 8 + len(p.Data)
}

// SetSequence updates the sequence number for the packet
func (p *ICMP6Packet) SetSequence(seq int) {
	p.Sequence = seq
}

// SendICMP6Probe sends an ICMP6 probe packet to the target
func SendICMP6Probe(conn *icmp.PacketConn, target *net.IPAddr, packet *ICMP6Packet) error {
	if conn == nil {
		return fmt.Errorf("connection is nil")
	}
	if target == nil {
		return fmt.Errorf("target address is nil")
	}

	debugf("SendICMP6Probe - target: %s, packet ID: %d, seq: %d\n",
		target.String(), packet.ID, packet.Sequence)

	// Marshal the packet
	data, err := packet.Marshal()
	if err != nil {
		debugf("Failed to marshal packet: %v\n", err)
		return fmt.Errorf("failed to marshal packet: %w", err)
	}

	debugf("Marshaled packet - size: %d bytes\n", len(data))

	// Send the packet
	n, err := conn.WriteTo(data, target)
	if err != nil {
		debugf("Failed to send packet: %v\n", err)
		return fmt.Errorf("failed to send ICMP6 probe: %w", err)
	}

	debugf("Successfully sent %d bytes to %s\n", n, target.String())
	return nil
}

// CreateProbePacketForMTU creates an ICMP6 packet sized to test a specific MTU
// The packet size includes IPv6 header (40 bytes) + ICMP6 header (8 bytes) + payload
func CreateProbePacketForMTU(targetMTU int, id, sequence int) (*ICMP6Packet, error) {
	if targetMTU < 68 {
		return nil, fmt.Errorf("MTU too small: %d (minimum is 68)", targetMTU)
	}

	// Calculate payload size: MTU - IPv6 header (40) - ICMP6 header (8)
	payloadSize := targetMTU - 40 - 8
	if payloadSize < 0 {
		payloadSize = 0
	}

	return BuildICMP6PacketWithSequence(payloadSize, id, sequence)
}
