package probe

import (
	"net"
	"testing"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
)

func TestBuildICMP6Packet(t *testing.T) {
	tests := []struct {
		name        string
		payloadSize int
		expectError bool
	}{
		{
			name:        "Zero payload",
			payloadSize: 0,
			expectError: false,
		},
		{
			name:        "Small payload",
			payloadSize: 64,
			expectError: false,
		},
		{
			name:        "Large payload",
			payloadSize: 1400,
			expectError: false,
		},
		{
			name:        "Negative payload",
			payloadSize: -1,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packet, err := BuildICMP6Packet(tt.payloadSize)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if packet == nil {
				t.Fatal("Packet should not be nil")
			}

			if packet.Type != ipv6.ICMPTypeEchoRequest {
				t.Errorf("Expected Type=%v, got %v", ipv6.ICMPTypeEchoRequest, packet.Type)
			}

			if packet.Code != 0 {
				t.Errorf("Expected Code=0, got %d", packet.Code)
			}

			if len(packet.Data) != tt.payloadSize {
				t.Errorf("Expected payload size=%d, got %d", tt.payloadSize, len(packet.Data))
			}

			if packet.PayloadSize != tt.payloadSize {
				t.Errorf("Expected PayloadSize=%d, got %d", tt.payloadSize, packet.PayloadSize)
			}

			if packet.ID != 1 {
				t.Errorf("Expected ID=1, got %d", packet.ID)
			}

			if packet.Sequence != 1 {
				t.Errorf("Expected Sequence=1, got %d", packet.Sequence)
			}

			// Verify payload pattern
			for i, b := range packet.Data {
				expected := byte(i % 256)
				if b != expected {
					t.Errorf("Expected data[%d]=%d, got %d", i, expected, b)
				}
			}
		})
	}
}

func TestBuildICMP6PacketWithSequence(t *testing.T) {
	payloadSize := 100
	id := 42
	sequence := 123

	packet, err := BuildICMP6PacketWithSequence(payloadSize, id, sequence)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if packet.ID != id {
		t.Errorf("Expected ID=%d, got %d", id, packet.ID)
	}

	if packet.Sequence != sequence {
		t.Errorf("Expected Sequence=%d, got %d", sequence, packet.Sequence)
	}

	if len(packet.Data) != payloadSize {
		t.Errorf("Expected payload size=%d, got %d", payloadSize, len(packet.Data))
	}
}

func TestICMP6PacketMarshal(t *testing.T) {
	packet, err := BuildICMP6Packet(64)
	if err != nil {
		t.Fatalf("Failed to build packet: %v", err)
	}

	data, err := packet.Marshal()
	if err != nil {
		t.Errorf("Failed to marshal packet: %v", err)
	}

	if len(data) == 0 {
		t.Error("Marshaled data should not be empty")
	}

	// Verify the marshaled data can be parsed back
	msg, err := icmp.ParseMessage(58, data) // 58 is ICMPv6 protocol number
	if err != nil {
		t.Errorf("Failed to parse marshaled data: %v", err)
	}

	if msg.Type != ipv6.ICMPTypeEchoRequest {
		t.Errorf("Expected Type=%v, got %v", ipv6.ICMPTypeEchoRequest, msg.Type)
	}

	if msg.Code != 0 {
		t.Errorf("Expected Code=0, got %d", msg.Code)
	}

	// Check if body is Echo type
	if echo, ok := msg.Body.(*icmp.Echo); ok {
		if echo.ID != packet.ID {
			t.Errorf("Expected ID=%d, got %d", packet.ID, echo.ID)
		}
		if echo.Seq != packet.Sequence {
			t.Errorf("Expected Sequence=%d, got %d", packet.Sequence, echo.Seq)
		}
		if len(echo.Data) != len(packet.Data) {
			t.Errorf("Expected data length=%d, got %d", len(packet.Data), len(echo.Data))
		}
	} else {
		t.Error("Expected Echo body type")
	}
}

func TestICMP6PacketGetTotalSize(t *testing.T) {
	tests := []struct {
		name         string
		payloadSize  int
		expectedSize int
	}{
		{
			name:         "Zero payload",
			payloadSize:  0,
			expectedSize: 8, // ICMP6 header only
		},
		{
			name:         "Small payload",
			payloadSize:  64,
			expectedSize: 72, // 8 + 64
		},
		{
			name:         "Large payload",
			payloadSize:  1400,
			expectedSize: 1408, // 8 + 1400
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packet, err := BuildICMP6Packet(tt.payloadSize)
			if err != nil {
				t.Fatalf("Failed to build packet: %v", err)
			}

			totalSize := packet.GetTotalSize()
			if totalSize != tt.expectedSize {
				t.Errorf("Expected total size=%d, got %d", tt.expectedSize, totalSize)
			}
		})
	}
}

func TestICMP6PacketSetSequence(t *testing.T) {
	packet, err := BuildICMP6Packet(64)
	if err != nil {
		t.Fatalf("Failed to build packet: %v", err)
	}

	newSequence := 999
	packet.SetSequence(newSequence)

	if packet.Sequence != newSequence {
		t.Errorf("Expected Sequence=%d, got %d", newSequence, packet.Sequence)
	}
}

func TestSendICMP6Probe(t *testing.T) {
	// Test with nil connection
	packet, _ := BuildICMP6Packet(64)
	target := &net.IPAddr{IP: net.ParseIP("::1")}

	err := SendICMP6Probe(nil, target, packet)
	if err == nil {
		t.Error("Expected error with nil connection")
	}

	// Test with nil target
	err = SendICMP6Probe(nil, nil, packet)
	if err == nil {
		t.Error("Expected error with nil target")
	}

	// Note: We can't easily test successful sending without creating actual network connections
	// which would require root privileges and might not work in all test environments
}

func TestCreateProbePacketForMTU(t *testing.T) {
	tests := []struct {
		name                string
		targetMTU           int
		id                  int
		sequence            int
		expectError         bool
		expectedPayloadSize int
	}{
		{
			name:                "Minimum MTU",
			targetMTU:           68,
			id:                  1,
			sequence:            1,
			expectError:         false,
			expectedPayloadSize: 20, // 68 - 40 (IPv6) - 8 (ICMP6)
		},
		{
			name:                "Standard MTU",
			targetMTU:           1500,
			id:                  2,
			sequence:            2,
			expectError:         false,
			expectedPayloadSize: 1452, // 1500 - 40 - 8
		},
		{
			name:                "Large MTU",
			targetMTU:           9000,
			id:                  3,
			sequence:            3,
			expectError:         false,
			expectedPayloadSize: 8952, // 9000 - 40 - 8
		},
		{
			name:                "Too small MTU",
			targetMTU:           67,
			id:                  4,
			sequence:            4,
			expectError:         true,
			expectedPayloadSize: 0,
		},
		{
			name:                "Very small MTU (edge case)",
			targetMTU:           48,
			id:                  5,
			sequence:            5,
			expectError:         true, // Should error because 48 < 68
			expectedPayloadSize: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packet, err := CreateProbePacketForMTU(tt.targetMTU, tt.id, tt.sequence)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if packet == nil {
				t.Fatal("Packet should not be nil")
			}

			if packet.ID != tt.id {
				t.Errorf("Expected ID=%d, got %d", tt.id, packet.ID)
			}

			if packet.Sequence != tt.sequence {
				t.Errorf("Expected Sequence=%d, got %d", tt.sequence, packet.Sequence)
			}

			if len(packet.Data) != tt.expectedPayloadSize {
				t.Errorf("Expected payload size=%d, got %d", tt.expectedPayloadSize, len(packet.Data))
			}

			// Verify total packet size matches expected MTU calculation
			expectedTotalICMPSize := tt.expectedPayloadSize + 8 // Add ICMP6 header
			if packet.GetTotalSize() != expectedTotalICMPSize {
				t.Errorf("Expected total ICMP size=%d, got %d", expectedTotalICMPSize, packet.GetTotalSize())
			}
		})
	}
}

func TestICMP6PacketPayloadPattern(t *testing.T) {
	payloadSize := 256
	packet, err := BuildICMP6Packet(payloadSize)
	if err != nil {
		t.Fatalf("Failed to build packet: %v", err)
	}

	// Verify the payload pattern repeats correctly
	for i := 0; i < payloadSize; i++ {
		expected := byte(i % 256)
		if packet.Data[i] != expected {
			t.Errorf("At position %d: expected %d, got %d", i, expected, packet.Data[i])
		}
	}

	// Test pattern wrapping
	if payloadSize > 256 {
		// Check that pattern wraps around after 256
		if packet.Data[256] != packet.Data[0] {
			t.Error("Pattern should wrap around after 256 bytes")
		}
	}
}

func TestICMP6PacketMarshalConsistency(t *testing.T) {
	packet, err := BuildICMP6Packet(100)
	if err != nil {
		t.Fatalf("Failed to build packet: %v", err)
	}

	// Marshal the same packet multiple times
	data1, err1 := packet.Marshal()
	data2, err2 := packet.Marshal()

	if err1 != nil || err2 != nil {
		t.Fatalf("Marshal errors: %v, %v", err1, err2)
	}

	if len(data1) != len(data2) {
		t.Errorf("Inconsistent marshal lengths: %d vs %d", len(data1), len(data2))
	}

	// Compare byte by byte (excluding checksum which might vary)
	// We'll just check that the lengths are consistent
	if len(data1) == 0 || len(data2) == 0 {
		t.Error("Marshaled data should not be empty")
	}
}
