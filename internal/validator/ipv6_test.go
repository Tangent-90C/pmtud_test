package validator

import (
	"testing"
	"time"
)

func TestValidateIPv6Address(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectValid bool
		expectError bool
	}{
		// Valid IPv6 addresses
		{
			name:        "Valid full IPv6 address",
			input:       "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
			expectValid: true,
			expectError: false,
		},
		{
			name:        "Valid compressed IPv6 address",
			input:       "2001:db8:85a3::8a2e:370:7334",
			expectValid: true,
			expectError: false,
		},
		{
			name:        "Valid loopback address",
			input:       "::1",
			expectValid: true,
			expectError: false,
		},
		{
			name:        "Valid all zeros address",
			input:       "::",
			expectValid: true,
			expectError: false,
		},
		{
			name:        "Valid link-local address",
			input:       "fe80::1",
			expectValid: true,
			expectError: false,
		},
		{
			name:        "Valid multicast address",
			input:       "ff02::1",
			expectValid: true,
			expectError: false,
		},

		// Invalid IPv6 addresses
		{
			name:        "Empty string",
			input:       "",
			expectValid: false,
			expectError: true,
		},
		{
			name:        "IPv4 address",
			input:       "192.168.1.1",
			expectValid: false,
			expectError: true,
		},
		{
			name:        "Invalid format - too many colons",
			input:       "2001:db8:::85a3::8a2e:370:7334",
			expectValid: false,
			expectError: true,
		},
		{
			name:        "Invalid format - invalid hex characters",
			input:       "2001:db8:85g3::8a2e:370:7334",
			expectValid: false,
			expectError: true,
		},
		{
			name:        "Invalid format - group too long",
			input:       "2001:db8:85a33::8a2e:370:7334",
			expectValid: false,
			expectError: true,
		},
		{
			name:        "Invalid format - malformed",
			input:       "not-an-ipv6-address",
			expectValid: false,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ValidateIPv6Address(tt.input)

			if tt.expectError && err == nil {
				t.Errorf("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			if result == nil {
				t.Fatal("Result should not be nil")
			}

			if result.IsValid != tt.expectValid {
				t.Errorf("Expected IsValid=%v, got %v", tt.expectValid, result.IsValid)
			}

			if result.Original != tt.input {
				t.Errorf("Expected Original=%s, got %s", tt.input, result.Original)
			}
		})
	}
}

func TestValidateIPv6AddressWithZoneAndPort(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectValid bool
	}{
		{
			name:        "IPv6 with zone identifier",
			input:       "fe80::1%eth0",
			expectValid: true,
		},
		{
			name:        "IPv6 with port in brackets",
			input:       "[2400:3200::1]:80",
			expectValid: true,
		},
		{
			name:        "IPv6 with whitespace",
			input:       "  2400:3200::1  ",
			expectValid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ValidateIPv6Address(tt.input)

			if tt.expectValid && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			if result.IsValid != tt.expectValid {
				t.Errorf("Expected IsValid=%v, got %v", tt.expectValid, result.IsValid)
			}
		})
	}
}

func TestIPv6AddressMethods(t *testing.T) {
	// Test loopback detection
	loopback, _ := ValidateIPv6Address("::1")
	if !loopback.IsLoopback() {
		t.Error("Expected ::1 to be detected as loopback")
	}

	// Test link-local detection
	linkLocal, _ := ValidateIPv6Address("fe80::1")
	if !linkLocal.IsLinkLocal() {
		t.Error("Expected fe80::1 to be detected as link-local")
	}

	// Test multicast detection
	multicast, _ := ValidateIPv6Address("ff02::1")
	if !multicast.IsMulticast() {
		t.Error("Expected ff02::1 to be detected as multicast")
	}

	// Test invalid address methods
	invalid, _ := ValidateIPv6Address("invalid")
	if invalid.IsLoopback() || invalid.IsLinkLocal() || invalid.IsMulticast() {
		t.Error("Invalid address should not match any type checks")
	}
}

func TestIPv6AddressString(t *testing.T) {
	valid, _ := ValidateIPv6Address("2400:3200::1")
	if valid.String() != "2400:3200::1" {
		t.Errorf("Expected string representation to be '2400:3200::1', got '%s'", valid.String())
	}

	invalid, _ := ValidateIPv6Address("invalid")
	expected := "Invalid IPv6: invalid"
	if invalid.String() != expected {
		t.Errorf("Expected string representation to be '%s', got '%s'", expected, invalid.String())
	}
}

func TestCheckReachability(t *testing.T) {
	// Test with invalid address
	invalid, _ := ValidateIPv6Address("invalid")
	err := invalid.CheckReachability(time.Second)
	if err == nil {
		t.Error("Expected error when checking reachability of invalid address")
	}

	// Test with valid address (loopback should be reachable)
	loopback, _ := ValidateIPv6Address("::1")
	err = loopback.CheckReachability(time.Second)
	// Note: This may fail in some environments without IPv6 support
	// We just check that the method doesn't panic and handles the case
	if err != nil {
		t.Logf("Reachability check failed (may be expected in test environment): %v", err)
	}
}

func TestValidateIPv6Format(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectError bool
	}{
		{
			name:        "Valid format with compression",
			input:       "2400:3200::1",
			expectError: false,
		},
		{
			name:        "Invalid - too many colons",
			input:       "2001:db8:::::1",
			expectError: true,
		},
		{
			name:        "Invalid - multiple double colons",
			input:       "2001::db8::1",
			expectError: true,
		},
		{
			name:        "Invalid - unnecessary compression",
			input:       "2001:0:0:0:0:0:0:1",
			expectError: false, // This is actually valid, just not compressed
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateIPv6Format(tt.input)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestIsHexDigit(t *testing.T) {
	validHex := []rune{'0', '1', '9', 'a', 'f', 'A', 'F'}
	for _, char := range validHex {
		if !isHexDigit(char) {
			t.Errorf("Expected %c to be valid hex digit", char)
		}
	}

	invalidHex := []rune{'g', 'G', 'z', 'Z', '!', '@'}
	for _, char := range invalidHex {
		if isHexDigit(char) {
			t.Errorf("Expected %c to be invalid hex digit", char)
		}
	}
}
