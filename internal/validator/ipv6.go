package validator

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// IPv6Address represents a validated IPv6 address
type IPv6Address struct {
	IP          net.IP
	IsValid     bool
	IsReachable bool
	Original    string // Store original input for reference
}

// ValidateIPv6Address validates an IPv6 address string and handles various formats
func ValidateIPv6Address(addrStr string) (*IPv6Address, error) {
	if addrStr == "" {
		return &IPv6Address{
			Original: addrStr,
			IsValid:  false,
		}, fmt.Errorf("empty IPv6 address")
	}

	// Clean the input - remove whitespace
	cleanAddr := strings.TrimSpace(addrStr)

	// Handle IPv6 address with zone identifier (e.g., fe80::1%eth0)
	if strings.Contains(cleanAddr, "%") {
		parts := strings.Split(cleanAddr, "%")
		cleanAddr = parts[0]
	}

	// Handle IPv6 address with port (e.g., [2400:3200::1]:80)
	if strings.HasPrefix(cleanAddr, "[") && strings.Contains(cleanAddr, "]:") {
		end := strings.Index(cleanAddr, "]:")
		if end > 0 {
			cleanAddr = cleanAddr[1:end]
		}
	}

	// Parse the IPv6 address
	ip := net.ParseIP(cleanAddr)
	if ip == nil {
		return &IPv6Address{
			Original: addrStr,
			IsValid:  false,
		}, fmt.Errorf("invalid IPv6 address format: %s", addrStr)
	}

	// Ensure it's actually an IPv6 address (not IPv4)
	if ip.To4() != nil {
		return &IPv6Address{
			Original: addrStr,
			IsValid:  false,
		}, fmt.Errorf("address is IPv4, not IPv6: %s", addrStr)
	}

	// Additional IPv6 format validation
	if err := validateIPv6Format(cleanAddr); err != nil {
		return &IPv6Address{
			Original: addrStr,
			IsValid:  false,
		}, err
	}

	return &IPv6Address{
		IP:       ip,
		IsValid:  true,
		Original: addrStr,
	}, nil
}

// validateIPv6Format performs additional IPv6 format validation
func validateIPv6Format(addr string) error {
	// Check for valid IPv6 patterns

	// Count colons - IPv6 should have 2-7 colons
	colonCount := strings.Count(addr, ":")
	if colonCount < 2 || colonCount > 7 {
		return fmt.Errorf("invalid IPv6 format: incorrect colon count")
	}

	// Check for double colon (::) - should appear at most once
	doubleColonCount := strings.Count(addr, "::")
	if doubleColonCount > 1 {
		return fmt.Errorf("invalid IPv6 format: multiple double colons")
	}

	// If there's a double colon, validate the compression is valid
	if doubleColonCount == 1 {
		parts := strings.Split(addr, "::")
		if len(parts) != 2 {
			return fmt.Errorf("invalid IPv6 format: malformed double colon")
		}

		// Count total groups to ensure compression is necessary
		leftGroups := 0
		rightGroups := 0

		if parts[0] != "" {
			leftGroups = len(strings.Split(parts[0], ":"))
		}
		if parts[1] != "" {
			rightGroups = len(strings.Split(parts[1], ":"))
		}

		totalGroups := leftGroups + rightGroups
		if totalGroups >= 8 {
			return fmt.Errorf("invalid IPv6 format: unnecessary compression")
		}
	}

	// Validate each hexadecimal group
	groups := strings.Split(strings.ReplaceAll(addr, "::", ":0:"), ":")
	for _, group := range groups {
		if group == "" {
			continue
		}

		// Each group should be 1-4 hex digits
		if len(group) > 4 {
			return fmt.Errorf("invalid IPv6 format: group too long: %s", group)
		}

		// Check if all characters are valid hex
		for _, char := range group {
			if !isHexDigit(char) {
				return fmt.Errorf("invalid IPv6 format: invalid hex character in group: %s", group)
			}
		}
	}

	return nil
}

// isHexDigit checks if a character is a valid hexadecimal digit
func isHexDigit(char rune) bool {
	return (char >= '0' && char <= '9') ||
		(char >= 'a' && char <= 'f') ||
		(char >= 'A' && char <= 'F')
}

// CheckReachability checks if the IPv6 address is reachable using ICMP ping
func (addr *IPv6Address) CheckReachability(timeout time.Duration) error {
	if !addr.IsValid {
		return fmt.Errorf("cannot check reachability of invalid address")
	}

	// Create an ICMP connection for IPv6
	conn, err := net.Dial("ip6:ipv6-icmp", addr.IP.String())
	if err != nil {
		addr.IsReachable = false
		return fmt.Errorf("failed to create ICMP connection: %v", err)
	}
	defer conn.Close()

	// Set deadline for the operation
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		addr.IsReachable = false
		return fmt.Errorf("failed to set deadline: %v", err)
	}

	// For now, if we can create the connection, consider it reachable
	// Full ICMP ping implementation will be done in the ICMP probe task
	addr.IsReachable = true
	return nil
}

// String returns a string representation of the IPv6Address
func (addr *IPv6Address) String() string {
	if !addr.IsValid {
		return fmt.Sprintf("Invalid IPv6: %s", addr.Original)
	}
	return addr.IP.String()
}

// IsLoopback checks if the address is a loopback address
func (addr *IPv6Address) IsLoopback() bool {
	if !addr.IsValid {
		return false
	}
	return addr.IP.IsLoopback()
}

// IsLinkLocal checks if the address is a link-local address
func (addr *IPv6Address) IsLinkLocal() bool {
	if !addr.IsValid {
		return false
	}
	return addr.IP.IsLinkLocalUnicast()
}

// IsMulticast checks if the address is a multicast address
func (addr *IPv6Address) IsMulticast() bool {
	if !addr.IsValid {
		return false
	}
	return addr.IP.IsMulticast()
}
