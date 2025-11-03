# pmtud_test
Path MTU Discovery Test Site

## Overview

This repository provides a test site for Path MTU Discovery (PMTUD) functionality. PMTUD is a standardized technique in computer networking for determining the maximum transmission unit (MTU) size on the network path between two IP hosts.

## What is Path MTU Discovery?

Path MTU Discovery (PMTUD) is a method that allows network hosts to determine the largest packet size that can be transmitted across a network path without fragmentation. 

### Key Concepts

- **MTU (Maximum Transmission Unit)**: The largest packet or frame size that can be transmitted in a single network-layer transaction
- **PMTUD**: A technique that discovers the path MTU by sending packets with the "Don't Fragment" (DF) bit set
- **ICMP Fragmentation Needed**: When a packet is too large, routers return this message to indicate the maximum size accepted

### How PMTUD Works

1. The sender transmits packets with the DF (Don't Fragment) bit set
2. If a router along the path cannot forward the packet due to MTU constraints, it:
   - Drops the packet
   - Sends an ICMP "Fragmentation Needed" message back to the sender
   - Includes the MTU of the next hop
3. The sender reduces the packet size and retries
4. This process continues until the optimal MTU is discovered

## Purpose of This Test Site

This test site allows you to:

- Verify that PMTUD is working correctly in your network
- Diagnose MTU-related connectivity issues
- Test network path behavior with different packet sizes
- Validate firewall and router configurations related to PMTUD

## Common Use Cases

### Troubleshooting Connection Issues

If you experience:
- Connections that establish but hang during data transfer
- Problems accessing certain websites while others work fine
- SSH/VPN connections that connect but freeze

These may be symptoms of PMTUD blackholing, where ICMP messages are blocked.

### Testing Network Configuration

Network administrators can use this site to:
- Verify ICMP Fragmentation Needed messages are properly forwarded
- Test MTU configuration on routers and firewalls
- Validate end-to-end path MTU discovery functionality

## Technical Details

### Standards and RFCs

- **RFC 1191**: Path MTU Discovery (IPv4)
- **RFC 8201**: Path MTU Discovery for IP version 6 (IPv6)
- **RFC 4821**: Packetization Layer Path MTU Discovery

### Common MTU Values

- **1500 bytes**: Standard Ethernet MTU
- **1492 bytes**: PPPoE connections
- **1280 bytes**: Minimum MTU for IPv6
- **576 bytes**: Minimum MTU for IPv4
- **9000 bytes**: Jumbo frames (specialized networks)

## Testing Your Connection

To test PMTUD functionality from your system:

### Linux/macOS
```bash
# Test with a specific packet size (replace <test-site> with your target hostname/IP)
ping -M do -s 1472 <test-site>

# Trace path MTU
tracepath <test-site>
```

### Windows
```cmd
# Test with specific packet size and Don't Fragment bit (replace <test-site> with target)
ping -f -l 1472 <test-site>

# Test different sizes
ping -f -l 1400 <test-site>
```

### Expected Behavior

- **Success**: Packets of appropriate size receive replies
- **Failure with "Packet needs to be fragmented"**: Indicates path MTU is smaller than test size
- **Timeout with DF bit set**: May indicate PMTUD blackholing

## Common Issues and Solutions

### PMTUD Blackholing

**Problem**: ICMP messages are blocked by firewalls, preventing PMTUD from working.

**Solutions**:
- Allow ICMP Type 3, Code 4 (IPv4) messages through firewalls
- Allow ICMPv6 Type 2 (Packet Too Big) messages for IPv6
- Consider implementing RFC 4821 (Packetization Layer PMTUD) as a fallback

### MSS Clamping

For TCP connections, Maximum Segment Size (MSS) clamping can work around PMTUD issues:
```bash
# Linux: Clamp MSS on interface
iptables -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
```

## Contributing

Contributions to improve this test site are welcome! Please feel free to:
- Report issues or bugs
- Suggest improvements
- Submit pull requests

## References

- [RFC 1191 - Path MTU Discovery](https://tools.ietf.org/html/rfc1191)
- [RFC 8201 - Path MTU Discovery for IPv6](https://tools.ietf.org/html/rfc8201)
- [RFC 4821 - Packetization Layer Path MTU Discovery](https://tools.ietf.org/html/rfc4821)
- [Wikipedia: Path MTU Discovery](https://en.wikipedia.org/wiki/Path_MTU_Discovery)

## License

Please refer to the LICENSE file for licensing information.

## Support

For questions, issues, or support, please open an issue in this repository.
