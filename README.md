# IPv6 MTU Discovery Tool

English | [中文](README_zh.md)

A command-line tool for discovering IPv6 path MTU and detecting TCP MSS clamping.

## Features

- IPv6 Path MTU Discovery using ICMP6 probes
- TCP MSS clamping detection (client and server modes)
- MSS integrity verification and tampering detection
- Binary search algorithm for efficient MTU discovery
- Cross-platform support (Linux, macOS, Windows)
- Detailed progress reporting and statistics
- Network error scenario handling
- Concurrent operation support

## Requirements

- Go 1.19 or later
- Root/Administrator privileges (for raw socket operations)
- IPv6 network connectivity

## Installation

### From Source

```bash
git clone <repository-url>
cd ipv6-mtu-discovery
make deps
make build
```

### Install System-wide

```bash
make install
```

## Usage

### MTU Discovery

```bash
# Basic MTU discovery
sudo ./ipv6-mtu-discovery -t 2001:db8::1

# Verbose output
sudo ./ipv6-mtu-discovery -t 2001:db8::1 -v

# Custom timeout
sudo ./ipv6-mtu-discovery -t 2001:db8::1 -T 10
```

### TCP MSS Detection

```bash
# Client mode MSS detection
sudo ./ipv6-mtu-discovery -t 2001:db8::1 -m tcp-client -p 80

# Server mode MSS detection
sudo ./ipv6-mtu-discovery -t :: -m tcp-server -p 8080

# MSS integrity verification
sudo ./ipv6-mtu-discovery -t 2001:db8::1 -m mss-integrity -p 80 --control-port 8080 --test-mss 1460
```

## Command Line Options

### Basic Options
- `-t, --target`: Target IPv6 address (required)
- `-m, --mode`: Operation mode (mtu, tcp-client, tcp-server, mss-integrity) [default: mtu]
- `-p, --port`: TCP port for MSS detection [default: 80]
- `-v, --verbose`: Enable verbose output
- `-T, --timeout`: Timeout in seconds [default: 5]

### MTU Discovery Options
- `--min-mtu`: Minimum MTU value [default: 68]
- `--max-mtu`: Maximum MTU value [default: 1500]

### MSS Integrity Verification Options
- `--control-port`: Control connection port
- `--test-mss`: Test MSS value

### Logging Options
- `--log-level`: Log level (debug, info, warn, error)
- `--log-file`: Enable file logging
- `--log-path`: Log file path

## Build Targets

```bash
make build      # Build the binary
make test       # Run tests
make clean      # Clean build artifacts
make deps       # Download dependencies
make lint       # Format and vet code
make install    # Install system-wide
```

## Testing

### Run All Tests
```bash
make test
```

### Run Integration Tests
```bash
# Run all tests (including integration tests)
./test_integration.sh

# Run unit tests only
./test_integration.sh unit

# Run integration tests only
./test_integration.sh integration
```

## Architecture

The tool is organized into several packages:

- `cmd/`: Main application entry point
- `internal/app/`: Application logic and state management
- `internal/cli/`: Command line interface and argument parsing
- `internal/probe/`: ICMP6 probing and packet handling
- `internal/network/`: TCP connection and MSS detection
- `internal/validator/`: IPv6 address and permission validation
- `internal/algorithm/`: Binary search implementation
- `internal/display/`: Result formatting and display
- `internal/config/`: Configuration management
- `internal/stats/`: Statistics collection
- `internal/logging/`: Logging system
- `internal/platform/`: Platform-specific functionality

## Operation Modes

### 1. MTU Discovery Mode (`mtu`)
Performs IPv6 Path MTU Discovery using ICMP6 echo requests:
- Uses binary search algorithm for efficient MTU determination
- Handles ICMP6 "Packet Too Big" responses
- Provides detailed probe progress and statistics

### 2. TCP Client MSS Detection (`tcp-client`)
Detects MSS clamping as a TCP client:
- Connects to specified server and port
- Detects negotiated MSS value
- Identifies MSS clamping scenarios

### 3. TCP Server MSS Detection (`tcp-server`)
Detects MSS clamping as a TCP server:
- Listens on specified port for connections
- Captures client MSS values
- Analyzes MSS modifications

### 4. MSS Integrity Verification (`mss-integrity`)
Verifies MSS value integrity:
- Establishes control connection for verification exchange
- Detects MSS tampering and modifications
- Provides detailed integrity analysis reports

## Usage Examples

### Basic MTU Discovery
```bash
# Discover path MTU to Google IPv6 DNS
sudo ./ipv6-mtu-discovery -t 2001:4860:4860::8888 -v

# Example output:
# Starting IPv6 Path MTU Discovery to 2001:4860:4860::8888
# Testing MTU 784... Success
# Testing MTU 1142... Success  
# Testing MTU 1321... Failed (Packet Too Big, reported MTU: 1280)
# Testing MTU 1280... Success
# 
# MTU Discovery Results:
# Final MTU: 1280 bytes
# Probe attempts: 4
# Success rate: 75%
```

### MSS Integrity Verification
```bash
# Verify if MSS is modified by intermediate devices
sudo ./ipv6-mtu-discovery -t 2001:db8::1 -m mss-integrity \
  -p 80 --control-port 8080 --test-mss 1460 -v

# Example output:
# Starting MSS Integrity Verification
# Test MSS: 1460, Control Port: 8080
# Establishing control connection...
# Performing MSS integrity verification...
# 
# MSS Integrity Results:
# Client sent MSS: 1460
# Server received MSS: 1440
# MSS Modified: Yes
# Modification Delta: -20
# Tampering Detected: Yes (Medium severity)
```

## Configuration

Supports YAML configuration file for advanced settings:

```yaml
# config.yaml example
network:
  timeout_ms: 5000
  max_retries: 3
  
mtu_discovery:
  min_mtu: 68
  max_mtu: 1500
  probe_timeout_ms: 3000
  
mss_verification:
  session_timeout_ms: 10000
  handshake_timeout_ms: 5000
  
logging:
  level: "info"
  file_enabled: true
  file_path: "logs/ipv6-mtu-discovery.log"
```

## Troubleshooting

### Common Issues

1. **Permission Denied**
   ```bash
   # Error: socket: operation not permitted
   # Solution: Run with sudo
   sudo ./ipv6-mtu-discovery -t ::1
   ```

2. **IPv6 Not Supported**
   ```bash
   # Check IPv6 support
   ip -6 addr show
   # Enable IPv6 loopback
   sudo sysctl net.ipv6.conf.lo.disable_ipv6=0
   ```

3. **Firewall Blocking**
   ```bash
   # Temporarily allow ICMP6
   sudo ip6tables -I INPUT -p ipv6-icmp -j ACCEPT
   ```

## Related Documentation

- [Integration Tests Documentation](INTEGRATION_TESTS.md)
- [Architecture Design](docs/architecture.md)
- [API Documentation](docs/api.md)

## License

[License information to be added]

## Contributing

Contributions are welcome! Please see [Contributing Guidelines](CONTRIBUTING.md).

### Development Setup

1. Clone the repository
2. Install Go 1.19+
3. Run `make deps` to install dependencies
4. Run `make test` to ensure tests pass
5. Use `make lint` to check code quality

## Support

For questions or suggestions:
1. Check the [FAQ](docs/faq.md)
2. Search existing [Issues](../../issues)
3. Create a new Issue describing the problem

---

**Note**: This tool requires raw socket privileges. Please ensure you use it in a trusted environment.