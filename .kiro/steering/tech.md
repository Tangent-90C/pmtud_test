# Technology Stack & Build System

## Tech Stack

- **Language**: Go 1.19+
- **CLI Framework**: Cobra (github.com/spf13/cobra)
- **Configuration**: Viper (github.com/spf13/viper) with YAML support
- **Network**: golang.org/x/net for low-level networking, golang.org/x/sys for system calls
- **Raw Sockets**: Platform-specific implementations (Linux, macOS, Windows)

## Build System

Uses Make for build automation with the following targets:

### Common Commands

```bash
# Development
make deps          # Download dependencies
make build         # Build the binary
make test          # Run all tests
make lint          # Format and vet code (runs fmt + vet)

# Testing
make test-coverage # Run tests with coverage report
./test_integration.sh        # Run integration tests
./test_integration.sh unit   # Unit tests only
./test_integration.sh integration # Integration tests only

# Deployment
make install       # Install system-wide to /usr/local/bin
make uninstall     # Remove from system
make clean         # Clean build artifacts

# Platform-specific
make build-linux   # Cross-compile for Linux
```

## Project Dependencies

- **Core**: Standard library + golang.org/x/net, golang.org/x/sys
- **CLI**: spf13/cobra for command parsing
- **Config**: spf13/viper for configuration management
- **Testing**: Standard testing package, no external test frameworks

## Build Configuration

- Binary output: `build/ipv6-mtu-discovery`
- Main package: `./cmd`
- Module name: `ipv6-mtu-discovery`
- CGO: Enabled (required for raw sockets)

## Platform Requirements

- **Privileges**: Root/sudo required for raw socket operations
- **IPv6**: Must be enabled on target system
- **Firewall**: ICMP6 and TCP traffic must be allowed