# Project Structure & Architecture

## Directory Organization

```
├── cmd/                    # Main application entry point
├── internal/               # Private application code
│   ├── algorithm/          # Binary search implementation for MTU discovery
│   ├── app/               # Application logic and state management
│   ├── cli/               # Command line interface and argument parsing
│   ├── config/            # Configuration management and detection
│   ├── display/           # Result formatting and output display
│   ├── logging/           # Logging system and configuration
│   ├── network/           # TCP connections, MSS detection, socket management
│   ├── platform/          # Platform-specific functionality detection
│   ├── probe/             # ICMP6 probing and packet handling
│   ├── stats/             # Statistics collection and analysis
│   └── validator/         # IPv6 address and permission validation
├── build/                 # Build output directory
├── logs/                  # Application logs
└── docs/                  # Documentation
```

## Architecture Patterns

### Package Organization
- **`cmd/`**: Contains only main.go - application bootstrap and signal handling
- **`internal/`**: All business logic organized by domain/responsibility
- **Platform-specific files**: Use build tags and filename suffixes (`_linux.go`, `_darwin.go`, `_windows.go`)

### Error Handling
- Custom error types in `internal/cli/errors.go` with error codes and context
- Structured error handling with severity levels (Info, Warning, Error, Fatal)
- Network errors wrapped with operation context and retry information

### State Management
- Application state centralized in `internal/app/app.go`
- Resource cleanup tracked and executed in reverse order
- Context-based cancellation for graceful shutdown

### Testing Conventions
- Test files use `_test.go` suffix
- Table-driven tests for multiple scenarios
- Integration tests in separate files (`integration_test.go`)
- Mock implementations for network interfaces

## Code Style Guidelines

### Naming Conventions
- Interfaces: Use `-er` suffix (e.g., `Prober`, `Detector`)
- Error variables: Prefix with `Err` (e.g., `ErrInvalidIPv6`)
- Constants: Use descriptive names with appropriate grouping

### Package Dependencies
- No circular dependencies between internal packages
- External dependencies minimized to essential libraries only
- Platform-specific code isolated in separate files

### Configuration
- YAML configuration files supported via Viper
- CLI arguments override configuration file values
- Default values provided for all configuration options