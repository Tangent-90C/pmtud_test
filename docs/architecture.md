# Project Architecture

## Directory Structure

```
ipv6-mtu-discovery/
├── cmd/                    # Application entry points
│   └── main.go            # Main application entry point
├── internal/              # Private application code
│   ├── app/               # Application logic and state management
│   │   └── app.go         # Main application struct and run logic
│   ├── cli/               # Command line interface
│   │   ├── cli.go         # CLI parsing and setup
│   │   ├── types.go       # CLI argument types and validation
│   │   └── errors.go      # Error definitions and handling
│   ├── probe/             # ICMP6 probing functionality
│   │   ├── icmp6.go       # ICMP6 prober implementation
│   │   ├── packet.go      # ICMP6 packet construction
│   │   └── pmtud.go       # PMTUD response parsing
│   ├── network/           # TCP networking functionality
│   │   ├── mss.go         # MSS detection implementation
│   │   └── tcp.go         # TCP connection management
│   ├── validator/         # Input validation
│   │   ├── ipv6.go        # IPv6 address validation
│   │   └── permission.go  # Permission checking
│   ├── algorithm/         # Core algorithms
│   │   └── binary_search.go # Binary search for MTU discovery
│   ├── display/           # Output formatting
│   │   └── result.go      # Result display and formatting
│   ├── config/            # Configuration management
│   │   └── config.go      # Configuration structures and loading
│   └── stats/             # Statistics collection
│       └── stats.go       # Network and probe statistics
├── build/                 # Build output directory
├── docs/                  # Documentation
│   └── architecture.md    # This file
├── go.mod                 # Go module definition
├── go.sum                 # Go module checksums
├── Makefile              # Build automation
└── README.md             # Project documentation
```

## Package Dependencies

```
cmd/main.go
└── internal/app
    ├── internal/cli
    │   └── internal/cli/errors
    ├── internal/config
    ├── internal/network
    ├── internal/probe
    └── internal/validator

internal/probe
├── internal/validator (for IPv6Address)
└── golang.org/x/net/icmp
└── golang.org/x/net/ipv6

internal/network
├── internal/cli (for ProbeMode)
└── internal/validator (for IPv6Address)

internal/display
├── internal/network (for MSSResult)
└── internal/probe (for MTUResult, PMTUDResponse)

internal/cli
└── github.com/spf13/cobra
```

## Core Interfaces

The project defines several key interfaces that will be implemented in subsequent tasks:

1. **Prober Interface**: For MTU probing operations
2. **Detector Interface**: For MSS detection operations  
3. **Validator Interface**: For input validation
4. **Display Interface**: For result formatting

## Data Flow

1. **Input Processing**: CLI arguments → Validation → Application State
2. **Probe Execution**: State → Prober/Detector → Results
3. **Output Generation**: Results → Display → User Output

## Error Handling Strategy

- Custom error types with error codes
- Graceful degradation for network errors
- User-friendly error messages
- Proper resource cleanup on errors