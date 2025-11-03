# IPv6 MTU Discovery Tool

## Product Overview

A command-line tool for discovering IPv6 path MTU and detecting TCP MSS clamping. The tool helps network administrators and developers diagnose IPv6 connectivity issues and identify network devices that modify TCP Maximum Segment Size values.

## Core Features

- **IPv6 Path MTU Discovery**: Uses ICMP6 echo requests with binary search algorithm to efficiently determine maximum transmission unit size
- **TCP MSS Detection**: Operates in client/server modes to detect MSS clamping by network devices
- **MSS Integrity Verification**: Detects tampering and modification of MSS values by intermediate network devices
- **Cross-platform Support**: Works on Linux, macOS, and Windows with appropriate privileges
- **Network Error Handling**: Comprehensive error detection and unreachability analysis

## Operation Modes

1. `mtu` - IPv6 Path MTU Discovery (default)
2. `tcp-client` - TCP MSS detection as client
3. `tcp-server` - TCP MSS detection as server  
4. `mss-integrity` - MSS integrity verification and tampering detection

## Key Requirements

- Root/Administrator privileges (for raw socket operations)
- IPv6 network connectivity
- Go 1.19 or later for building from source