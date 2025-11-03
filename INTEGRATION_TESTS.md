# Integration Tests Implementation

This document describes the integration tests implemented for the IPv6 MTU Discovery tool.

## Overview

The integration tests cover the complete functionality of the IPv6 MTU discovery tool, including:

1. **MTU Discovery Flow Integration Tests** - Testing the complete MTU discovery process
2. **MSS Detection Functionality Integration Tests** - Testing TCP MSS detection and verification
3. **Network Error Scenarios Integration Tests** - Testing various network error conditions

## Test Files Created

### 1. `internal/app/integration_test.go`
**Application-level integration tests covering:**

- **TestMTUDiscoveryIntegration**: Complete MTU discovery workflow
  - Tests with loopback address (::1)
  - Tests with invalid addresses
  - Validates MTU range results
  - Verifies probe attempt counting

- **TestMSSDetectionIntegration**: MSS detection functionality
  - TCP server mode MSS detection
  - Client-server connection establishment
  - MSS value capture and validation

- **TestNetworkErrorScenarios**: Error handling scenarios
  - Unreachable addresses (2400:3200::1)
  - Connection refused scenarios
  - Invalid port ranges
  - Timeout handling

- **TestApplicationLifecycle**: Complete application execution
  - Full application run with arguments
  - Help command execution
  - Resource cleanup verification

- **TestConcurrentOperations**: Concurrent probe operations
  - Multiple simultaneous MTU probes
  - Resource contention handling
  - Performance under load

- **TestResourceCleanup**: Proper resource management
  - State cleanup verification
  - Double cleanup safety
  - Memory leak prevention

- **TestConfigurationIntegration**: Configuration system
  - Default configuration loading
  - Platform detection integration
  - Configuration validation

- **TestAddressValidationIntegration**: IPv6 address validation
  - Loopback, documentation, and invalid addresses
  - Reachability testing with timeouts
  - Address format validation

### 2. `internal/probe/integration_test.go`
**ICMP6 probing integration tests covering:**

- **TestICMP6ProberIntegration**: Complete ICMP6 probing flow
  - Loopback and link-local address probing
  - MTU range validation
  - Probe attempt statistics

- **TestMTUDiscoveryWithCallbacks**: Callback functionality
  - Progress callback invocation
  - Result callback handling
  - Callback parameter validation

- **TestProbePacketSending**: Actual packet transmission
  - Single probe packet sending
  - Response handling and parsing
  - Timeout management

- **TestPMTUDResponseParsing**: PMTUD response parsing
  - Packet Too Big messages
  - Destination Unreachable messages
  - Echo Reply messages
  - MTU value extraction

- **TestProbeTimeout**: Timeout handling
  - Unreachable address timeout testing
  - Timeout duration validation
  - Context cancellation handling

- **TestConcurrentProbes**: Concurrent probe operations
  - Multiple simultaneous probers
  - Resource sharing and contention
  - Error rate analysis

- **TestProbePacketSizes**: Different packet sizes
  - Various MTU sizes (68, 576, 1280, 1500)
  - Packet size validation
  - IPv6 header accounting

- **TestProbeStatistics**: Statistics collection
  - Probe attempt counting
  - Success rate calculation
  - Performance metrics

### 3. `internal/network/integration_test.go`
**Network and MSS detection integration tests covering:**

- **TestMSSDetectionIntegration**: Complete MSS detection
  - Server mode MSS detection
  - Client mode MSS detection
  - Connection establishment and MSS capture

- **TestMSSIntegrityVerification**: MSS integrity verification
  - Control connection establishment
  - MSS verification session management
  - Tampering detection logic

- **TestTCPManagerIntegration**: TCP connection management
  - IPv6 TCP socket creation
  - TCP listener creation
  - MSS option handling
  - Connection information retrieval

- **TestMSSDetectionWithDifferentSizes**: Various MSS sizes
  - Testing with different MSS values (536, 1280, 1400, 1460)
  - MSS clamping detection
  - Size-specific behavior validation

- **TestMSSDiscoveryIntegration**: MSS discovery process
  - Multiple MSS size testing
  - Connection success tracking
  - Discovery result analysis

- **TestNetworkErrorHandling**: Network error scenarios
  - Connection refused errors
  - Invalid port handling
  - Unreachable address scenarios
  - Error type classification

- **TestConcurrentMSSDetection**: Concurrent MSS operations
  - Multiple simultaneous MSS detectors
  - Connection counting and management
  - Resource cleanup under load

- **TestControlConnectionIntegration**: Control connection functionality
  - Control channel establishment
  - Verification data exchange
  - Protocol message handling

## Test Runner Script

### `test_integration.sh`
A comprehensive test runner script that:

- **Environment Checks**: Verifies IPv6 support and privileges
- **Test Modes**: Supports unit-only, integration-only, or full test runs
- **Error Handling**: Provides clear success/failure reporting
- **Timeout Management**: Configurable test timeouts
- **Usage Examples**: Help documentation and usage patterns

**Usage:**
```bash
# Run all tests
./test_integration.sh

# Run only unit tests
./test_integration.sh unit

# Run only integration tests  
./test_integration.sh integration

# Run with custom timeout
TEST_TIMEOUT=60s ./test_integration.sh
```

## Test Coverage

The integration tests cover the following requirements from the specification:

### Requirement 2.2 (MTU Discovery Algorithm)
- Binary search algorithm integration
- Probe packet generation and sending
- Response parsing and MTU determination
- PMTUD response handling

### Requirement 5.4 (MSS Detection)
- TCP client and server mode MSS detection
- MSS clamping detection and reporting
- Connection establishment with specific MSS values
- MSS integrity verification

### Requirement 4.1 (Network Error Handling)
- Timeout scenarios with unreachable addresses
- Connection refused error handling
- Invalid parameter validation
- Graceful error recovery

## Key Features Tested

1. **End-to-End Workflows**: Complete application execution paths
2. **Error Scenarios**: Network failures, timeouts, and invalid inputs
3. **Concurrent Operations**: Multiple simultaneous operations
4. **Resource Management**: Proper cleanup and resource handling
5. **Cross-Platform Compatibility**: IPv6 support validation
6. **Performance**: Statistics collection and analysis

## Test Environment Requirements

- **IPv6 Support**: Tests require IPv6 loopback (::1) availability
- **Privileges**: Some tests may require root privileges for raw sockets
- **Network Access**: Basic network connectivity for timeout testing
- **Go Version**: Compatible with Go 1.19+

## Test Execution

The tests are designed to:
- **Skip gracefully** when privileges are insufficient
- **Handle timeouts** appropriately for network operations
- **Provide clear output** for debugging and validation
- **Run efficiently** with reasonable timeouts
- **Clean up resources** properly after execution

All integration tests follow Go testing best practices and can be executed individually or as part of the complete test suite.