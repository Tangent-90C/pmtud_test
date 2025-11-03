package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"ipv6-mtu-discovery/internal/app"
	"ipv6-mtu-discovery/internal/logging"
)

const (
	// Application metadata
	AppName    = "ipv6-mtu-discovery"
	AppVersion = "1.0.0"

	// Graceful shutdown timeout
	ShutdownTimeout = 5 * time.Second
)

func main() {
	// Set up graceful shutdown
	exitCode := run()
	os.Exit(exitCode)
}

func run() int {
	// Ensure logging is properly closed on exit
	defer func() {
		if err := logging.CloseGlobalLogger(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Failed to close logger: %v\n", err)
		}
	}()

	// Create context that can be cancelled
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT)

	// Handle signals in a separate goroutine
	go func() {
		sig := <-sigChan
		fmt.Fprintf(os.Stderr, "\nReceived signal %v, shutting down gracefully...\n", sig)
		cancel()

		// Force exit if graceful shutdown takes too long
		time.AfterFunc(ShutdownTimeout, func() {
			fmt.Fprintf(os.Stderr, "Shutdown timeout exceeded, forcing exit\n")
			os.Exit(1)
		})
	}()

	// Create application instance
	application, err := createApplication()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create application: %v\n", err)
		return 1
	}

	// Run the application
	if err := application.Run(ctx, os.Args[1:]); err != nil {
		// Check if error is due to context cancellation (graceful shutdown)
		if ctx.Err() != nil {
			fmt.Fprintf(os.Stderr, "Application interrupted\n")
			return 130 // Standard exit code for SIGINT
		}

		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}

	return 0
}

// createApplication creates the application instance with configuration
func createApplication() (*app.App, error) {
	// Try to load configuration from standard locations
	configPaths := []string{
		"config.yaml",
		"config.yml",
		"config.json",
		filepath.Join(os.Getenv("HOME"), ".config", AppName, "config.yaml"),
		filepath.Join("/etc", AppName, "config.yaml"),
	}

	// Try each config path
	for _, configPath := range configPaths {
		if _, err := os.Stat(configPath); err == nil {
			// Config file exists, try to load it
			application, err := app.NewAppWithConfig(configPath)
			if err != nil {
				// Log warning but continue with default config
				fmt.Fprintf(os.Stderr, "Warning: Failed to load config from %s: %v\n", configPath, err)
				continue
			}
			return application, nil
		}
	}

	// No config file found or all failed, use default configuration
	return app.NewApp(), nil
}

// printVersion prints version information
func printVersion() {
	fmt.Printf("%s version %s\n", AppName, AppVersion)
	fmt.Println("Built with Go")
	fmt.Println("Copyright (c) 2024")
}

// handlePanic recovers from panics and provides useful error information
func handlePanic() {
	if r := recover(); r != nil {
		fmt.Fprintf(os.Stderr, "Fatal error: %v\n", r)
		fmt.Fprintf(os.Stderr, "This is likely a bug. Please report it.\n")
		os.Exit(2)
	}
}
