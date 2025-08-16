package caddystarter

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	_ "github.com/caddyserver/caddy/v2/modules/standard"
)

func StartCaddy(host string, port int, useTLS bool) error {
	// Build the Caddyfile dynamically
	tlsDirective := ""
	if useTLS {
		tlsDirective = "tls internal"
	}

	caddyConfig := fmt.Sprintf(`
%s {
    reverse_proxy 127.0.0.1:%d
    %s
}
`, host, port, tlsDirective)

	log.Printf("📁 Caddy config:%s", caddyConfig)

	// Load config into Caddy using the registered caddyfile adapter
	adapter := caddyconfig.GetAdapter("caddyfile")
	if adapter == nil {
		return fmt.Errorf("caddyfile adapter not available")
	}

	configJSON, warnings, err := adapter.Adapt([]byte(caddyConfig), nil)
	if err != nil {
		return fmt.Errorf("failed to adapt caddyfile: %w", err)
	}
	if warnings != nil {
		for _, w := range warnings {
			log.Printf("Caddy warning: %s", w.String())
		}
	}

	// Start Caddy with this config
	err = caddy.Load(configJSON, true)
	if err != nil {
		return fmt.Errorf("failed to start caddy: %w", err)
	}

	log.Printf("✅ Caddy started for %s -> 127.0.0.1:%d (TLS=%v)", host, port, useTLS)
	return nil
}

// StopCaddy gracefully stops the Caddy server
func StopCaddy() error {
	_ = context.Background()
	err := caddy.Stop()
	if err != nil {
		return fmt.Errorf("failed to stop caddy: %w", err)
	}
	log.Println("✅ Caddy stopped gracefully")
	return nil
}

// RunCaddyUntilSignal starts Caddy and keeps it running until interrupted
func RunCaddyUntilSignal(host string, port int, useTLS bool) {
	// Start Caddy
	err := StartCaddy(host, port, useTLS)
	if err != nil {
		log.Fatalf("Failed to start Caddy: %v", err)
	}

	// Create a channel to receive OS signals
	sigChan := make(chan os.Signal, 1)

	// Register the channel to receive specific signals
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	log.Println("🚀 Caddy is running. Press Ctrl+C to stop...")

	// Block until a signal is received
	sig := <-sigChan
	log.Printf("📡 Received signal: %v", sig)

	// Gracefully stop Caddy
	log.Println("🛑 Shutting down Caddy...")
	err = StopCaddy()
	if err != nil {
		log.Printf("Error stopping Caddy: %v", err)
		os.Exit(1)
	}

	log.Println("👋 Goodbye!")
}

// Example usage function
func ExampleUsage() {
	// Start Caddy to proxy localhost:8080 with TLS
	err := StartCaddy("localhost", 8080, true)
	if err != nil {
		log.Fatal(err)
	}

	// Your application logic here...

	// Stop Caddy when done
	err = StopCaddy()
	if err != nil {
		log.Fatal(err)
	}
}
