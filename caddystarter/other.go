package caddystarter

//
//import (
//	"context"
//	"fmt"
//	"log"
//
//	"github.com/caddyserver/caddy/v2"
//	"github.com/caddyserver/caddy/v2/caddyconfig"
//	_ "github.com/caddyserver/caddy/v2/modules/standard"
//)
//
//func StartCaddy(host string, port int, useTLS bool) error {
//	// Build the Caddyfile dynamically
//	var caddyConfig string
//
//	if useTLS {
//		// For TLS, use a specific port to avoid trying to bind to 443
//		caddyConfig = fmt.Sprintf(`
//%s:8443 {
//    reverse_proxy 127.0.0.1:%d
//    tls internal
//}
//`, host, port)
//	} else {
//		// For HTTP, use port 8080 to avoid needing root privileges
//		caddyConfig = fmt.Sprintf(`
//%s:8080 {
//    reverse_proxy 127.0.0.1:%d
//}
//`, host, port)
//	}
//
//	// Load config into Caddy using the registered caddyfile adapter
//	adapter := caddyconfig.GetAdapter("caddyfile")
//	if adapter == nil {
//		return fmt.Errorf("caddyfile adapter not available")
//	}
//
//	configJSON, warnings, err := adapter.Adapt([]byte(caddyConfig), nil)
//	if err != nil {
//		return fmt.Errorf("failed to adapt caddyfile: %w", err)
//	}
//	if warnings != nil {
//		for _, w := range warnings {
//			log.Printf("Caddy warning: %s", w.String())
//		}
//	}
//
//	// Start Caddy with this config
//	err = caddy.Load(configJSON, true)
//	if err != nil {
//		return fmt.Errorf("failed to start caddy: %w", err)
//	}
//
//	if useTLS {
//		log.Printf("✅ Caddy started for %s:8443 -> 127.0.0.1:%d (HTTPS)", host, port)
//	} else {
//		log.Printf("✅ Caddy started for %s:8080 -> 127.0.0.1:%d (HTTP)", host, port)
//	}
//	return nil
//}
//
//// StopCaddy gracefully stops the Caddy server
//func StopCaddy() error {
//	ctx := context.Background()
//	err := caddy.Stop()
//	if err != nil {
//		return fmt.Errorf("failed to stop caddy: %w", err)
//	}
//	log.Println("✅ Caddy stopped gracefully")
//	return nil
//}
//
//// StartCaddyWithCustomPort allows you to specify the listening port
//func StartCaddyWithCustomPort(host string, listenPort, backendPort int, useTLS bool) error {
//	// Build the Caddyfile dynamically
//	var caddyConfig string
//
//	if useTLS {
//		caddyConfig = fmt.Sprintf(`
//%s:%d {
//    reverse_proxy 127.0.0.1:%d
//    tls internal
//}
//`, host, listenPort, backendPort)
//	} else {
//		caddyConfig = fmt.Sprintf(`
//%s:%d {
//    reverse_proxy 127.0.0.1:%d
//}
//`, host, listenPort, backendPort)
//	}
//
//	// Load config into Caddy using the registered caddyfile adapter
//	adapter := caddyconfig.GetAdapter("caddyfile")
//	if adapter == nil {
//		return fmt.Errorf("caddyfile adapter not available")
//	}
//
//	configJSON, warnings, err := adapter.Adapt([]byte(caddyConfig), nil)
//	if err != nil {
//		return fmt.Errorf("failed to adapt caddyfile: %w", err)
//	}
//	if warnings != nil {
//		for _, w := range warnings {
//			log.Printf("Caddy warning: %s", w.String())
//		}
//	}
//
//	// Start Caddy with this config
//	err = caddy.Load(configJSON, true)
//	if err != nil {
//		return fmt.Errorf("failed to start caddy: %w", err)
//	}
//
//	protocol := "HTTP"
//	if useTLS {
//		protocol = "HTTPS"
//	}
//	log.Printf("✅ Caddy started for %s:%d -> 127.0.0.1:%d (%s)", host, listenPort, backendPort, protocol)
//	return nil
//}
