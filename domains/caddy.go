package domains

import (
	"context"
	"encoding/json"
	"fmt"
	"hosts-cli/config"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/spf13/cobra"
)

// Directory structure constants

var (
	ConfigDir  = config.GetConfigDir() + "/domain-configs"
	DomainsDir = ConfigDir + "/domains"
	MainConfig = ConfigDir + "/caddy.json"
	IncludeDir = ConfigDir + "/includes"
)

// CaddyConfig represents the main Caddy configuration
type CaddyConfig struct {
	Apps map[string]interface{} `json:"apps"`
}

// DomainConfig represents a single domain configuration
type DomainConfig struct {
	Domain      string                 `json:"domain"`
	Type        string                 `json:"type"` // "proxy", "static", "docker"
	Upstream    string                 `json:"upstream,omitempty"`
	StaticPath  string                 `json:"static_path,omitempty"`
	DockerName  string                 `json:"docker_name,omitempty"`
	DockerPort  int                    `json:"docker_port,omitempty"`
	EnableHTTPS bool                   `json:"enable_https"`
	Headers     map[string]interface{} `json:"headers,omitempty"`
	Middlewares []string               `json:"middlewares,omitempty"`
}

// DockerInfo represents Docker container information
type DockerInfo struct {
	Name      string
	ID        string
	IPAddress string
	Ports     []string
	Networks  []string
}

var (
	configDir   string
	domain      string
	upstream    string
	staticPath  string
	dockerName  string
	dockerPort  int
	port        string
	httpsPort   string
	enableHTTPS bool
	headers     []string
	middlewares []string
)

func Manager() *cobra.Command {
	var rootCmd = &cobra.Command{
		Use:   "domains",
		Short: "A CLI tool to manage Caddy domains with auto SSL and Docker integration",
		Long: `Caddy Manager is a CLI tool that helps you easily manage domains,
configure auto SSL, and integrate with Docker containers using a structured
directory approach for better organization.`,
	}

	// Add domain command
	var addCmd = &cobra.Command{
		Use:   "add",
		Short: "Add a new domain configuration",
		Long:  `Add a new domain with proxy, static files, or Docker container backend`,
		Run:   addDomain,
	}

	// Remove domain command
	var removeCmd = &cobra.Command{
		Use:   "remove",
		Short: "Remove a domain configuration",
		Long:  `Remove an existing domain configuration`,
		Run:   removeDomain,
	}

	// List domains command
	var listCmd = &cobra.Command{
		Use:   "list",
		Short: "List all configured domains",
		Long:  `List all currently configured domains`,
		Run:   listDomains,
	}

	// Docker commands
	var dockerCmd = &cobra.Command{
		Use:   "docker",
		Short: "Docker container management",
		Long:  `Commands for managing Docker container integration`,
	}

	var dockerListCmd = &cobra.Command{
		Use:   "list",
		Short: "List available Docker containers",
		Long:  `List running Docker containers that can be used as backends`,
		Run:   listDockerContainers,
	}

	var dockerExposeCmd = &cobra.Command{
		Use:   "expose",
		Short: "Expose a Docker container via domain",
		Long:  `Expose a Docker container directly through Caddy without host port mapping`,
		Run:   exposeDockerContainer,
	}

	// Generate/rebuild commands
	var generateCmd = &cobra.Command{
		Use:   "generate",
		Short: "Generate main Caddy configuration",
		Long:  `Generate the main Caddy configuration that includes all domain configs`,
		Run:   generateMainConfig,
	}

	var initCmd = &cobra.Command{
		Use:   "init",
		Short: "Initialize directory structure",
		Long:  `Initialize the directory structure for organized config management`,
		Run:   initDirectoryStructure,
	}

	// Add flags for add command
	addCmd.Flags().StringVarP(&domain, "domain", "d", "", "Domain name (required)")
	addCmd.Flags().StringVarP(&upstream, "upstream", "u", "", "Upstream server (e.g., localhost:3000)")
	addCmd.Flags().StringVarP(&staticPath, "static", "s", "", "Static files path")
	addCmd.Flags().BoolVar(&enableHTTPS, "https", true, "Enable HTTPS with auto SSL")
	addCmd.Flags().StringSliceVar(&headers, "header", []string{}, "Custom headers (format: 'name:value')")
	addCmd.Flags().StringSliceVar(&middlewares, "middleware", []string{}, "Enable middlewares (cors, compress, etc.)")
	addCmd.MarkFlagRequired("domain")

	// Docker expose flags
	dockerExposeCmd.Flags().StringVarP(&domain, "domain", "d", "", "Domain name (required)")
	dockerExposeCmd.Flags().StringVarP(&dockerName, "container", "c", "", "Docker container name (required)")
	dockerExposeCmd.Flags().IntVarP(&dockerPort, "port", "p", 80, "Container port to expose")
	dockerExposeCmd.Flags().BoolVar(&enableHTTPS, "https", true, "Enable HTTPS with auto SSL")
	dockerExposeCmd.Flags().StringSliceVar(&headers, "header", []string{}, "Custom headers (format: 'name:value')")
	dockerExposeCmd.MarkFlagRequired("domain")
	dockerExposeCmd.MarkFlagRequired("container")

	// Remove flags
	removeCmd.Flags().StringVarP(&domain, "domain", "d", "", "Domain name to remove (required)")
	removeCmd.MarkFlagRequired("domain")

	// Global flags
	rootCmd.PersistentFlags().StringVarP(&configDir, "config-dir", "c", ConfigDir, "Configuration directory path")
	rootCmd.PersistentFlags().StringVarP(&port, "port", "p", "80", "HTTP port")
	rootCmd.PersistentFlags().StringVar(&httpsPort, "https-port", "443", "HTTPS port")

	// Add subcommands
	dockerCmd.AddCommand(dockerListCmd, dockerExposeCmd)
	rootCmd.AddCommand(addCmd, removeCmd, listCmd, dockerCmd, generateCmd, initCmd)

	//if err := rootCmd.Execute(); err != nil {
	//	fmt.Println(err)
	//	os.Exit(1)
	//}
	return rootCmd
}

func initDirectoryStructure(cmd *cobra.Command, args []string) {
	dirs := []string{
		configDir,
		filepath.Join(configDir, "domains"),
		filepath.Join(configDir, "includes"),
		filepath.Join(configDir, "logs"),
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			log.Fatalf("Failed to create directory %s: %v", dir, err)
		}
	}

	// Create a sample .gitignore
	gitignoreContent := `logs/
*.log
caddy.json
`
	gitignorePath := filepath.Join(configDir, ".gitignore")
	if err := os.WriteFile(gitignorePath, []byte(gitignoreContent), 0644); err != nil {
		log.Fatalf("Failed to create .gitignore file: %v", err)
	}

	// Create README
	readmeContent := `# Caddy Configuration Directory

## Structure
- domains/     - Individual domain configuration files
- includes/    - Shared configuration snippets  
- logs/        - Caddy log files
- caddy.json   - Main generated configuration (auto-generated)

## Usage
Use hosts-cli domains commands to manage configurations.
The main caddy.json file is automatically generated from domain configs.

## Starting Caddy
caddy run --config caddy.json
`
	readmePath := filepath.Join(configDir, "README.md")
	os.WriteFile(readmePath, []byte(readmeContent), 0644)

	fmt.Printf("✅ Initialized directory structure at: %s\n", configDir)
	fmt.Printf("📁 Created directories:\n")
	for _, dir := range dirs {
		fmt.Printf("   - %s\n", dir)
	}
	fmt.Printf("\n🚀 You can now start adding domains!\n")
	fmt.Printf("   hosts-cli domains add -d example.com -u localhost:3000\n")
}

func addDomain(cmd *cobra.Command, args []string) {
	ensureDirectoryStructure()

	// Parse headers
	headerMap := make(map[string]interface{})
	for _, header := range headers {
		parts := strings.SplitN(header, ":", 2)
		if len(parts) == 2 {
			headerMap[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}

	// Determine configuration type
	configType := "static"
	upstreamAddr := upstream

	if upstream != "" {
		configType = "proxy"
	} else if staticPath == "" {
		staticPath = "/var/www/" + domain
	}

	domainConfig := DomainConfig{
		Domain:      domain,
		Type:        configType,
		Upstream:    upstreamAddr,
		StaticPath:  staticPath,
		EnableHTTPS: enableHTTPS,
		Headers:     headerMap,
		Middlewares: middlewares,
	}

	// Save domain config
	saveDomainConfig(domain, &domainConfig)

	// Regenerate main config
	generateMainConfig(nil, nil)

	fmt.Printf("✅ Domain '%s' added successfully!\n", domain)
	fmt.Printf("📁 Config saved to: %s\n", getDomainConfigPath(domain))

	if enableHTTPS {
		fmt.Printf("🔒 HTTPS with auto SSL enabled\n")
	}

	switch configType {
	case "proxy":
		fmt.Printf("🔄 Proxying to: %s\n", upstream)
	case "static":
		fmt.Printf("📁 Serving static files from: %s\n", staticPath)
	}

	if len(headerMap) > 0 {
		fmt.Printf("📋 Custom headers configured: %d\n", len(headerMap))
	}

	fmt.Printf("\n🔄 To reload Caddy:\n")
	fmt.Printf("   caddy reload --config %s\n", getMainConfigPath())
}

func exposeDockerContainer(cmd *cobra.Command, args []string) {
	ensureDirectoryStructure()

	// Get Docker container info
	dockerInfo, err := getDockerContainerInfo(dockerName)
	if err != nil {
		log.Fatalf("Failed to get Docker container info: %v", err)
	}

	if dockerInfo.IPAddress == "" {
		log.Fatalf("Container '%s' does not have an IP address. Make sure it's running.", dockerName)
	}

	// Parse headers
	headerMap := make(map[string]interface{})
	for _, header := range headers {
		parts := strings.SplitN(header, ":", 2)
		if len(parts) == 2 {
			headerMap[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}

	upstreamAddr := fmt.Sprintf("%s:%d", dockerInfo.IPAddress, dockerPort)

	domainConfig := DomainConfig{
		Domain:      domain,
		Type:        "docker",
		Upstream:    upstreamAddr,
		DockerName:  dockerName,
		DockerPort:  dockerPort,
		EnableHTTPS: enableHTTPS,
		Headers:     headerMap,
		Middlewares: middlewares,
	}

	// Save domain config
	saveDomainConfig(domain, &domainConfig)

	// Regenerate main config
	generateMainConfig(nil, nil)

	fmt.Printf("✅ Docker container '%s' exposed via domain '%s'!\n", dockerName, domain)
	fmt.Printf("📁 Config saved to: %s\n", getDomainConfigPath(domain))
	fmt.Printf("🐳 Container IP: %s\n", dockerInfo.IPAddress)
	fmt.Printf("🔄 Proxying to: %s\n", upstreamAddr)

	if enableHTTPS {
		fmt.Printf("🔒 HTTPS with auto SSL enabled\n")
	}

	fmt.Printf("\n🔄 To reload Caddy:\n")
	fmt.Printf("   caddy reload --config %s\n", getMainConfigPath())
}

func removeDomain(cmd *cobra.Command, args []string) {
	configPath := getDomainConfigPath(domain)

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		fmt.Printf("❌ Domain '%s' configuration not found\n", domain)
		return
	}

	if err := os.Remove(configPath); err != nil {
		log.Fatalf("Failed to remove domain config: %v", err)
	}

	// Regenerate main config
	generateMainConfig(nil, nil)

	fmt.Printf("✅ Domain '%s' removed successfully!\n", domain)
	fmt.Printf("🗑️  Deleted: %s\n", configPath)
	fmt.Printf("\n🔄 To reload Caddy:\n")
	fmt.Printf("   caddy reload --config %s\n", getMainConfigPath())
}

func listDomains(cmd *cobra.Command, args []string) {
	ensureDirectoryStructure()

	domainsDir := filepath.Join(configDir, "domains")
	files, err := os.ReadDir(domainsDir)
	if err != nil {
		fmt.Printf("❌ Failed to read domains directory: %v\n", err)
		return
	}

	fmt.Printf("📋 Configured Domains:\n")
	fmt.Printf("=====================\n")

	domainCount := 0
	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".json") {
			continue
		}

		configPath := filepath.Join(domainsDir, file.Name())
		config, err := loadDomainConfig(configPath)
		if err != nil {
			fmt.Printf("❌ Failed to load %s: %v\n", file.Name(), err)
			continue
		}

		domainCount++

		var typeInfo string
		switch config.Type {
		case "proxy":
			typeInfo = fmt.Sprintf("proxy → %s", config.Upstream)
		case "static":
			typeInfo = fmt.Sprintf("static → %s", config.StaticPath)
		case "docker":
			typeInfo = fmt.Sprintf("docker → %s (%s:%d)", config.Upstream, config.DockerName, config.DockerPort)
		}

		httpsStatus := "HTTP"
		if config.EnableHTTPS {
			httpsStatus = "HTTPS"
		}

		fmt.Printf("🌐 %s (%s) [%s]\n", config.Domain, typeInfo, httpsStatus)

		if len(config.Headers) > 0 {
			fmt.Printf("   📋 Headers: %d custom\n", len(config.Headers))
		}

		if len(config.Middlewares) > 0 {
			fmt.Printf("   🔧 Middlewares: %s\n", strings.Join(config.Middlewares, ", "))
		}
	}

	if domainCount == 0 {
		fmt.Printf("No domains configured yet.\n")
		fmt.Printf("\nUse 'hosts-cli domains add -d example.com -u localhost:3000' to add your first domain.\n")
	} else {
		fmt.Printf("\nTotal: %d domain(s)\n", domainCount)
		fmt.Printf("📁 Config directory: %s\n", configDir)
		fmt.Printf("🔧 Main config: %s\n", getMainConfigPath())
	}
}

// Common Docker socket locations to try (Docker Desktop specific)
var dockerSocketPaths = []string{
	"/var/run/docker.sock",               // Standard location
	"/mnt/wsl/shared-docker/docker.sock", // WSL2 with Docker Desktop
	"/run/docker.sock",                   // Alternative location
	"/var/run/dockerd.sock",              // Some configurations
	"/tmp/docker.sock",                   // Sometimes used by Docker Desktop
	//"/home/levi/.docker/desktop/docker.sock",
}

func listDockerContainers(cmd *cobra.Command, args []string) {
	// First, try to detect and fix Docker connection
	if !checkDockerConnection() {
		log.Printf("❌ Cannot connect to Docker daemon")
		suggestDockerFixes()
		return
	}

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		log.Printf("❌ Failed to create Docker client: %v", err)
		return
	}
	defer cli.Close()

	containers, err := cli.ContainerList(context.Background(), container.ListOptions{})
	if err != nil {
		log.Printf("❌ Failed to list containers: %v", err)
		return
	}

	fmt.Printf("🐳 Running Docker Containers:\n")
	fmt.Printf("==============================\n")

	if len(containers) == 0 {
		fmt.Printf("No running containers found.\n")
		return
	}

	for _, container := range containers {
		displayContainerInfo(cli, container)
	}
}

func checkDockerConnection() bool {
	// Try different socket locations
	for _, socketPath := range dockerSocketPaths {
		if _, err := os.Stat(socketPath); err == nil {
			log.Printf("✅ Found Docker socket at: %s", socketPath)
			os.Setenv("DOCKER_HOST", "unix://"+socketPath)

			// Test the connection
			if testDockerConnection() {
				return true
			}
		}
	}

	sock, err := getDockerContextHost()
	if err != nil {
		log.Fatalf("Could not get host : %s", err.Error())
	}
	log.Printf("The socket is running on : " + sock)
	if sock != "" {
		os.Setenv("DOCKER_HOST", sock)
		return true
	}

	// Try default connection without specifying socket
	log.Printf("🔍 Trying default Docker connection...")
	return testDockerConnection()
}

// Alternative function that returns the result instead of printing
func getDockerContextHost() (string, error) {
	cmd := exec.Command("docker", "context", "inspect", "--format", "{{.Endpoints.docker.Host}}")

	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get docker context host: %w", err)
	}

	return strings.TrimSpace(string(output)), nil
}

func testDockerConnection() bool {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		log.Printf("⚠️  Client creation failed: %v", err)
		return false
	}
	defer cli.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	_, err = cli.Ping(ctx)
	if err != nil {
		log.Printf("⚠️  Docker ping failed: %v", err)
		return false
	}

	log.Printf("✅ Docker daemon is responding")
	return true
}

func suggestDockerFixes() {
	fmt.Printf("\n🔧 Troubleshooting Steps:\n")
	fmt.Printf("========================\n")

	// Check what OS we're likely on
	if _, err := os.Stat("/etc/os-release"); err == nil {
		fmt.Printf("1. Check if Docker service is running:\n")
		fmt.Printf("   sudo systemctl status docker\n\n")

		fmt.Printf("2. If not running, start Docker:\n")
		fmt.Printf("   sudo systemctl start docker\n")
		fmt.Printf("   sudo systemctl enable docker\n\n")

		fmt.Printf("3. Add yourself to docker group:\n")
		fmt.Printf("   sudo usermod -aG docker $USER\n")
		fmt.Printf("   # Then log out and back in\n\n")
	}

	// Check for WSL
	if os.Getenv("WSL_DISTRO_NAME") != "" {
		fmt.Printf("🐧 WSL Detected - Additional steps:\n")
		fmt.Printf("1. Make sure Docker Desktop is running on Windows\n")
		fmt.Printf("2. Enable WSL integration in Docker Desktop settings\n")
		fmt.Printf("3. Try: docker context use default\n\n")
	}

	fmt.Printf("4. Test Docker manually:\n")
	fmt.Printf("   docker version\n")
	fmt.Printf("   docker ps\n\n")

	// Show what sockets we checked
	fmt.Printf("🔍 Checked these socket locations:\n")
	for _, path := range dockerSocketPaths {
		if _, err := os.Stat(path); err == nil {
			fmt.Printf("   ✅ %s (exists)\n", path)
		} else {
			fmt.Printf("   ❌ %s (not found)\n", path)
		}
	}
}

func displayContainerInfo(cli *client.Client, container container.Summary) {
	name := strings.TrimPrefix(container.Names[0], "/")

	// Get container details for IP
	inspect, err := cli.ContainerInspect(context.Background(), container.ID)
	if err != nil {
		log.Printf("⚠️  Failed to inspect container %s: %v", name, err)
		return
	}

	var ipAddress string
	if len(inspect.NetworkSettings.Networks) > 0 {
		for _, network := range inspect.NetworkSettings.Networks {
			if network.IPAddress != "" {
				ipAddress = network.IPAddress
				break
			}
		}
	}
	if ipAddress == "" {
		ipAddress = "N/A"
	}

	var ports []string
	for _, port := range container.Ports {
		if port.PrivatePort != 0 {
			if port.PublicPort != 0 {
				ports = append(ports, fmt.Sprintf("%d:%d", port.PublicPort, port.PrivatePort))
			} else {
				ports = append(ports, fmt.Sprintf("%d", port.PrivatePort))
			}
		}
	}

	fmt.Printf("📦 %s (ID: %s)\n", name, container.ID[:12])
	fmt.Printf("   🌐 IP: %s\n", ipAddress)
	fmt.Printf("   🔌 Ports: %s\n", strings.Join(ports, ", "))
	fmt.Printf("   🏃 Status: %s\n", container.Status)
	fmt.Printf("   🖼️  Image: %s\n", container.Image)

	if len(ports) > 0 {
		firstPort := strings.Split(ports[0], ":")[0]
		if strings.Contains(ports[0], ":") {
			firstPort = strings.Split(ports[0], ":")[1]
		}
		fmt.Printf("   💡 Expose example: hosts-cli domains docker expose -d %s.local -c %s -p %s\n",
			name, name, firstPort)
	}
	fmt.Println()
}

// Utility function to diagnose Docker setup
func diagnoseDocker(cmd *cobra.Command, args []string) {
	fmt.Printf("🔍 Docker Diagnosis\n")
	fmt.Printf("==================\n\n")

	// Check environment variables
	fmt.Printf("Environment Variables:\n")
	fmt.Printf("DOCKER_HOST: %s\n", os.Getenv("DOCKER_HOST"))
	fmt.Printf("DOCKER_API_VERSION: %s\n", os.Getenv("DOCKER_API_VERSION"))
	fmt.Printf("DOCKER_CONFIG: %s\n", os.Getenv("DOCKER_CONFIG"))
	fmt.Printf("WSL_DISTRO_NAME: %s\n", os.Getenv("WSL_DISTRO_NAME"))
	fmt.Printf("\n")

	// Check socket files
	fmt.Printf("Socket Files:\n")
	for _, path := range dockerSocketPaths {
		if info, err := os.Stat(path); err == nil {
			fmt.Printf("✅ %s (mode: %v)\n", path, info.Mode())
		} else {
			fmt.Printf("❌ %s (not found)\n", path)
		}
	}
	fmt.Printf("\n")

	// Try to connect
	fmt.Printf("Connection Test:\n")
	checkDockerConnection()
}

func generateMainConfig(cmd *cobra.Command, args []string) {
	ensureDirectoryStructure()

	// Load all domain configs
	domainsDir := filepath.Join(configDir, "domains")
	files, err := os.ReadDir(domainsDir)
	if err != nil {
		log.Fatalf("Failed to read domains directory: %v", err)
	}

	// Create main configuration
	mainConfig := &CaddyConfig{
		Apps: map[string]interface{}{
			"http": map[string]interface{}{
				"servers": map[string]interface{}{
					"main": map[string]interface{}{
						"listen": []string{
							fmt.Sprintf(":%s", port),
							fmt.Sprintf(":%s", httpsPort),
						},
						"routes": []interface{}{},
						"logs": map[string]interface{}{
							"default_logger_name": "main",
						},
					},
				},
			},
		},
	}

	// Process each domain config
	httpApp := mainConfig.Apps["http"].(map[string]interface{})
	server := httpApp["servers"].(map[string]interface{})["main"].(map[string]interface{})
	routes := server["routes"].([]interface{})

	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".json") {
			continue
		}

		configPath := filepath.Join(domainsDir, file.Name())
		domainConfig, err := loadDomainConfig(configPath)
		if err != nil {
			fmt.Printf("❌ Failed to load %s: %v\n", file.Name(), err)
			continue
		}

		route := generateRouteFromDomainConfig(domainConfig)
		routes = append(routes, route)
	}

	server["routes"] = routes

	// Save main config
	mainConfigPath := getMainConfigPath()
	data, err := json.MarshalIndent(mainConfig, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal main config: %v", err)
	}

	if err := ioutil.WriteFile(mainConfigPath, data, 0644); err != nil {
		log.Fatalf("Failed to write main config: %v", err)
	}

	fmt.Printf("✅ Main configuration generated: %s\n", mainConfigPath)
	fmt.Printf("📊 Loaded %d domain configurations\n", len(routes))
	fmt.Printf("\n🚀 Start Caddy with:\n")
	fmt.Printf("   caddy run --config %s\n", mainConfigPath)
}

// Helper functions
func ensureDirectoryStructure() {
	dirs := []string{
		configDir,
		filepath.Join(configDir, "domains"),
		filepath.Join(configDir, "includes"),
		filepath.Join(configDir, "logs"),
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			log.Fatalf("Failed to create directory %s: %v", dir, err)
		}
	}
}

func getDomainConfigPath(domain string) string {
	filename := strings.ReplaceAll(domain, ".", "_") + ".json"
	return filepath.Join(configDir, "domains", filename)
}

func getMainConfigPath() string {
	return filepath.Join(configDir, "caddy.json")
}

func saveDomainConfig(domain string, config *DomainConfig) {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal domain config: %v", err)
	}

	configPath := getDomainConfigPath(domain)
	if err := ioutil.WriteFile(configPath, data, 0644); err != nil {
		log.Fatalf("Failed to write domain config: %v", err)
	}
}

func loadDomainConfig(configPath string) (*DomainConfig, error) {
	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	var config DomainConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

func generateRouteFromDomainConfig(config *DomainConfig) map[string]interface{} {
	// Create handlers
	var handlers []interface{}

	// Add middleware handlers first
	for _, middleware := range config.Middlewares {
		switch middleware {
		case "compress":
			handlers = append(handlers, map[string]interface{}{
				"handler": "encode",
				"encodings": map[string]interface{}{
					"gzip": map[string]interface{}{},
				},
			})
		case "cors":
			handlers = append(handlers, map[string]interface{}{
				"handler": "headers",
				"response": map[string]interface{}{
					"set": map[string]interface{}{
						"Access-Control-Allow-Origin":  "*",
						"Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
						"Access-Control-Allow-Headers": "Content-Type, Authorization",
					},
				},
			})
		}
	}

	// Add custom headers if specified
	if len(config.Headers) > 0 {
		handlers = append(handlers, map[string]interface{}{
			"handler": "headers",
			"response": map[string]interface{}{
				"set": config.Headers,
			},
		})
	}

	// Add main handler based on type
	switch config.Type {
	case "proxy", "docker":
		handlers = append(handlers, map[string]interface{}{
			"handler": "reverse_proxy",
			"upstreams": []map[string]interface{}{
				{"dial": config.Upstream},
			},
		})
	case "static":
		handlers = append(handlers, map[string]interface{}{
			"handler": "file_server",
			"root":    config.StaticPath,
		})
	}

	return map[string]interface{}{
		"match": []map[string]interface{}{
			{"host": []string{config.Domain}},
		},
		"handle":   handlers,
		"terminal": true,
	}
}

func getDockerContainerInfo(containerName string) (*DockerInfo, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, err
	}
	defer cli.Close()

	containers, err := cli.ContainerList(context.Background(), container.ListOptions{})
	if err != nil {
		return nil, err
	}

	for _, container := range containers {
		name := strings.TrimPrefix(container.Names[0], "/")
		if name == containerName {
			// Get detailed container info
			inspect, err := cli.ContainerInspect(context.Background(), container.ID)
			if err != nil {
				return nil, err
			}

			var ipAddress string
			var networks []string
			for networkName, network := range inspect.NetworkSettings.Networks {
				networks = append(networks, networkName)
				if network.IPAddress != "" {
					ipAddress = network.IPAddress
				}
			}

			var ports []string
			for _, port := range container.Ports {
				if port.PrivatePort != 0 {
					ports = append(ports, fmt.Sprintf("%d", port.PrivatePort))
				}
			}

			return &DockerInfo{
				Name:      name,
				ID:        container.ID,
				IPAddress: ipAddress,
				Ports:     ports,
				Networks:  networks,
			}, nil
		}
	}

	return nil, fmt.Errorf("container '%s' not found", containerName)
}
