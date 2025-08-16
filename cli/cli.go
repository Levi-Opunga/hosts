package cli

import (
	"fmt"
	"hosts-cli/caddystarter"
	"hosts-cli/core"
	"hosts-cli/data"
	"log"
	"os"
	"regexp"
	"strconv"
	_ "time"

	"github.com/spf13/cobra"
)

// Deps contains required host-ops that the CLI invokes.
type Deps struct {
	// Paths and filesystem
	HostsPath func() string
	BackupDir func() string

	// Hosts ops
	ReadHosts      func() ([]data.Entry, error)
	WriteHosts     func([]data.Entry) error
	ValidateEntry  func(data.Entry) error
	CalculateStats func([]data.Entry) data.Stats
	CreateBackup   func() error
	GetBackups     func() ([]data.BackupInfo, error)
	RestoreBackup  func(string) error
	HostExists     func(string) bool

	// Web start
	StartWebServer func(port int) error // Called by root command to run the web UI
}

// Runner encapsulates CLI execution.
type Runner struct {
	Deps Deps
}

// regex used for validation
var (
	ipv4Regex     = regexp.MustCompile(`^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$`)
	ipv6Regex     = regexp.MustCompile(`^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^::$`)
	hostnameRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?$`)
)

// Build a cobra command tree and execute it with provided args.
// Returns process exit code (0 = success).
func (r Runner) Execute(args []string) int {
	rootCmd := r.newRootCmd()

	// Attach subcommands
	rootCmd.AddCommand(
		r.newAddCmd(),
		r.newRemoveCmd(),
		r.newListCmd(),
		r.newDisableCmd(),
		r.newEnableCmd(),
		r.newBackupCmd(),
		r.newRestoreCmd(),
		r.newCaddyCmd(),
		r.newProxyCmd(),
		r.newInitCmd(),
		r.newVersionCmd(),
		r.newCheckCmd(),
	)

	// Supply args
	rootCmd.SetArgs(args)

	// Execute
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}
	return 0
}

// Root: starts web UI when no subcommand is specified.
func (r Runner) newRootCmd() *cobra.Command {
	var port int

	cmd := &cobra.Command{
		Use:   "hosts-cli",
		Short: "Hosts Editor Pro - Advanced /etc/hosts management",
		Long: fmt.Sprintf(`Hosts CLI  v%s - Advanced /etc/hosts management

Start without subcommands to launch the web UI at http://localhost:3000
Requires elevated permissions (sudo/Administrator) for saving changes.`, data.Version()),
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Start web UI
			if port < 1 || port > 65535 {
				return fmt.Errorf("invalid port: %d", port)
			}

			// Port selection
			var addr string
			if core.IsPortInUse(port) {
				fmt.Printf("Port %d is already in use. Selecting a random port...\n", port)
				port = core.GetRandomUnusedPort()
				addr = ":" + strconv.Itoa(port)
			} else {
				addr = ":" + strconv.Itoa(port)
			}

			r.printWebBanner(addr, port)

			if r.Deps.StartWebServer == nil {
				return fmt.Errorf("StartWebServer dependency is not provided")
			}
			if err := r.Deps.StartWebServer(port); err != nil {
				return fmt.Errorf("server error: %w", err)
			}
			return nil
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.Flags().IntVarP(&port, "port", "p", 3000, "Web server port")

	return cmd
}

// add subcommand
func (r Runner) newAddCmd() *cobra.Command {
	var ip, comment string

	cmd := &cobra.Command{
		Use:   "add <hostname>",
		Short: "Add hostname entry",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			hostname := args[0]
			return core.CliAddEntry(hostname, ip, comment)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.Flags().StringVar(&ip, "ip", "127.0.0.1", "IP address for the entry")
	cmd.Flags().StringVar(&comment, "comment", "", "Optional comment")
	return cmd
}

// remove subcommand
func (r Runner) newRemoveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remove <hostname>",
		Short: "Remove hostname entry",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return core.CliRemoveEntry(args[0])
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	return cmd
}

// list subcommand
func (r Runner) newListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all entries",
		RunE: func(_ *cobra.Command, _ []string) error {
			return core.CliListEntries()
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	return cmd
}

// disable subcommand
func (r Runner) newDisableCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "disable <hostname>",
		Short: "Disable hostname entry",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return core.CliToggleEntry(args[0], true)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	return cmd
}

// enable subcommand
func (r Runner) newEnableCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "enable <hostname>",
		Short: "Enable hostname entry",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return core.CliToggleEntry(args[0], false)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	return cmd
}

// backup subcommand
func (r Runner) newBackupCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "backup",
		Short: "Create a backup",
		RunE: func(_ *cobra.Command, _ []string) error {
			return core.CliCreateBackup()
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	return cmd
}

// restore subcommand
func (r Runner) newRestoreCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "restore <backup-file>",
		Short: "Restore from backup file",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return core.CliRestoreBackup(args[0])
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	return cmd
}

// caddy subcommand
func (r Runner) newCaddyCmd() *cobra.Command {
	var port int
	var domain string

	cmd := &cobra.Command{
		Use:   "caddy --proxy <domain> [--port <port>]",
		Short: "Create and run a Caddy reverse proxy for a local domain",
		RunE: func(_ *cobra.Command, _ []string) error {
			if domain == "" {
				return fmt.Errorf("--proxy is required")
			}
			core.EnsureProxyHostExists(&domain)
			if port == 0 {
				port = 3000
			}
			log.Printf("🚀 Caddy is running for %s -> 127.0.0.1:%d (TLS=%v)", domain, port, true)
			caddystarter.RunCaddyUntilSignal(domain, port, true)
			return nil
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.Flags().StringVar(&domain, "proxy", "", "Local domain to proxy to (e.g. example.local)")
	cmd.Flags().IntVar(&port, "port", 3000, "Local port to bind to proxy server")
	return cmd
}

// proxy subcommand (alias of caddy for convenience)
func (r Runner) newProxyCmd() *cobra.Command {
	var port int
	var domain string

	cmd := &cobra.Command{
		Use:   "proxy <domain> [--port <port>]",
		Short: "Run a Caddy reverse proxy to the given local domain",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			domain = args[0]
			if domain == "" {
				return fmt.Errorf("domain is required")
			}
			core.EnsureProxyHostExists(&domain)
			if port == 0 {
				port = 3000
			}
			log.Printf("🚀 Caddy is running for %s -> 127.0.0.1:%d (TLS=%v)", domain, port, true)
			caddystarter.RunCaddyUntilSignal(domain, port, true)
			return nil
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.Flags().IntVar(&port, "port", 3000, "Local port to bind to proxy server")
	return cmd
}

// init subcommand
func (r Runner) newInitCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize configuration and add necessary capabilities",
		RunE: func(_ *cobra.Command, _ []string) error {
			return core.CliInit()
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	return cmd
}

// version subcommand
func (r Runner) newVersionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Show version information",
		Run: func(_ *cobra.Command, _ []string) {
			fmt.Printf("Hosts CLI v%s\n", data.Version())
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	return cmd
}

// check subcommand
func (r Runner) newCheckCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "check",
		Short: "Check if you have the necessary privileges to run the program",
		Run: func(_ *cobra.Command, _ []string) {
			_ = core.CheckNetworkPrivileges()
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	return cmd
}

// ----- Implementation helpers (ported logic) -----
//
//func (r Runner) checkRootPrivileges() bool {
//	if runtime.GOOS == "windows" {
//		return true
//	}
//	currentUser, err := user.Current()
//	if err != nil {
//		return false
//	}
//	return currentUser.Uid == "0"
//}
//
//func executablePath() string {
//	path, err := os.Executable()
//	if err != nil {
//		return ""
//	}
//	return path
//}
//
//func (r Runner) yesNoPrompt(prompt string) bool {
//	var response string
//	fmt.Print(prompt)
//	_, err := fmt.Scanln(&response)
//	if err != nil {
//		fmt.Println("Error reading input:", err)
//		return false
//	}
//	response = strings.ToLower(strings.TrimSpace(response))
//	return response == "y" || response == "yes"
//}
//
//func (r Runner) cliAddEntry(hostname, ip, comment string) error {
//	if !r.checkRootPrivileges() {
//		fmt.Println("You need to escalate privileges to add a new entry.")
//		if r.yesNoPrompt("Do you want to escalate privileges now? (y/n) ") {
//			cmd := exec.Command("sudo", os.Args[0], "add", hostname, "--ip", ip, "--comment", comment)
//			if err := cmd.Run(); err != nil {
//				return err
//			}
//			return nil
//		}
//		return errors.New("operation cancelled")
//	}
//
//	entries, err := r.Deps.ReadHosts()
//	if err != nil {
//		return fmt.Errorf("failed to read hosts: %w", err)
//	}
//
//	// Validate IP
//	if !ipv4Regex.MatchString(ip) && !ipv6Regex.MatchString(ip) {
//		return fmt.Errorf("invalid IP address: %s", ip)
//	}
//
//	// Validate hostname
//	if !hostnameRegex.MatchString(hostname) && hostname != "localhost" {
//		return fmt.Errorf("invalid hostname: %s", hostname)
//	}
//
//	// Check if hostname already exists
//	for _, entry := range entries {
//		if !entry.IsComment {
//			for _, h := range entry.Hostnames {
//				if h == hostname {
//					return fmt.Errorf("hostname %s already exists with IP %s", hostname, entry.IP)
//				}
//			}
//		}
//	}
//
//	// Find next ID
//	maxID := 0
//	for _, e := range entries {
//		if e.ID > maxID {
//			maxID = e.ID
//		}
//	}
//
//	entries = append(entries, data.Entry{
//		ID:        maxID + 1,
//		IP:        ip,
//		Hostnames: []string{hostname},
//		Comment:   comment,
//		Disabled:  false,
//		IsComment: false,
//		IsSystem:  false,
//	})
//
//	if err := r.Deps.WriteHosts(entries); err != nil {
//		return fmt.Errorf("failed to write hosts: %w", err)
//	}
//
//	fmt.Printf("✓ Added: %s -> %s", hostname, ip)
//	if comment != "" {
//		fmt.Printf(" (%s)", comment)
//	}
//	fmt.Println()
//	return nil
//}
//
//func (r Runner) cliRemoveEntry(hostname string) error {
//	entries, err := r.Deps.ReadHosts()
//	if err != nil {
//		return fmt.Errorf("failed to read hosts: %w", err)
//	}
//
//	found := false
//	for i := len(entries) - 1; i >= 0; i-- {
//		entry := entries[i]
//		if !entry.IsComment {
//			for j, h := range entry.Hostnames {
//				if h == hostname {
//					found = true
//					entry.Hostnames = append(entry.Hostnames[:j], entry.Hostnames[j+1:]...)
//					if len(entry.Hostnames) == 0 {
//						entries = append(entries[:i], entries[i+1:]...)
//					} else {
//						entries[i] = entry
//					}
//					break
//				}
//			}
//		}
//	}
//
//	if !found {
//		return fmt.Errorf("hostname %s not found", hostname)
//	}
//
//	if err := r.Deps.WriteHosts(entries); err != nil {
//		return fmt.Errorf("failed to write hosts: %w", err)
//	}
//
//	fmt.Printf("✓ Removed: %s\n", hostname)
//	return nil
//}
//
//func (r Runner) cliListEntries() error {
//	entries, err := r.Deps.ReadHosts()
//	if err != nil {
//		return fmt.Errorf("failed to read hosts: %w", err)
//	}
//
//	stats := r.Deps.CalculateStats(entries)
//
//	fmt.Printf("Hosts File: %s\n", r.Deps.HostsPath())
//	fmt.Printf("Total Entries: %d | Active: %d | Disabled: %d | Comments: %d\n\n",
//		stats.TotalEntries, stats.ActiveEntries, stats.DisabledEntries, stats.CommentLines)
//
//	activeFound := false
//	disabledFound := false
//
//	for _, entry := range entries {
//		if !entry.IsComment && !entry.Disabled {
//			if !activeFound {
//				fmt.Println("🟢 ACTIVE ENTRIES:")
//				activeFound = true
//			}
//			status := "  "
//			if entry.IsSystem {
//				status = "🛡️"
//			}
//			fmt.Printf("%s %-15s -> %s", status, entry.IP, strings.Join(entry.Hostnames, " "))
//			if entry.Comment != "" {
//				fmt.Printf(" # %s", entry.Comment)
//			}
//			fmt.Println()
//		}
//	}
//	if activeFound {
//		fmt.Println()
//	}
//	for _, entry := range entries {
//		if !entry.IsComment && entry.Disabled {
//			if !disabledFound {
//				fmt.Println("🔴 DISABLED ENTRIES:")
//				disabledFound = true
//			}
//			status := "  "
//			if entry.IsSystem {
//				status = "🛡️"
//			}
//			fmt.Printf("%s %-15s -> %s", status, entry.IP, strings.Join(entry.Hostnames, " "))
//			if entry.Comment != "" {
//				fmt.Printf(" # %s", entry.Comment)
//			}
//			fmt.Println()
//		}
//	}
//	return nil
//}
//
//func (r Runner) cliToggleEntry(hostname string, disable bool) error {
//	entries, err := r.Deps.ReadHosts()
//	if err != nil {
//		return fmt.Errorf("failed to read hosts: %w", err)
//	}
//
//	found := false
//	for i, entry := range entries {
//		if !entry.IsComment {
//			for _, h := range entry.Hostnames {
//				if h == hostname {
//					found = true
//					entries[i].Disabled = disable
//					break
//				}
//			}
//		}
//		if found {
//			break
//		}
//	}
//	if !found {
//		return fmt.Errorf("hostname %s not found", hostname)
//	}
//
//	if err := r.Deps.WriteHosts(entries); err != nil {
//		return fmt.Errorf("failed to write hosts: %w", err)
//	}
//
//	action := "Enabled"
//	if disable {
//		action = "Disabled"
//	}
//	fmt.Printf("✓ %s: %s\n", action, hostname)
//	return nil
//}
//
//func (r Runner) cliCreateBackup() error {
//	if err := r.Deps.CreateBackup(); err != nil {
//		return fmt.Errorf("failed to create backup: %w", err)
//	}
//	backups, err := r.Deps.GetBackups()
//	if err == nil && len(backups) > 0 {
//		fmt.Printf("✓ Backup created: %s\n", backups[0].Name)
//		fmt.Printf("  Location: %s\n", filepath.Join(r.Deps.BackupDir(), backups[0].Name))
//	} else {
//		fmt.Println("✓ Backup created successfully")
//	}
//	return nil
//}
//
//func (r Runner) cliRestoreBackup(filename string) error {
//	if err := r.Deps.RestoreBackup(filename); err != nil {
//		return fmt.Errorf("failed to restore backup: %w", err)
//	}
//	fmt.Printf("✓ Restored from backup: %s\n", filename)
//	return nil
//}
//
//func (r Runner) ensureProxyHostExists(proxy string) {
//	if proxy == "" {
//		fmt.Fprintf(os.Stderr, "Error: proxy flag is required\n")
//		os.Exit(1)
//	}
//
//	if !r.checkNetworkPrivileges() {
//		if err := r.addNetworkPrivileges(); err != nil {
//			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
//			os.Exit(1)
//		}
//	}
//	if !r.Deps.HostExists(proxy) {
//		fmt.Fprintf(os.Stderr, "Error: host %s does not exist\n", proxy)
//		if r.yesNoPrompt("Do you want to add the host now? (y/n) ") {
//			if err := r.cliAddEntry(proxy, "127.0.0.1", ""); err != nil {
//				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
//				os.Exit(1)
//			}
//		} else {
//			log.Println("Host does not exist. Exiting...")
//			os.Exit(1)
//		}
//	}
//}
//
//func (r Runner) checkNetworkPrivileges() bool {
//	cmd := exec.Command("getcap", executablePath())
//	output, err := cmd.Output()
//	if err != nil {
//		fmt.Println("Error checking privileges:", err)
//		return false
//	}
//	if !strings.Contains(string(output), "cap_net_bind_service") {
//		fmt.Println("You need to add the following capability to the binary: cap_net_bind_service")
//		fmt.Printf("To do this, run the following command:\n\nsudo setcap cap_net_bind_service=+ep $(which %s)\n\n", os.Args[0])
//		return false
//	}
//	return true
//}
//
//func (r Runner) addNetworkPrivileges() error {
//	r.yesNoPrompt("Do you want to add the necessary capability to the binary? (y/n) ")
//	formatted := fmt.Sprintf("sudo setcap cap_net_bind_service=+ep %s", executablePath())
//	fmt.Printf("Running command: %s\n", formatted)
//	cmd := exec.Command("sudo", "setcap", "cap_net_bind_service=+ep", executablePath())
//	if err := cmd.Run(); err != nil {
//		return fmt.Errorf("failed to add capability: %w", err)
//	}
//	r.restartProgram()
//	return nil
//}
//
//func (r Runner) restartProgram() {
//	_ = exec.Command("clear").Run()
//	fmt.Println("Restarting program...")
//	_, _ = os.StartProcess(executablePath(), os.Args, &os.ProcAttr{
//		Files: []*os.File{os.Stdin, os.Stdout, os.Stderr},
//		Env:   os.Environ(),
//	})
//	os.Exit(0)
//}
//
//func isPortInUse(port int) bool {
//	ln, err := net.Listen("tcp", ":"+strconv.Itoa(port))
//	if err != nil {
//		return true
//	}
//	_ = ln.Close()
//	return false
//}
//
//func getRandomUnusedPort() int {
//	for {
//		port := rand.Intn(10000) + 10000
//		if !isPortInUse(port) {
//			return port
//		}
//	}
//}
//
//func (r Runner) cliInit() error {
//	if !r.checkNetworkPrivileges() {
//		if err := r.addNetworkPrivileges(); err != nil {
//			return err
//		}
//	}
//	return config.InitConfig()
//}

func (r Runner) printWebBanner(addr string, port int) {
	fmt.Printf("🚀 Enhanced Hosts Editor Pro v%s\n", data.Version())
	fmt.Printf("📍 Web Interface: http://localhost%s\n", addr)
	fmt.Printf("📁 Hosts File: %s\n", r.Deps.HostsPath())
	fmt.Printf("💾 Backups: %s\n", r.Deps.BackupDir())
	fmt.Printf("⌨️  Use Ctrl+C to stop server\n\n")
	fmt.Printf("💡 CLI Usage: %s --help\n", os.Args[0])
	if core.CheckRootPrivileges() {
		fmt.Printf("\033[31m")
		fmt.Println("📢❗🚨 You are not running the web ui as root.\n📢❗🚨 You will not be able to save changes to the hosts file.")
		fmt.Printf("\033[0m")
	}
}
