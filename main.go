// Enhanced Hosts CLI – Modern web UI and CLI to manage /etc/hosts and https proxying with Caddy
// Features: Web UI, CLI operations, search, filtering, validation, backup management
//
// Build: go build -o hosts-cli
//
// Web UI Usage:
//   sudo ./hosts-ui                    (Linux/macOS)
//   ./hosts-ui.exe                     (Windows as Administrator)
//   Open: http://localhost:3000
//
// CLI Usage:
//   sudo ./hosts-ui --add example.local                    # Add example.local -> 127.0.0.1
//   sudo ./hosts-ui --add example.local --ip 192.168.1.10  # Add with custom IP
//   sudo ./hosts-ui --remove example.local                 # Remove entry
//   sudo ./hosts-ui --list                                 # List all entries
//   sudo ./hosts-ui --disable example.local               # Disable entry
//   sudo ./hosts-ui --enable example.local                # Enable entry
//   sudo ./hosts-ui --backup                              # Create backup
//   sudo ./hosts-ui --restore backup-file.bak             # Restore backup

package main

import (
	"bufio"
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hosts-cli/caddystarter"
	"hosts-cli/config"
	"html/template"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

//go:embed web/*
var webFS embed.FS

var version = "2.0"

// Entry represents one logical line in hosts
type Entry struct {
	ID        int      `json:"id"`
	IP        string   `json:"ip"`
	Hostnames []string `json:"hostnames"`
	Comment   string   `json:"comment"`
	Disabled  bool     `json:"disabled"`
	Raw       string   `json:"raw,omitempty"`
	IsComment bool     `json:"isComment"`
	IsSystem  bool     `json:"isSystem"` // Mark system entries
}

type State struct {
	Entries []Entry `json:"entries"`
	Stats   Stats   `json:"stats"`
}

type Stats struct {
	TotalEntries    int `json:"totalEntries"`
	ActiveEntries   int `json:"activeEntries"`
	DisabledEntries int `json:"disabledEntries"`
	CommentLines    int `json:"commentLines"`
}

type BackupInfo struct {
	Name     string    `json:"name"`
	Size     int64     `json:"size"`
	Modified time.Time `json:"modified"`
}

// CLI flags
var (
	addFlag             = flag.String("add", "", "Add hostname (defaults to 127.0.0.1)")
	removeFlag          = flag.String("remove", "", "Remove hostname")
	ipFlag              = flag.String("ip", "127.0.0.1", "IP address for --add operation")
	commentFlag         = flag.String("comment", "", "Comment for --add operation")
	listFlag            = flag.Bool("list", false, "List all entries")
	disableFlag         = flag.String("disable", "", "Disable hostname")
	enableFlag          = flag.String("enable", "", "Enable hostname")
	backupFlag          = flag.Bool("backup", false, "Create backup")
	restoreFlag         = flag.String("restore", "", "Restore from backup file")
	portFlag            = flag.String("port", "3000", "Web server port")
	caddyFlag           = flag.Bool("caddy", false, "Create a Caddyfile for use in local Caddy server")
	proxyFlag           = flag.String("proxy", "", "Local domain to proxy to (e.g. example.local)")
	helpFlag            = flag.Bool("help", false, "Show help")
	checkPrivilegesFlag = flag.Bool("check", false, "Check if you have the necessary privileges to run the program")
	versionFlag         = flag.Bool("version", false, "Show version information")
	initFlag            = flag.Bool("init", false, "Initialize the hosts file")
)

var ipv4Regex = regexp.MustCompile(`^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$`)
var ipv6Regex = regexp.MustCompile(`^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^::$`)
var hostnameRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?$`)

func hostsPath() string {
	if runtime.GOOS == "windows" {
		windir := os.Getenv("SystemRoot")
		if windir == "" {
			windir = `C:\Windows`
		}
		return filepath.Join(windir, "System32", "drivers", "etc", "hosts")
	}
	return "/etc/hosts"
}

func executablePath() string {
	path, err := os.Executable()
	if err != nil {
		return ""
	}
	return path
}

func backupDir() string {
	dir := filepath.Dir(hostsPath())
	if config.GetConfig().Backup.Dir != "" {
		return config.GetConfig().Backup.Dir
	}
	return filepath.Join(dir, "hosts_backups")
}

func isSystemEntry(ip string, hostnames []string) bool {
	systemEntries := map[string]bool{
		"127.0.0.1": true,
		"::1":       true,
		"0.0.0.0":   true,
	}

	if systemEntries[ip] {
		for _, host := range hostnames {
			if host == "localhost" || host == "localhost.localdomain" ||
				strings.HasSuffix(host, ".localhost") {
				return true
			}
		}
	}
	return false
}

func readHosts() ([]Entry, error) {
	path := hostsPath()
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var entries []Entry
	id := 1

	for scanner.Scan() {
		line := scanner.Text()
		trim := strings.TrimSpace(line)

		if trim == "" {
			entries = append(entries, Entry{
				ID: id, Raw: line, IsComment: true,
			})
			id++
			continue
		}

		if strings.HasPrefix(trim, "#") {
			// Check if it's a disabled entry
			withoutHash := strings.TrimSpace(trim[1:])
			fields := strings.Fields(withoutHash)

			if len(fields) >= 2 && (ipv4Regex.MatchString(fields[0]) || ipv6Regex.MatchString(fields[0])) {
				// This is a disabled host entry
				var cmt string
				line := withoutHash
				if idx := strings.Index(line, "#"); idx >= 0 {
					cmt = strings.TrimSpace(line[idx+1:])
					line = strings.TrimSpace(line[:idx])
				}

				fields = strings.Fields(line)
				ip := fields[0]
				hosts := []string{}
				if len(fields) > 1 {
					hosts = fields[1:]
				}

				entries = append(entries, Entry{
					ID: id, IP: ip, Hostnames: hosts, Comment: cmt,
					Disabled: true, IsSystem: isSystemEntry(ip, hosts),
				})
			} else {
				// Regular comment
				entries = append(entries, Entry{
					ID: id, Raw: line, IsComment: true,
				})
			}
			id++
			continue
		}

		// Parse active entry
		var cmt string
		if idx := strings.Index(line, "#"); idx >= 0 {
			cmt = strings.TrimSpace(line[idx+1:])
			line = strings.TrimSpace(line[:idx])
		}

		fields := strings.Fields(line)
		if len(fields) == 0 {
			entries = append(entries, Entry{ID: id, Raw: line, IsComment: true})
			id++
			continue
		}

		ip := fields[0]
		hosts := []string{}
		if len(fields) > 1 {
			hosts = fields[1:]
		}

		entries = append(entries, Entry{
			ID: id, IP: ip, Hostnames: hosts, Comment: cmt,
			IsSystem: isSystemEntry(ip, hosts),
		})
		id++
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

func writeHosts(entries []Entry) error {
	path := hostsPath()

	// Create backup
	if err := createBackup(); err != nil {
		return fmt.Errorf("backup failed: %w", err)
	}

	var buf bytes.Buffer
	for _, e := range entries {
		if e.IsComment && e.Raw != "" {
			buf.WriteString(e.Raw)
			buf.WriteByte('\n')
			continue
		}

		if strings.TrimSpace(e.IP) == "" && len(e.Hostnames) == 0 && e.Comment == "" {
			buf.WriteByte('\n')
			continue
		}

		line := strings.TrimSpace(e.IP)
		if len(e.Hostnames) > 0 {
			line += "\t" + strings.Join(cleanHosts(e.Hostnames), " ")
		}
		if e.Comment != "" {
			line += "\t# " + e.Comment
		}
		if e.Disabled {
			line = "# " + line
		}
		buf.WriteString(line)
		buf.WriteByte('\n')
	}

	// Write atomically
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, buf.Bytes(), 0644); err != nil {
		return fmt.Errorf("write temp failed: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("replace failed: %w", err)
	}
	return nil
}

func hostExists(host string) bool {
	entries, err := readHosts()
	if err != nil {
		return false
	}
	for _, e := range entries {
		for _, h := range e.Hostnames {
			if h == host {
				return true
			}
		}
	}
	return false
}

func createBackup() error {
	path := hostsPath()
	dir := backupDir()

	// Create backup directory if it doesn't exist
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	backup := filepath.Join(dir, fmt.Sprintf("hosts.bak.%s", time.Now().Format("20060102-150405")))
	return copyFile(path, backup)
}

func getBackups() ([]BackupInfo, error) {
	dir := backupDir()
	files, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return []BackupInfo{}, nil
		}
		return nil, err
	}

	var backups []BackupInfo
	for _, file := range files {
		if strings.HasPrefix(file.Name(), "hosts.bak.") {
			info, err := file.Info()
			if err != nil {
				continue
			}
			backups = append(backups, BackupInfo{
				Name:     file.Name(),
				Size:     info.Size(),
				Modified: info.ModTime(),
			})
		}
	}

	// Sort by modification time (newest first)
	sort.Slice(backups, func(i, j int) bool {
		return backups[i].Modified.After(backups[j].Modified)
	})

	return backups, nil
}

func restoreBackup(filename string) error {
	var backupPath string
	if filepath.IsAbs(filename) {
		backupPath = filename
	} else {
		backupPath = filepath.Join(backupDir(), filename)
	}
	return copyFile(backupPath, hostsPath())
}

func cleanHosts(hs []string) []string {
	out := make([]string, 0, len(hs))
	for _, h := range hs {
		h = strings.TrimSpace(h)
		if h != "" {
			out = append(out, h)
		}
	}
	return out
}

func copyFile(src, dst string) error {
	s, err := os.Open(src)
	if err != nil {
		return err
	}
	defer s.Close()
	d, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer d.Close()
	if _, err := io.Copy(d, s); err != nil {
		return err
	}
	return nil
}

func validateEntry(e Entry) error {
	if e.IsComment {
		return nil
	}

	ip := strings.TrimSpace(e.IP)
	if ip == "" {
		return errors.New("IP address is required")
	}

	if !ipv4Regex.MatchString(ip) && !ipv6Regex.MatchString(ip) {
		return errors.New("invalid IP address format")
	}

	for _, hostname := range e.Hostnames {
		if !hostnameRegex.MatchString(hostname) && hostname != "localhost" {
			return fmt.Errorf("invalid hostname: %s", hostname)
		}
	}

	return nil
}

func calculateStats(entries []Entry) Stats {
	stats := Stats{}
	for _, e := range entries {
		if e.IsComment {
			stats.CommentLines++
		} else {
			stats.TotalEntries++
			if e.Disabled {
				stats.DisabledEntries++
			} else {
				stats.ActiveEntries++
			}
		}
	}
	return stats
}

// CLI Functions
func showUsage() {
	fmt.Printf(`Hosts Editor Pro v2.0 - Advanced /etc/hosts management

USAGE:
    %s [flags]                           # Start web interface
    %s --add <hostname> [flags]          # Add hostname entry
    %s --remove <hostname>               # Remove hostname entry
    %s --list                            # List all entries
    %s --disable <hostname>              # Disable hostname entry
    %s --enable <hostname>               # Enable hostname entry
    %s --backup                          # Create backup
    %s --restore <backup-file>           # Restore from backup
    %s --caddy <hostname> [flags]        # Create Caddyfile for Caddy server
	%s --proxy <domain>  [flags]         # Local domain to proxy to (e.g. example.local)

FLAGS:
    --add <hostname>     Add hostname (defaults to 127.0.0.1)
    --ip <ip>           IP address for --add (default: 127.0.0.1)
    --comment <text>    Comment for --add
    --remove <hostname> Remove hostname
    --list              List all entries
    --disable <hostname> Disable hostname
    --enable <hostname>  Enable hostname
    --backup            Create backup
    --restore <file>    Restore from backup
    --port <port>       Web server port (default: 3000)
    --help              Show this help
    --caddy <hostname>  Create Caddyfile for Caddy server
	--proxy <domain>    Local domain to proxy to (e.g. example.local)
    --port <port>       Local port to bind to proxy server (default: 3000)

Caddyfile Usage:
    %s --caddy api.local                  # Create Caddyfile for reverse proxying to api.local (default port 3000)
    %s --caddy api.local --proxy  --port 5000  # Create Caddyfile for reverse proxying to api.local (port 5000) and run the caddy server
    %s --proxy api.local --port 3000       # 

EXAMPLES:
    %s                                   # Start web interface
    %s --add api.local                   # Add api.local -> 127.0.0.1
    %s --add db.local --ip 192.168.1.10  # Add db.local -> 192.168.1.10
    %s --add test.local --comment "Dev environment"
    %s --remove api.local                # Remove api.local
    %s --disable api.local               # Disable api.local
    %s --enable api.local                # Enable api.local
    %s --list                            # Show all entries
    %s --backup                          # Create backup
    %s --restore hosts.bak.20240101-120000  # Restore backup

WEB INTERFACE:
    Start without flags to launch web UI at http://localhost:3000
    Requires elevated permissions (sudo/Administrator) for saving changes.

`, os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0],
		os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0])
}

func checkRootPrivileges() bool {
	if runtime.GOOS == "windows" {
		return true
	}
	currentUser, err := user.Current()
	if err != nil {
		return false
	}
	if currentUser.Uid != "0" {
		return false
	}
	return true
}
func cliAddEntry(hostname, ip, comment string) error {
	if !checkRootPrivileges() {
		fmt.Println("You need to escalate privileges to add a new entry.")
		// prompt user to escalate privileges
		var escalatePrivileges = yesNoPrompt("Do you want to escalate privileges now? (y/n)")
		if escalatePrivileges {
			cmd := exec.Command("sudo", os.Args[0], "--add", hostname, "--ip", ip, "--comment", comment)
			err := cmd.Run()
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			return nil
		} else {
			fmt.Println("Exiting...")
			os.Exit(1)
		}

	}
	entries, err := readHosts()
	if err != nil {
		return fmt.Errorf("failed to read hosts: %w", err)
	}

	// Validate IP
	if !ipv4Regex.MatchString(ip) && !ipv6Regex.MatchString(ip) {
		return fmt.Errorf("invalid IP address: %s", ip)
	}

	// Validate hostname
	if !hostnameRegex.MatchString(hostname) && hostname != "localhost" {
		return fmt.Errorf("invalid hostname: %s", hostname)
	}

	// Check if hostname already exists
	for _, entry := range entries {
		if !entry.IsComment {
			for _, h := range entry.Hostnames {
				if h == hostname {
					return fmt.Errorf("hostname %s already exists with IP %s", hostname, entry.IP)
				}
			}
		}
	}

	// Find next ID
	maxID := 0
	for _, e := range entries {
		if e.ID > maxID {
			maxID = e.ID
		}
	}

	// Create new entry
	newEntry := Entry{
		ID:        maxID + 1,
		IP:        ip,
		Hostnames: []string{hostname},
		Comment:   comment,
		Disabled:  false,
		IsComment: false,
		IsSystem:  false,
	}

	entries = append(entries, newEntry)

	if err := writeHosts(entries); err != nil {
		return fmt.Errorf("failed to write hosts: %w", err)
	}

	fmt.Printf("✓ Added: %s -> %s", hostname, ip)
	if comment != "" {
		fmt.Printf(" (%s)", comment)
	}
	fmt.Println()
	return nil
}

func cliRemoveEntry(hostname string) error {
	entries, err := readHosts()
	if err != nil {
		return fmt.Errorf("failed to read hosts: %w", err)
	}

	found := false
	for i := len(entries) - 1; i >= 0; i-- {
		entry := entries[i]
		if !entry.IsComment {
			for j, h := range entry.Hostnames {
				if h == hostname {
					found = true
					// Remove hostname from the entry
					entry.Hostnames = append(entry.Hostnames[:j], entry.Hostnames[j+1:]...)

					// If no hostnames left, remove the entire entry
					if len(entry.Hostnames) == 0 {
						entries = append(entries[:i], entries[i+1:]...)
					} else {
						entries[i] = entry
					}
					break
				}
			}
		}
	}

	if !found {
		return fmt.Errorf("hostname %s not found", hostname)
	}

	if err := writeHosts(entries); err != nil {
		return fmt.Errorf("failed to write hosts: %w", err)
	}

	fmt.Printf("✓ Removed: %s\n", hostname)
	return nil
}

func cliListEntries() error {
	entries, err := readHosts()
	if err != nil {
		return fmt.Errorf("failed to read hosts: %w", err)
	}

	stats := calculateStats(entries)

	fmt.Printf("Hosts File: %s\n", hostsPath())
	fmt.Printf("Total Entries: %d | Active: %d | Disabled: %d | Comments: %d\n\n",
		stats.TotalEntries, stats.ActiveEntries, stats.DisabledEntries, stats.CommentLines)

	activeFound := false
	disabledFound := false

	// Show active entries
	for _, entry := range entries {
		if !entry.IsComment && !entry.Disabled {
			if !activeFound {
				fmt.Println("🟢 ACTIVE ENTRIES:")
				activeFound = true
			}
			status := "  "
			if entry.IsSystem {
				status = "🛡️"
			}
			fmt.Printf("%s %-15s -> %s", status, entry.IP, strings.Join(entry.Hostnames, " "))
			if entry.Comment != "" {
				fmt.Printf(" # %s", entry.Comment)
			}
			fmt.Println()
		}
	}

	if activeFound {
		fmt.Println()
	}

	// Show disabled entries
	for _, entry := range entries {
		if !entry.IsComment && entry.Disabled {
			if !disabledFound {
				fmt.Println("🔴 DISABLED ENTRIES:")
				disabledFound = true
			}
			status := "  "
			if entry.IsSystem {
				status = "🛡️"
			}
			fmt.Printf("%s %-15s -> %s", status, entry.IP, strings.Join(entry.Hostnames, " "))
			if entry.Comment != "" {
				fmt.Printf(" # %s", entry.Comment)
			}
			fmt.Println()
		}
	}

	return nil
}

func cliToggleEntry(hostname string, disable bool) error {
	entries, err := readHosts()
	if err != nil {
		return fmt.Errorf("failed to read hosts: %w", err)
	}

	found := false
	for i, entry := range entries {
		if !entry.IsComment {
			for _, h := range entry.Hostnames {
				if h == hostname {
					found = true
					entries[i].Disabled = disable
					break
				}
			}
		}
		if found {
			break
		}
	}

	if !found {
		return fmt.Errorf("hostname %s not found", hostname)
	}

	if err := writeHosts(entries); err != nil {
		return fmt.Errorf("failed to write hosts: %w", err)
	}

	action := "Enabled"
	if disable {
		action = "Disabled"
	}
	fmt.Printf("✓ %s: %s\n", action, hostname)
	return nil
}

func cliCreateBackup() error {
	if err := createBackup(); err != nil {
		return fmt.Errorf("failed to create backup: %w", err)
	}

	// Get the latest backup to show the filename
	backups, err := getBackups()
	if err == nil && len(backups) > 0 {
		fmt.Printf("✓ Backup created: %s\n", backups[0].Name)
		fmt.Printf("  Location: %s\n", filepath.Join(backupDir(), backups[0].Name))
	} else {
		fmt.Println("✓ Backup created successfully")
	}
	return nil
}

func cliRestoreBackup(filename string) error {
	if err := restoreBackup(filename); err != nil {
		return fmt.Errorf("failed to restore backup: %w", err)
	}

	fmt.Printf("✓ Restored from backup: %s\n", filename)
	return nil
}

func yesNoPrompt(prompt string) bool {
	var response string
	fmt.Print(prompt)

	_, err := fmt.Scanln(&response)
	if err != nil {
		fmt.Println("Error reading input:", err)
		return false
	}

	response = strings.ToLower(response)
	if response == "y" || response == "yes" {
		return true
	}
	return false
}

func startWebServer() {
	mux := http.NewServeMux()

	// Serve static files
	mux.Handle("/static/", http.FileServer(http.FS(webFS)))

	// UI
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		b, _ := webFS.ReadFile("web/index.html")
		t := template.Must(template.New("index").Parse(string(b)))
		_ = t.Execute(w, map[string]any{
			"Path":    hostsPath(),
			"OS":      runtime.GOOS,
			"Version": "2.0",
		})
	})

	// API: read hosts
	mux.HandleFunc("/api/hosts", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		entries, err := readHosts()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		stats := calculateStats(entries)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(State{Entries: entries, Stats: stats})
	})

	// API: save hosts
	mux.HandleFunc("/api/save", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var st State
		if err := json.NewDecoder(r.Body).Decode(&st); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		for i, e := range st.Entries {
			if err := validateEntry(e); err != nil {
				http.Error(w, fmt.Sprintf("entry %d: %v", i+1, err), http.StatusBadRequest)
				return
			}
		}
		if err := writeHosts(st.Entries); err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})

	// API: get backups
	mux.HandleFunc("/api/backups", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		backups, err := getBackups()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(backups)
	})

	// API: restore backup
	mux.HandleFunc("/api/restore", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		filename := r.URL.Query().Get("file")
		if filename == "" {
			http.Error(w, "filename required", http.StatusBadRequest)
			return
		}
		if err := restoreBackup(filename); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})

	// API: validate entry
	mux.HandleFunc("/api/validate", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var e Entry
		if err := json.NewDecoder(r.Body).Decode(&e); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		if err := validateEntry(e); err != nil {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"valid": false, "error": err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"valid": true})
	})

	port, err := strconv.Atoi(*portFlag)
	if err != nil || port < 1 || port > 65535 {
		fmt.Fprintf(os.Stderr, "Error: invalid port: %v\n", err)

	}
	var addr string
	if isPortIsInUse(port) {
		fmt.Printf("Port %d is already in use.Selecting a random port...\n", port)
		port = getRandomUnusedPort()
		addr = ":" + strconv.Itoa(port)
	} else {
		addr = ":" + *portFlag
	}
	fmt.Printf("🚀 Enhanced Hosts Editor Pro v2.0\n")
	fmt.Printf("📍 Web Interface: http://localhost%s\n", addr)
	fmt.Printf("📁 Hosts File: %s\n", hostsPath())
	fmt.Printf("💾 Backups: %s\n", backupDir())
	fmt.Printf("⌨️  Use Ctrl+C to stop server\n\n")
	fmt.Printf("💡 CLI Usage: %s --help\n", os.Args[0])
	if !checkRootPrivileges() {
		// red color
		fmt.Printf("\033[31m")
		fmt.Println("📢❗🚨 You are not running the web ui as root.\n📢❗🚨 You will not be able to save changes to the hosts file.")
		fmt.Printf("\033[0m")
	}

	if err := http.ListenAndServe(addr, mux); err != nil {
		fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
		os.Exit(1)
	}
}

func isPortIsInUse(port int) bool {
	ln, err := net.Listen("tcp", ":"+strconv.Itoa(port))
	if err != nil {
		return true
	}
	defer func() {
		_ = ln.Close()
	}()
	return false
}
func getRandomUnusedPort() int {
	for {
		port := rand.Intn(10000) + 10000
		if !isPortIsInUse(port) {
			return port
		}
	}
}

func ensureProxyHostExists() {
	if *proxyFlag == "" {
		fmt.Fprintf(os.Stderr, "Error: proxy flag is required\n")
		os.Exit(1)
	}

	if !checkNetworkPrivileges() {
		err := addNetworkPrivileges()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	}

	if !hostExists(*proxyFlag) {
		fmt.Fprintf(os.Stderr, "Error: host %s does not exist\n", *proxyFlag)
		// prompt user to add host

		var addHost = yesNoPrompt("Do you want to add the host now? (y/n)")
		if addHost {
			if err := cliAddEntry(*proxyFlag, "127.0.0.1", ""); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
		} else {
			log.Println("Host does not exist. Exiting...")
			os.Exit(1)
		}

	}
}

func checkNetworkPrivileges() bool {
	cmd := exec.Command("getcap", executablePath())
	output, err := cmd.Output()
	if err != nil {
		fmt.Println("Error checking privileges:", err)
		return false
	}

	if !strings.Contains(string(output), "cap_net_bind_service") {
		fmt.Println("You need to add the following capability to the binary: cap_net_bind_service")
		fmt.Printf("To do this, run the following command:\n\nsudo setcap cap_net_bind_service=+ep $(which %s)\n\n", os.Args[0])
		return false
	}
	return true
}

func addNetworkPrivileges() error {
	yesNoPrompt("Do you want to add the necessary capability to the binary? (y/n)")
	formatedCommand := fmt.Sprintf("sudo setcap cap_net_bind_service=+ep %s", executablePath())
	fmt.Printf("Running command: %s\n", formatedCommand)
	cmd := exec.Command("sudo", "setcap", "cap_net_bind_service=+ep", executablePath())
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to add capability: %w", err)
	}
	// start the program again
	restartProgram()

	return nil
}

func restartProgram() {
	// restart the program
	//clear the terminal
	cmd := exec.Command("clear")
	_, _ = cmd.Output()
	fmt.Println("Restarting program...")
	os.Args = append([]string{os.Args[0]}, os.Args[1:]...)
	os.StartProcess(executablePath(), os.Args, &os.ProcAttr{
		Files: []*os.File{os.Stdin, os.Stdout, os.Stderr},
		Env:   os.Environ(),
	})
	os.Exit(0)
}

func cliInit() error {
	if !checkNetworkPrivileges() {
		err := addNetworkPrivileges()
		if err != nil {
			return err
		}
	}
	err := config.InitConfig()
	if err != nil {
		return err
	}
	return nil
}

func main() {
	flag.Parse()

	if *checkPrivilegesFlag {
		checkNetworkPrivileges()
		return
	}
	if *versionFlag {
		fmt.Printf("Hosts CLI v%s\n", version)
		return
	}
	if *initFlag {
		if err := cliInit(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if *helpFlag {
		showUsage()
		return
	}
	if *caddyFlag {
		ensureProxyHostExists()
		if *portFlag == "" {
			*portFlag = "3000"
		}
		port, err := strconv.Atoi(*portFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: invalid port: %v\n", err)
			os.Exit(1)
		}
		log.Printf("🚀 Caddy is running. for %s -> 127.0.0.1:%d (TLS=%v)", *proxyFlag, port, true)
		caddystarter.RunCaddyUntilSignal(*proxyFlag, port, true)
		return
	}
	if *proxyFlag != "" {
		ensureProxyHostExists()
		if *portFlag == "" {
			*portFlag = "3000"
		}
		port, err := strconv.Atoi(*portFlag)
		if err != nil || port < 1 || port > 65535 {
			fmt.Fprintf(os.Stderr, "Error: invalid port: %v\n", err)
			os.Exit(1)
		}
		log.Printf("🚀 Caddy is running. for %s -> 127.0.0.1:%d (TLS=%v)", *proxyFlag, port, true)
		caddystarter.RunCaddyUntilSignal(*proxyFlag, port, true)
		return
	}

	// Handle CLI operations
	if *addFlag != "" {
		if err := cliAddEntry(*addFlag, *ipFlag, *commentFlag); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if *removeFlag != "" {
		if err := cliRemoveEntry(*removeFlag); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if *listFlag {
		if err := cliListEntries(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if *disableFlag != "" {
		if err := cliToggleEntry(*disableFlag, true); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if *enableFlag != "" {
		if err := cliToggleEntry(*enableFlag, false); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if *backupFlag {
		if err := cliCreateBackup(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if *restoreFlag != "" {
		if err := cliRestoreBackup(*restoreFlag); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// No CLI flags provided, start web server
	startWebServer()

}
