package core

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"hosts/config"
	"hosts/data"
	"io"
	"log"
	"math/rand"
	"net"
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

var Ipv4Regex = regexp.MustCompile(`^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$`)
var Ipv6Regex = regexp.MustCompile(`^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^::$`)
var HostnameRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?$`)

func HostsPath() string {
	if runtime.GOOS == "windows" {
		windir := os.Getenv("SystemRoot")
		if windir == "" {
			windir = `C:\Windows`
		}
		return filepath.Join(windir, "System32", "drivers", "etc", "hosts")
	}
	return "/etc/hosts"
}

func ExecutablePath() string {
	path, err := os.Executable()
	if err != nil {
		return ""
	}
	return path
}

func BackupDir() string {
	dir := filepath.Dir(HostsPath())
	if config.GetConfig().Backup.Dir != "" {
		return config.GetConfig().Backup.Dir
	}
	return filepath.Join(dir, "hosts_backups")
}

func IsSystemEntry(ip string, hostnames []string) bool {
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

func ReadHosts() ([]data.Entry, error) {
	path := HostsPath()
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var entries []data.Entry
	id := 1

	for scanner.Scan() {
		line := scanner.Text()
		trim := strings.TrimSpace(line)

		if trim == "" {
			entries = append(entries, data.Entry{
				ID: id, Raw: line, IsComment: true,
			})
			id++
			continue
		}

		if strings.HasPrefix(trim, "#") {
			// Check if it's a disabled entry
			withoutHash := strings.TrimSpace(trim[1:])
			fields := strings.Fields(withoutHash)

			if len(fields) >= 2 && (Ipv4Regex.MatchString(fields[0]) || Ipv6Regex.MatchString(fields[0])) {
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

				entries = append(entries, data.Entry{
					ID: id, IP: ip, Hostnames: hosts, Comment: cmt,
					Disabled: true, IsSystem: IsSystemEntry(ip, hosts),
				})
			} else {
				// Regular comment
				entries = append(entries, data.Entry{
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
			entries = append(entries, data.Entry{ID: id, Raw: line, IsComment: true})
			id++
			continue
		}

		ip := fields[0]
		hosts := []string{}
		if len(fields) > 1 {
			hosts = fields[1:]
		}

		entries = append(entries, data.Entry{
			ID: id, IP: ip, Hostnames: hosts, Comment: cmt,
			IsSystem: IsSystemEntry(ip, hosts),
		})
		id++
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

func WriteHosts(entries []data.Entry) error {
	path := HostsPath()

	// Create backup
	if err := CreateBackup(); err != nil {
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
			line += "\t" + strings.Join(CleanHosts(e.Hostnames), " ")
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

func HostExists(host string) bool {
	entries, err := ReadHosts()
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

func CreateBackup() error {
	path := HostsPath()
	dir := BackupDir()

	// Create backup directory if it doesn't exist
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	backup := filepath.Join(dir, fmt.Sprintf("hosts.bak.%s", time.Now().Format("20060102-150405")))
	return CopyFile(path, backup)
}

func GetBackups() ([]data.BackupInfo, error) {
	dir := BackupDir()
	files, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return []data.BackupInfo{}, nil
		}
		return nil, err
	}

	var backups []data.BackupInfo
	for _, file := range files {
		if strings.HasPrefix(file.Name(), "hosts.bak.") {
			info, err := file.Info()
			if err != nil {
				continue
			}
			backups = append(backups, data.BackupInfo{
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

func RestoreBackup(filename string) error {
	var backupPath string
	if filepath.IsAbs(filename) {
		backupPath = filename
	} else {
		backupPath = filepath.Join(BackupDir(), filename)
	}
	return CopyFile(backupPath, HostsPath())
}

func CleanHosts(hs []string) []string {
	out := make([]string, 0, len(hs))
	for _, h := range hs {
		h = strings.TrimSpace(h)
		if h != "" {
			out = append(out, h)
		}
	}
	return out
}

func CopyFile(src, dst string) error {
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

func ValidateEntry(e data.Entry) error {
	if e.IsComment {
		return nil
	}

	ip := strings.TrimSpace(e.IP)
	if ip == "" {
		return errors.New("IP address is required")
	}

	if !Ipv4Regex.MatchString(ip) && !Ipv6Regex.MatchString(ip) {
		return errors.New("invalid IP address format")
	}

	for _, hostname := range e.Hostnames {
		if !HostnameRegex.MatchString(hostname) && hostname != "localhost" {
			return fmt.Errorf("invalid hostname: %s", hostname)
		}
	}

	return nil
}

func CalculateStats(entries []data.Entry) data.Stats {
	stats := data.Stats{}
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

func CheckRootPrivileges() bool {
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
func CliAddEntry(hostname, ip, comment string) error {
	if !CheckRootPrivileges() {
		fmt.Println("You need to escalate privileges to add a new entry.")
		// prompt user to escalate privileges
		var escalatePrivileges = YesNoPrompt("Do you want to escalate privileges now? (y/n) ")
		if escalatePrivileges {
			cmd := exec.Command("sudo", os.Args[0], "add", hostname, "--ip", ip, "--comment", comment)
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
	entries, err := ReadHosts()
	if err != nil {
		return fmt.Errorf("failed to read hosts: %w", err)
	}

	// Validate IP
	if !Ipv4Regex.MatchString(ip) && !Ipv6Regex.MatchString(ip) {
		return fmt.Errorf("invalid IP address: %s", ip)
	}

	// Validate hostname
	if !HostnameRegex.MatchString(hostname) && hostname != "localhost" {
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
	newEntry := data.Entry{
		ID:        maxID + 1,
		IP:        ip,
		Hostnames: []string{hostname},
		Comment:   comment,
		Disabled:  false,
		IsComment: false,
		IsSystem:  false,
	}

	entries = append(entries, newEntry)

	if err := WriteHosts(entries); err != nil {
		return fmt.Errorf("failed to write hosts: %w", err)
	}

	fmt.Printf("✓ Added: %s -> %s", hostname, ip)
	if comment != "" {
		fmt.Printf(" (%s)", comment)
	}
	fmt.Println()
	return nil
}

func CliRemoveEntry(hostname string) error {
	if !CheckRootPrivileges() {
		fmt.Println("You need to escalate privileges to add a new entry.")
		// prompt user to escalate privileges
		var escalatePrivileges = YesNoPrompt("Do you want to escalate privileges now? (y/n) ")
		if escalatePrivileges {
			cmd := exec.Command("sudo", os.Args[0], "remove", hostname)
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
	entries, err := ReadHosts()
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

	if err := WriteHosts(entries); err != nil {
		return fmt.Errorf("failed to write hosts: %w", err)
	}

	fmt.Printf("✓ Removed: %s\n", hostname)
	return nil
}

func CliListEntries() error {
	entries, err := ReadHosts()
	if err != nil {
		return fmt.Errorf("failed to read hosts: %w", err)
	}

	stats := CalculateStats(entries)

	fmt.Printf("Hosts File: %s\n", HostsPath())
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

func CliToggleEntry(hostname string, disable bool) error {
	entries, err := ReadHosts()
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

	if err := WriteHosts(entries); err != nil {
		return fmt.Errorf("failed to write hosts: %w", err)
	}

	action := "Enabled"
	if disable {
		action = "Disabled"
	}
	fmt.Printf("✓ %s: %s\n", action, hostname)
	return nil
}

func CliCreateBackup() error {
	if err := CreateBackup(); err != nil {
		return fmt.Errorf("failed to create backup: %w", err)
	}

	// Get the latest backup to show the filename
	backups, err := GetBackups()
	if err == nil && len(backups) > 0 {
		fmt.Printf("✓ Backup created: %s\n", backups[0].Name)
		fmt.Printf("  Location: %s\n", filepath.Join(BackupDir(), backups[0].Name))
	} else {
		fmt.Println("✓ Backup created successfully")
	}
	return nil
}

func CliRestoreBackup(filename string) error {
	if err := RestoreBackup(filename); err != nil {
		return fmt.Errorf("failed to restore backup: %w", err)
	}

	fmt.Printf("✓ Restored from backup: %s\n", filename)
	return nil
}

func CliInit() error {
	if !CheckNetworkPrivileges() {
		err := AddNetworkPrivileges()
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

func YesNoPrompt(prompt string) bool {
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
func IsPortInUse(port int) bool {
	ln, err := net.Listen("tcp", ":"+strconv.Itoa(port))
	if err != nil {
		return true
	}
	defer func() {
		_ = ln.Close()
	}()
	return false
}

func GetRandomUnusedPort() int {
	for {
		port := rand.Intn(10000) + 10000
		if !IsPortInUse(port) {
			return port
		}
	}
}

func EnsureProxyHostExists(
	proxyFlag *string,
) {
	if *proxyFlag == "" {
		fmt.Fprintf(os.Stderr, "Error: proxy flag is required\n")
		os.Exit(1)
	}

	if !CheckNetworkPrivileges() {
		err := AddNetworkPrivileges()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	}

	if !HostExists(*proxyFlag) {
		fmt.Fprintf(os.Stderr, "Error: host %s does not exist\n", *proxyFlag)
		// prompt user to add host

		var addHost = YesNoPrompt("Do you want to add the host now? (y/n)")
		if addHost {
			if err := CliAddEntry(*proxyFlag, "127.0.0.1", ""); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
		} else {
			log.Println("Host does not exist. Exiting...")
			os.Exit(1)
		}

	}
}

func CheckNetworkPrivileges() bool {
	cmd := exec.Command("getcap", ExecutablePath())
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

func AddNetworkPrivileges() error {
	YesNoPrompt("Do you want to add the necessary capability to the binary? (y/n)")
	formatedCommand := fmt.Sprintf("sudo setcap cap_net_bind_service=+ep %s", ExecutablePath())
	fmt.Printf("Running command: %s\n", formatedCommand)
	cmd := exec.Command("sudo", "setcap", "cap_net_bind_service=+ep", ExecutablePath())
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to add capability: %w", err)
	}
	// start the program again
	RestartProgram()

	return nil
}

func RestartProgram() {
	// restart the program
	//clear the terminal
	cmd := exec.Command("clear")
	_, _ = cmd.Output()
	fmt.Println("Restarting program...")
	os.Args = append([]string{os.Args[0]}, os.Args[1:]...)
	os.StartProcess(ExecutablePath(), os.Args, &os.ProcAttr{
		Files: []*os.File{os.Stdin, os.Stdout, os.Stderr},
		Env:   os.Environ(),
	})
	os.Exit(0)
}
