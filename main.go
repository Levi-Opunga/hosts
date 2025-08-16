// Enhanced Hosts Editor – Modern web UI to view and edit /etc/hosts
// Features: Search, filtering, validation, backup management, bulk operations
// Build: go build -o hosts-ui
// Run (Linux/macOS): sudo ./hosts-ui
// Run (Windows as Administrator): ./hosts-ui.exe
// Open: http://localhost:3000

package main

import (
	"bufio"
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
)

//go:embed web/*
var webFS embed.FS

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

func backupDir() string {
	dir := filepath.Dir(hostsPath())
	return filepath.Join(dir, "hosts_backups")
}

func isSystemEntry(ip string, hostnames []string) bool {
	systemEntries := map[string]bool{
		"127.0.0.1": true,
		"::1":       true,
		"0.0.0.0":   true,
	}

	if systemEntries[ip] {
		return true
	}

	for _, host := range hostnames {
		if host == "localhost" || host == "localhost.localdomain" ||
			strings.HasSuffix(host, ".localhost") {
			return true
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
	backupPath := filepath.Join(backupDir(), filename)
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

func main() {
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

	addr := ":3010"
	fmt.Printf("🚀 Enhanced Hosts Editor v2.0\n")
	fmt.Printf("📍 Listening on http://localhost%s\n", addr)
	fmt.Printf("📁 Editing: %s\n", hostsPath())
	fmt.Printf("💾 Backups: %s\n", backupDir())
	if err := http.ListenAndServe(addr, mux); err != nil {
		panic(err)
	}
}
