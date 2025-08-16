package server

import (
	"embed"
	"encoding/json"
	"fmt"
	"hosts-cli/core"
	"hosts-cli/data"
	"html/template"
	"net/http"
	"os"
	"runtime"
	"strconv"
)

//go:embed web/*
var WebFS embed.FS

// StartWebServerCobraBridge Bridge to run web server on a specific port from the Cobra runner.
// It reuses the existing startWebServer implementation by setting the global port flag.
func StartWebServerCobraBridge(port int) error {
	StartWebServer(port) // blocks; exits on error internally
	return nil
}

func StartWebServer(bindPort int) {
	mux := http.NewServeMux()

	// Serve static files
	mux.Handle("/static/", http.FileServer(http.FS(WebFS)))

	// UI
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		b, _ := WebFS.ReadFile("web/index.html")
		t := template.Must(template.New("index").Parse(string(b)))
		_ = t.Execute(w, map[string]any{
			"Path":    core.HostsPath(),
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
		entries, err := core.ReadHosts()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		stats := core.CalculateStats(entries)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(data.State{Entries: entries, Stats: stats})
	})

	// API: save hosts
	mux.HandleFunc("/api/save", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var st data.State
		if err := json.NewDecoder(r.Body).Decode(&st); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		for i, e := range st.Entries {
			if err := core.ValidateEntry(e); err != nil {
				http.Error(w, fmt.Sprintf("entry %d: %v", i+1, err), http.StatusBadRequest)
				return
			}
		}
		if err := core.WriteHosts(st.Entries); err != nil {
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
		backups, err := core.GetBackups()
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
		if err := core.RestoreBackup(filename); err != nil {
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
		var e data.Entry
		if err := json.NewDecoder(r.Body).Decode(&e); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		if err := core.ValidateEntry(e); err != nil {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"valid": false, "error": err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"valid": true})
	})

	if bindPort < 1 || bindPort > 65535 {
		fmt.Fprintf(os.Stderr, "Error: invalid port: %v\n", bindPort)
	}
	var addr string
	if core.IsPortInUse(bindPort) {
		fmt.Printf("Port %d is already in use.Selecting a random port...\n", bindPort)
		bindPort = core.GetRandomUnusedPort()
		addr = ":" + strconv.Itoa(bindPort)
	} else {
		addr = ":" + strconv.Itoa(bindPort)
	}

	if err := http.ListenAndServe(addr, mux); err != nil {
		fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
		os.Exit(1)
	}
}
