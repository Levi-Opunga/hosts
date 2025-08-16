package data

import "time"

func Version() string {
	return "2.0"
}

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
