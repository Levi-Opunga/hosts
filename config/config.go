package config

import (
	"encoding/json"
	"os"
)

// Config represents the configuration for the application
type Config struct {
	Caddy struct {
		Port int  `json:"port"`
		TLS  bool `json:"tls"`
	} `json:"caddy"`
	Web struct {
		Port int `json:"port"`
	}
	Backup struct {
		Dir string `json:"dir"`
	}
	Aliases []Alias `json:"aliases"`
	// TODO: Add more configuration options
}
type Alias struct {
	Name string `json:"name"`
	Host string `json:"host"`
	Port int    `json:"port"`
}

func (c Config) String() string {
	b, _ := json.MarshalIndent(c, "", "  ")
	return string(b)
}

func GetConfigPath() string {
	homeDir := os.Getenv("HOME")
	if homeDir == "" {
		homeDir = os.Getenv("USERPROFILE")
	}
	if homeDir == "" {
		homeDir = os.Getenv("HOMEDRIVE") + os.Getenv("HOMEPATH")
	}
	// ensure the directory exists
	_ = os.MkdirAll(homeDir+"/.config/hosts-cli", 0755)
	return homeDir + "/.config/hosts-cli/config.json"
}

func GetConfigDir() string {
	homeDir := os.Getenv("HOME")
	if homeDir == "" {
		homeDir = os.Getenv("USERPROFILE")
	}
	if homeDir == "" {
		homeDir = os.Getenv("HOMEDRIVE") + os.Getenv("HOMEPATH")
	}
	return homeDir + "/.config/hosts-cli"
}

func GetConfig() Config {
	config, err := ReadConfig()
	if err != nil {
		return Config{}
	}
	return config
}

// CreateConfig creates new file in the config directory
func InitConfig() error {
	defaultConfig := Config{
		Caddy: struct {
			Port int  `json:"port"`
			TLS  bool `json:"tls"`
		}{
			Port: 3000,
			TLS:  false,
		},
		Web: struct {
			Port int `json:"port"`
		}{
			Port: 3000,
		},
		Backup: struct {
			Dir string `json:"dir"`
		}{
			Dir: GetConfigDir() + "/backups",
		},
		Aliases: []Alias{},
	}
	configPath := GetConfigPath()

	f, err := os.Create(configPath)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(defaultConfig.String())
	return err
}

// ReadConfig reads the configuration from the config file
func ReadConfig() (Config, error) {
	configPath := GetConfigPath()
	f, err := os.Open(configPath)
	if err != nil {
		return Config{}, err
	}
	defer f.Close()

	var config Config
	err = json.NewDecoder(f).Decode(&config)
	return config, err
}

// WriteConfig writes the configuration to the config file
func WriteConfig(config Config) error {
	configPath := GetConfigPath()
	f, err := os.Create(configPath)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(config.String())
	return err
}
