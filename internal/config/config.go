// Package config handles loading and saving the persistent configuration.
package config

import (
	"encoding/json"
	"os"
	"path/filepath"

	"ebpfproxy/internal/rule"
)

// Config is the on-disk configuration.
type Config struct {
	ProxyAddr     string      `json:"proxy_addr"`
	ProxyUser     string      `json:"proxy_user"`
	ProxyPass     string      `json:"proxy_pass"`
	DefaultAction string      `json:"default_action"`
	TCPRelayPort  uint16      `json:"tcp_relay_port"`
	UDPRelayPort  uint16      `json:"udp_relay_port"`
	CgroupPath    string      `json:"cgroup_path"`
	Rules         []rule.Rule `json:"rules"`
}

// Default returns a sensible default configuration.
func Default() Config {
	return Config{
		ProxyAddr:     "127.0.0.1:1080",
		DefaultAction: "DIRECT",
		TCPRelayPort:  15001,
		UDPRelayPort:  15002,
		CgroupPath:    "/sys/fs/cgroup",
		Rules:         []rule.Rule{},
	}
}

// Dir returns the configuration directory.
func Dir() string {
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "ebpfproxy")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "/etc/ebpfproxy"
	}
	return filepath.Join(home, ".config", "ebpfproxy")
}

// Path returns the default configuration file path.
func Path() string { return filepath.Join(Dir(), "config.json") }

// Load reads the configuration from path, falling back to defaults when the
// file does not exist.
func Load(path string) (Config, error) {
	cfg := Default()
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return cfg, err
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return Default(), err
	}
	if cfg.ProxyAddr == "" {
		cfg.ProxyAddr = "127.0.0.1:1080"
	}
	if cfg.DefaultAction == "" {
		cfg.DefaultAction = "DIRECT"
	}
	if cfg.CgroupPath == "" {
		cfg.CgroupPath = "/sys/fs/cgroup"
	}
	if cfg.TCPRelayPort == 0 {
		cfg.TCPRelayPort = 15001
	}
	if cfg.UDPRelayPort == 0 {
		cfg.UDPRelayPort = 15002
	}
	return cfg, nil
}

// Save writes the configuration to path.
func Save(path string, cfg Config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}
