// Package config handles loading and saving the persistent configuration.
package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"ebpfproxy/internal/rule"
)

// Proxy is one SOCKS5 endpoint.
type Proxy struct {
	Name string `json:"name"`
	Addr string `json:"addr"`
	User string `json:"user,omitempty"`
	Pass string `json:"pass,omitempty"`
}

// Config is the on-disk configuration.
type Config struct {
	Proxies       []Proxy     `json:"proxies"`
	DefaultProxy  string      `json:"default_proxy"`
	DefaultAction string      `json:"default_action"`
	TCPRelayPort  uint16      `json:"tcp_relay_port"`
	UDPRelayPort  uint16      `json:"udp_relay_port"`
	CgroupPath    string      `json:"cgroup_path"`
	LogLevel      int         `json:"log_level"`
	Rules         []rule.Rule `json:"rules"`

	// Legacy single-proxy fields, migrated into Proxies on load.
	ProxyAddr string `json:"proxy_addr,omitempty"`
	ProxyUser string `json:"proxy_user,omitempty"`
	ProxyPass string `json:"proxy_pass,omitempty"`
}

// Default returns a sensible default configuration.
func Default() Config {
	return Config{
		Proxies:       []Proxy{{Name: "default", Addr: "127.0.0.1:1080"}},
		DefaultProxy:  "default",
		DefaultAction: "DIRECT",
		TCPRelayPort:  15001,
		UDPRelayPort:  15002,
		CgroupPath:    "/sys/fs/cgroup",
		LogLevel:      2,
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

// ProxyByName returns the proxy with the given name.
func (c Config) ProxyByName(name string) (Proxy, bool) {
	for _, p := range c.Proxies {
		if p.Name == name {
			return p, true
		}
	}
	return Proxy{}, false
}

// DefaultProxyIndex returns the index of the default proxy (0 if unset).
func (c Config) DefaultProxyIndex() int {
	for i, p := range c.Proxies {
		if p.Name == c.DefaultProxy {
			return i
		}
	}
	return 0
}

// Migrate fills in the proxy list from legacy fields and normalises names.
func (c *Config) Migrate() {
	if len(c.Proxies) == 0 {
		addr := strings.TrimSpace(c.ProxyAddr)
		if addr == "" {
			addr = "127.0.0.1:1080"
		}
		c.Proxies = []Proxy{{Name: "default", Addr: addr, User: c.ProxyUser, Pass: c.ProxyPass}}
	}
	seen := map[string]bool{}
	for i := range c.Proxies {
		if strings.TrimSpace(c.Proxies[i].Name) == "" {
			c.Proxies[i].Name = "proxy" + itoa(i+1)
		}
		for seen[c.Proxies[i].Name] {
			c.Proxies[i].Name += "2"
		}
		seen[c.Proxies[i].Name] = true
		if strings.TrimSpace(c.Proxies[i].Addr) == "" {
			c.Proxies[i].Addr = "127.0.0.1:1080"
		}
	}
	if _, ok := c.ProxyByName(c.DefaultProxy); !ok {
		c.DefaultProxy = c.Proxies[0].Name
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

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
	cfg.Migrate()
	if cfg.DefaultAction == "" {
		cfg.DefaultAction = "DIRECT"
	}
	if cfg.TCPRelayPort == 0 {
		cfg.TCPRelayPort = 15001
	}
	if cfg.UDPRelayPort == 0 {
		cfg.UDPRelayPort = 15002
	}
	if cfg.CgroupPath == "" {
		cfg.CgroupPath = "/sys/fs/cgroup"
	}
	return cfg, nil
}

// Save writes the configuration to path.
func Save(path string, cfg Config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	cfg.Migrate()
	cfg.ProxyAddr, cfg.ProxyUser, cfg.ProxyPass = "", "", ""
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}
