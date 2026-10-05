// Command ebpfproxy is an eBPF based per-process TCP/UDP traffic manager that
// can block traffic or redirect it through a SOCKS5 proxy.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	tea "github.com/charmbracelet/bubbletea"

	"ebpfproxy/internal/config"
	"ebpfproxy/internal/engine"
	"ebpfproxy/internal/rule"
	"ebpfproxy/internal/socks"
	"ebpfproxy/internal/tui"
)

const version = "0.2.0"

type stringSlice []string

func (s *stringSlice) String() string { return strings.Join(*s, ",") }
func (s *stringSlice) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func main() {
	var (
		configPath    = flag.String("config", config.Path(), "configuration file path")
		proxyFlag     = flag.String("proxy", "", "SOCKS5 proxy (host:port or socks5://host:port)")
		defaultAction = flag.String("default-action", "", "action for unmatched traffic: DIRECT, PROXY or BLOCK")
		tcpPort       = flag.Uint("tcp-relay-port", 0, "local TCP relay port")
		udpPort       = flag.Uint("udp-relay-port", 0, "local UDP relay port")
		cgroupPath    = flag.String("cgroup", "", "cgroup v2 path to attach hooks to")
		logLevel      = flag.String("log-level", "", "log level: off, block, proxy or all")
		headless      = flag.Bool("headless", false, "run without the TUI")
		showVersion   = flag.Bool("version", false, "print version and exit")
		showHelp      = flag.Bool("help", false, "show help and exit")
		showHelpShort = flag.Bool("h", false, "show help and exit")
		rulesFlag     stringSlice
	)
	flag.Var(&rulesFlag, "rule", "rule: process:hosts:ports:protocol:action (repeatable)")
	flag.Usage = printHelp
	flag.Parse()

	if *showHelp || *showHelpShort {
		printHelp()
		return
	}
	if *showVersion {
		fmt.Println("ebpfproxy", version)
		return
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: %v; using defaults\n", err)
		cfg = config.Default()
	}

	if *proxyFlag != "" {
		addr, user, pass := parseProxy(*proxyFlag)
		cfg.ProxyAddr, cfg.ProxyUser, cfg.ProxyPass = addr, user, pass
	}
	if *defaultAction != "" {
		cfg.DefaultAction = strings.ToUpper(*defaultAction)
	}
	if *tcpPort != 0 {
		cfg.TCPRelayPort = uint16(*tcpPort)
	}
	if *udpPort != 0 {
		cfg.UDPRelayPort = uint16(*udpPort)
	}
	if *cgroupPath != "" {
		cfg.CgroupPath = *cgroupPath
	}
	if *logLevel != "" {
		lv, err := parseLogLevel(*logLevel)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid --log-level: %v\n", err)
			os.Exit(2)
		}
		cfg.LogLevel = lv
	}

	if len(rulesFlag) > 0 {
		cfg.Rules = nil
		for i, s := range rulesFlag {
			r, err := rule.Parse(s, i+1)
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid --rule %q: %v\n", s, err)
				os.Exit(2)
			}
			cfg.Rules = append(cfg.Rules, r)
		}
	}

	da, err := rule.ParseAction(cfg.DefaultAction)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid default action: %v\n", err)
		os.Exit(2)
	}

	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "warning: root is required to load eBPF programs")
	}

	eng := engine.New(engine.Config{
		CgroupPath:    cfg.CgroupPath,
		Proxy:         socks.Client{Addr: cfg.ProxyAddr, User: cfg.ProxyUser, Pass: cfg.ProxyPass},
		DefaultAction: da,
		TCPRelayPort:  cfg.TCPRelayPort,
		UDPRelayPort:  cfg.UDPRelayPort,
		LogLevel:      uint32(cfg.LogLevel),
		Rules:         cfg.Rules,
	})

	if *headless {
		runHeadless(eng)
		return
	}

	p := tea.NewProgram(tui.New(eng, &cfg, *configPath), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "tui error:", err)
		eng.Stop()
		os.Exit(1)
	}
	eng.Stop()
}

func runHeadless(eng *engine.Engine) {
	if err := eng.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "start failed:", err)
		os.Exit(1)
	}
	defer eng.Stop()
	fmt.Println("ebpfproxy running headless; press Ctrl-C to stop")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	for {
		select {
		case <-sig:
			fmt.Println("\nstopping")
			return
		case e := <-eng.Events:
			fmt.Println(e.String())
		}
	}
}

func printHelp() {
	fmt.Printf(`ebpfproxy %s - eBPF per-process TCP/UDP traffic manager (IPv4)

USAGE
  sudo ebpfproxy [OPTIONS]

DESCRIPTION
  Hooks connect()/sendmsg() system-wide via eBPF and applies the first matching
  rule for the calling process. A matching rule can:
    PROXY    redirect the flow through a SOCKS5 proxy (TCP and UDP)
    DIRECT   leave the flow untouched
    BLOCK    deny the operation
  Traffic that matches no rule uses the default action (DIRECT by default).

OPTIONS
  --proxy <url>           SOCKS5 proxy. Accepted forms:
                            host:port
                            socks5://host:port
                            socks5://user:pass@host:port
                          Default: 127.0.0.1:1080
  --rule <rule>           Add a rule (repeatable, in evaluation order).
                          Format: process:hosts:ports:protocol:action
  --default-action <a>    Action when no rule matches: DIRECT, PROXY or BLOCK
                          Default: DIRECT
  --tcp-relay-port <n>    Local TCP relay port (default 15001)
  --udp-relay-port <n>    Local UDP relay port (default 15002)
  --cgroup <path>         cgroup v2 path to attach the hooks to
                          Default: /sys/fs/cgroup
  --log-level <level>     Traffic log level: off, block, proxy or all
                          Default: proxy
  --config <path>         Config file
                          Default: ~/.config/ebpfproxy/config.json
  --headless              Run without the TUI (events printed to stdout)
  -h, --help              Show this help and exit
  --version               Print the version and exit

RULE SYNTAX
  process:hosts:ports:protocol:action

    process   name, matched against the task name (comm) OR executable
              basename. 'git' matches only "git"; 'git*' matches any prefix;
              '*' = any; multiple with ';' or ','
              e.g. git   git*   firefox   curl;wget   *
    hosts     IPv4 address, CIDR, hostname, or '*'; multiple with ';' or ','
              e.g. 1.1.1.1   10.0.0.0/8   example.com   192.168.*.*
    ports     single port, range, or '*'; multiple with ';' or ','
              e.g. 443   8000-8100   80;443   53
    protocol  TCP, UDP or BOTH
    action    PROXY, DIRECT or BLOCK

  Rules are evaluated top to bottom; the FIRST match wins and later rules are
  ignored. The connection log reports which rule order matched (rule #N). In
  the TUI press k / j to move the selected rule up / down.

NO IMPLICIT BYPASS
  Every flow (including loopback, broadcast and link-local) is decided by the
  rules and the default action. If you use a catch-all PROXY/default PROXY, add
  DIRECT rules for loopback and your proxy process, e.g.:
      --rule '*:127.0.0.1;localhost:*:BOTH:DIRECT'
      --rule 'v2ray:*:*:BOTH:DIRECT'
  otherwise the relay's own connection to the proxy would loop.

LOG LEVELS
  off    no traffic events
  block  blocked flows only
  proxy  blocked + proxied flows (default)
  all    blocked + proxied + direct flows

EXAMPLES
  # TUI (rules are saved to the config file)
  sudo ebpfproxy

  # Proxy curl and wget, block everything else
  sudo ebpfproxy --headless --proxy 127.0.0.1:1080 \
      --rule 'curl;wget:*:*:TCP:PROXY' \
      --rule '*:*:*:BOTH:BLOCK'

  # Route Firefox TCP traffic through the proxy
  sudo ebpfproxy --headless --proxy 127.0.0.1:1080 \
      --rule 'firefox:*:*:TCP:PROXY'

  # Proxy DNS over UDP for one process
  sudo ebpfproxy --headless --proxy 127.0.0.1:1080 \
      --rule 'firefox:*:53:UDP:PROXY'

NOTES
  - Root is required to load eBPF and to bind IP_TRANSPARENT sockets.
  - IPv4 only.
  - Hooks detach automatically on exit; 'kill -9' leaves nothing behind.
`, version)
}

func parseLogLevel(s string) (int, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "off", "0":
		return 0, nil
	case "block", "1":
		return 1, nil
	case "proxy", "2":
		return 2, nil
	case "all", "3":
		return 3, nil
	}
	return 0, fmt.Errorf("want off, block, proxy or all")
}

func parseProxy(s string) (addr, user, pass string) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "socks5://")
	s = strings.TrimPrefix(s, "socks5h://")
	s = strings.TrimPrefix(s, "socks://")
	// user:pass@host:port
	if at := strings.LastIndex(s, "@"); at >= 0 {
		cred := s[:at]
		s = s[at+1:]
		if c := strings.SplitN(cred, ":", 2); len(c) == 2 {
			user, pass = c[0], c[1]
		}
	}
	return s, user, pass
}
