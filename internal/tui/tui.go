// Package tui implements the interactive terminal interface.
package tui

import (
	"fmt"
	"net"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"ebpfproxy/internal/config"
	"ebpfproxy/internal/engine"
	"ebpfproxy/internal/relay"
	"ebpfproxy/internal/rule"
	"ebpfproxy/internal/socks"
)

var (
	styleTitle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("205"))
	styleTabOn   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("15")).Background(lipgloss.Color("62")).Padding(0, 1)
	styleTabOff  = lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Padding(0, 1)
	styleHelp    = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
	styleOK      = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	styleBad     = lipgloss.NewStyle().Foreground(lipgloss.Color("203"))
	styleSel     = lipgloss.NewStyle().Background(lipgloss.Color("236")).Bold(true)
	styleHeader  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("111"))
	styleModal   = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Padding(1, 2).BorderForeground(lipgloss.Color("62"))
	styleFldOn   = lipgloss.NewStyle().Foreground(lipgloss.Color("205"))
	styleFldOff  = lipgloss.NewStyle().Foreground(lipgloss.Color("250"))
	styleOverlay = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
)

const (
	tabStatus = iota
	tabRules
	tabLogs
	tabSettings
	tabCount
)

var tabNames = []string{"Status", "Rules", "Logs", "Settings"}

type input struct {
	value  string
	cursor int
}

func (in *input) set(s string) { in.value = s; in.cursor = len([]rune(s)) }

func (in *input) insert(r rune) {
	rs := []rune(in.value)
	if in.cursor < 0 {
		in.cursor = 0
	}
	if in.cursor > len(rs) {
		in.cursor = len(rs)
	}
	rs = append(rs[:in.cursor], append([]rune{r}, rs[in.cursor:]...)...)
	in.value = string(rs)
	in.cursor++
}

func (in *input) backspace() {
	rs := []rune(in.value)
	if in.cursor <= 0 || len(rs) == 0 {
		return
	}
	rs = append(rs[:in.cursor-1], rs[in.cursor:]...)
	in.value = string(rs)
	in.cursor--
}

func (in *input) del() {
	rs := []rune(in.value)
	if in.cursor < 0 || in.cursor >= len(rs) {
		return
	}
	rs = append(rs[:in.cursor], rs[in.cursor+1:]...)
	in.value = string(rs)
}

func (in *input) left() {
	if in.cursor > 0 {
		in.cursor--
	}
}
func (in *input) right() {
	if in.cursor < len([]rune(in.value)) {
		in.cursor++
	}
}
func (in *input) home() { in.cursor = 0 }
func (in *input) end()  { in.cursor = len([]rune(in.value)) }

type field struct {
	label string
	key   string // settings field identifier
	input
	cycle []string
}

type editForm struct {
	title  string
	fields []*field
	cur    int
	onSave func([]string) error
}

type eventMsg relay.Event

type tickMsg time.Time

type startedMsg struct{ err error }

type stoppedMsg struct {
	err    error
	report string
}

// Model is the root bubbletea model.
type Model struct {
	eng     *engine.Engine
	cfg     *config.Config
	cfgPath string

	active int
	width  int
	height int

	rules     []rule.Rule
	cursor    int
	setCur    int
	logs      []string
	logScroll int
	fullLogs  bool
	form      *editForm
	errMsg    string
	status    string
	busy      bool
	quitNext  bool
}

// New creates the TUI model.
func New(eng *engine.Engine, cfg *config.Config, cfgPath string) *Model {
	m := &Model{
		eng:     eng,
		cfg:     cfg,
		cfgPath: cfgPath,
		rules:   append([]rule.Rule(nil), cfg.Rules...),
		active:  tabStatus,
	}
	return m
}

// moveRule moves the selected rule delta positions (up = -1, down = +1) and
// re-applies the rule set so the kernel evaluation order follows immediately.
func (m *Model) moveRule(delta int) {
	i := m.cursor
	j := i + delta
	if i < 0 || i >= len(m.rules) || j < 0 || j >= len(m.rules) {
		return
	}
	m.rules[i], m.rules[j] = m.rules[j], m.rules[i]
	m.cursor = j
	m.applyRules()
}

// freeID returns the smallest positive ID not currently used.
func (m *Model) freeID() int {
	used := make(map[int]bool, len(m.rules))
	for _, r := range m.rules {
		used[r.ID] = true
	}
	for i := 1; ; i++ {
		if !used[i] {
			return i
		}
	}
}

func (m *Model) Init() tea.Cmd {
	return tea.Batch(waitForEvent(m.eng.Events), tick())
}

func tick() tea.Cmd {
	return tea.Tick(2*time.Second, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func waitForEvent(ch <-chan relay.Event) tea.Cmd {
	return func() tea.Msg {
		e, ok := <-ch
		if !ok {
			return nil
		}
		return eventMsg(e)
	}
}

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil
	case tickMsg:
		return m, tick()
	case startedMsg:
		m.busy = false
		if msg.err != nil {
			m.errMsg = msg.err.Error()
			m.status = "start failed"
			if m.quitNext {
				return m, tea.Quit
			}
			return m, nil
		}
		m.errMsg = ""
		m.status = "started: bpf hooks attached, tcp+udp relays listening"
		if m.quitNext {
			return m, m.stopEngine()
		}
		return m, nil
	case stoppedMsg:
		m.busy = false
		if msg.err != nil {
			m.errMsg = msg.err.Error()
		}
		m.status = msg.report
		if m.quitNext {
			return m, tea.Quit
		}
		return m, nil
	case eventMsg:
		m.logs = append(m.logs, relay.Event(msg).String())
		if len(m.logs) > 2000 {
			m.logs = m.logs[len(m.logs)-1000:]
		}
		// Keep a scrolled-up window anchored when new lines arrive.
		if m.logScroll > 0 {
			m.logScroll++
		}
		return m, waitForEvent(m.eng.Events)
	case tea.KeyMsg:
		if m.form != nil {
			return m.updateForm(msg)
		}
		return m.updateKey(msg)
	}
	return m, nil
}

func (m *Model) updateKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.fullLogs {
		return m.updateFullLogs(msg)
	}
	switch msg.String() {
	case "ctrl+c":
		if m.eng.Running() {
			m.quitNext = true
			return m, m.stopEngine()
		}
		return m, tea.Quit
	case "q":
		// Quit only once everything has actually stopped (first press starts
		// the shutdown and shows what was torn down).
		if m.eng.Running() {
			m.quitNext = true
			return m, m.stopEngine()
		}
		return m, tea.Quit
	case "tab":
		m.active = (m.active + 1) % tabCount
		return m, nil
	case "shift+tab":
		m.active = (m.active + tabCount - 1) % tabCount
		return m, nil
	case "1", "2", "3", "4":
		m.active = int(msg.String()[0] - '1')
		return m, nil
	}

	switch m.active {
	case tabRules:
		return m.updateRules(msg)
	case tabSettings:
		return m.updateSettings(msg)
	case tabLogs:
		switch msg.String() {
		case "s":
			return m, m.startEngine()
		case "x":
			return m, m.stopEngine()
		case "c":
			m.logs = nil
			m.logScroll = 0
		case "k", "up":
			m.scrollLogs(1)
		case "j", "down":
			m.scrollLogs(-1)
		case "enter", "f":
			m.fullLogs = true
			m.logScroll = 0
		}
	case tabStatus:
		switch msg.String() {
		case "s":
			return m, m.startEngine()
		case "x":
			return m, m.stopEngine()
		}
	}
	return m, nil
}

func (m *Model) scrollLogs(delta int) {
	m.logScroll += delta
	if m.logScroll < 0 {
		m.logScroll = 0
	}
}

func (m *Model) updateFullLogs(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "esc":
		m.fullLogs = false
	case "k", "up":
		m.scrollLogs(1)
	case "j", "down":
		m.scrollLogs(-1)
	case "g", "home":
		m.logScroll = len(m.logs)
	case "G", "end":
		m.logScroll = 0
	case "c":
		m.logs = nil
		m.logScroll = 0
	}
	return m, nil
}

func (m *Model) updateRules(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch msg.String() {
	case "up":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down":
		if m.cursor < len(m.rules)-1 {
			m.cursor++
		}
	case "k", "shift+up":
		m.moveRule(-1)
	case "j", "shift+down":
		m.moveRule(1)
	case "s":
		cmd = m.startEngine()
	case "x":
		cmd = m.stopEngine()
	case "a":
		m.form = &editForm{
			title: "Add rule",
			fields: []*field{
				{label: "process"},
				{label: "hosts"},
				{label: "ports"},
				{label: "protocol", cycle: []string{"TCP", "UDP", "BOTH"}},
				{label: "action", cycle: []string{"PROXY", "DIRECT", "BLOCK"}},
				{label: "proxy"},
			},
			onSave: func(v []string) error { return m.saveRule(-1, v) },
		}
		m.form.fields[0].set("*")
		m.form.fields[1].set("*")
		m.form.fields[2].set("*")
		m.form.fields[3].set("BOTH")
		m.form.fields[4].set("PROXY")
	case "enter", "e":
		if len(m.rules) == 0 {
			break
		}
		r := m.rules[m.cursor]
		idx := m.cursor
		m.form = &editForm{
			title: "Edit rule",
			fields: []*field{
				{label: "process"},
				{label: "hosts"},
				{label: "ports"},
				{label: "protocol", cycle: []string{"TCP", "UDP", "BOTH"}},
				{label: "action", cycle: []string{"PROXY", "DIRECT", "BLOCK"}},
				{label: "proxy"},
			},
			onSave: func(v []string) error { return m.saveRule(idx, v) },
		}
		m.form.fields[0].set(r.Process)
		m.form.fields[1].set(r.Hosts)
		m.form.fields[2].set(r.Ports)
		m.form.fields[3].set(strings.ToUpper(r.Protocol))
		m.form.fields[4].set(strings.ToUpper(r.Action))
		m.form.fields[5].set(r.Proxy)
	case "d", "delete":
		if len(m.rules) > 0 {
			m.rules = append(m.rules[:m.cursor], m.rules[m.cursor+1:]...)
			if m.cursor >= len(m.rules) && m.cursor > 0 {
				m.cursor--
			}
			m.applyRules()
		}
	case " ":
		if len(m.rules) > 0 {
			m.rules[m.cursor].Enabled = !m.rules[m.cursor].Enabled
			m.applyRules()
		}
	}
	return m, cmd
}

func (m *Model) updateSettings(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	fields := m.settingFields()
	switch msg.String() {
	case "up", "k":
		if m.setCur > 0 {
			m.setCur--
		}
	case "down", "j":
		if m.setCur < len(fields)-1 {
			m.setCur++
		}
	case "enter", "e":
		if len(fields) == 0 {
			break
		}
		idx := m.setCur
		key := fields[idx].key
		m.form = &editForm{
			title:  "Edit " + fields[idx].label,
			fields: []*field{{label: fields[idx].label, cycle: fields[idx].cycle}},
			onSave: func(v []string) error { return m.saveSetting(key, v[0]) },
		}
		m.form.fields[0].set(fields[idx].value)
	case "a":
		m.form = &editForm{
			title: "Add proxy",
			fields: []*field{
				{label: "name"},
				{label: "addr"},
				{label: "user"},
				{label: "pass"},
			},
			onSave: func(v []string) error { return m.addProxy(v) },
		}
		m.form.fields[1].set("127.0.0.1:1080")
	case "d", "delete":
		m.deleteProxy()
	case "s":
		cmd = m.startEngine()
	case "x":
		cmd = m.stopEngine()
	}
	return m, cmd
}

func (m *Model) settingFields() []*field {
	var out []*field
	if len(m.cfg.Proxies) > 1 {
		names := make([]string, len(m.cfg.Proxies))
		for i, p := range m.cfg.Proxies {
			names[i] = p.Name
		}
		out = append(out, &field{key: "default_proxy", label: "default_proxy", value: m.cfg.DefaultProxy, cycle: names})
	}
	for _, p := range m.cfg.Proxies {
		out = append(out, &field{key: "proxy:" + p.Name, label: "proxy/" + p.Name, value: p.Addr})
	}
	out = append(out,
		&field{key: "default_action", label: "default_action", value: strings.ToUpper(m.cfg.DefaultAction), cycle: []string{"DIRECT", "PROXY", "BLOCK"}},
		&field{key: "tcp_relay_port", label: "tcp_relay_port", value: fmt.Sprint(m.cfg.TCPRelayPort)},
		&field{key: "udp_relay_port", label: "udp_relay_port", value: fmt.Sprint(m.cfg.UDPRelayPort)},
		&field{key: "cgroup_path", label: "cgroup_path", value: m.cfg.CgroupPath},
		&field{key: "log_level", label: "log_level", value: logLevelName(m.cfg.LogLevel), cycle: []string{"OFF", "BLOCK", "PROXY", "ALL"}},
	)
	return out
}

// applyProxies pushes the current proxy list into the engine and re-expands rules.
func (m *Model) applyProxies() error {
	proxies := make([]engine.Proxy, 0, len(m.cfg.Proxies))
	for _, p := range m.cfg.Proxies {
		proxies = append(proxies, engine.Proxy{Name: p.Name, Client: socks.Client{Addr: p.Addr, User: p.User, Pass: p.Pass}})
	}
	m.eng.SetProxies(proxies, m.cfg.DefaultProxy)
	if err := m.eng.ApplyRules(m.rules); err != nil {
		return err
	}
	return config.Save(m.cfgPath, *m.cfg)
}

func (m *Model) addProxy(v []string) error {
	name := strings.TrimSpace(v[0])
	addr := strings.TrimSpace(v[1])
	if name == "" || addr == "" {
		return fmt.Errorf("proxy needs a name and an address")
	}
	if _, ok := m.cfg.ProxyByName(name); ok {
		return fmt.Errorf("proxy %q already exists", name)
	}
	m.cfg.Proxies = append(m.cfg.Proxies, config.Proxy{Name: name, Addr: addr, User: strings.TrimSpace(v[2]), Pass: v[3]})
	return m.applyProxies()
}

func (m *Model) deleteProxy() {
	fields := m.settingFields()
	if m.setCur < 0 || m.setCur >= len(fields) {
		return
	}
	key := fields[m.setCur].key
	if !strings.HasPrefix(key, "proxy:") {
		m.errMsg = "select a proxy/<name> field to delete"
		return
	}
	if len(m.cfg.Proxies) <= 1 {
		m.errMsg = "at least one proxy is required"
		return
	}
	name := strings.TrimPrefix(key, "proxy:")
	kept := m.cfg.Proxies[:0]
	for _, p := range m.cfg.Proxies {
		if p.Name != name {
			kept = append(kept, p)
		}
	}
	m.cfg.Proxies = kept
	m.cfg.Migrate()
	if m.setCur >= len(m.settingFields()) {
		m.setCur = len(m.settingFields()) - 1
	}
	if err := m.applyProxies(); err != nil {
		m.errMsg = err.Error()
	}
}

func (m *Model) updateForm(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	f := m.form
	cur := f.fields[f.cur]
	switch msg.String() {
	case "esc":
		m.form = nil
		return m, nil
	case "tab", "down":
		f.cur = (f.cur + 1) % len(f.fields)
	case "shift+tab", "up":
		f.cur = (f.cur + len(f.fields) - 1) % len(f.fields)
	case "left":
		cur.left()
	case "right":
		cur.right()
	case "home", "ctrl+a":
		cur.home()
	case "end", "ctrl+e":
		cur.end()
	case "backspace":
		cur.backspace()
	case "delete":
		cur.del()
	case "enter":
		if f.cur < len(f.fields)-1 {
			f.cur++
			break
		}
		if err := f.onSave(m.formValues()); err != nil {
			m.errMsg = err.Error()
			break
		}
		m.form = nil
		m.errMsg = ""
	case " ":
		if len(cur.cycle) > 0 {
			cur.set(nextCycle(cur.cycle, cur.value))
			break
		}
		cur.insert(' ')
	default:
		if len(msg.Runes) > 0 {
			cur.insert(msg.Runes[0])
		}
	}
	return m, nil
}

func nextCycle(list []string, cur string) string {
	for i, v := range list {
		if strings.EqualFold(v, cur) {
			return list[(i+1)%len(list)]
		}
	}
	return list[0]
}

func (m *Model) formValues() []string {
	out := make([]string, len(m.form.fields))
	for i, f := range m.form.fields {
		out[i] = strings.TrimSpace(f.value)
	}
	return out
}

func (m *Model) saveRule(idx int, v []string) error {
	if _, err := rule.ParseAction(v[4]); err != nil {
		return err
	}
	proxy := ""
	if len(v) > 5 {
		proxy = strings.TrimSpace(v[5])
	}
	r := rule.Rule{
		Process:  v[0],
		Hosts:    v[1],
		Ports:    v[2],
		Protocol: strings.ToUpper(v[3]),
		Action:   strings.ToUpper(v[4]),
		Proxy:    proxy,
		Enabled:  true,
	}
	switch strings.ToUpper(r.Protocol) {
	case "TCP", "UDP", "BOTH":
	default:
		return fmt.Errorf("protocol must be TCP, UDP or BOTH")
	}
	if r.Process == "" {
		return fmt.Errorf("process must not be empty")
	}
	if r.Proxy != "" && !strings.EqualFold(r.Action, "PROXY") {
		r.Proxy = ""
	}
	if r.Proxy != "" {
		if _, ok := m.cfg.ProxyByName(r.Proxy); !ok {
			return fmt.Errorf("unknown proxy %q (see Settings)", r.Proxy)
		}
	}
	if idx >= 0 && idx < len(m.rules) {
		r.ID = m.rules[idx].ID
		r.Enabled = m.rules[idx].Enabled
		m.rules[idx] = r
	} else {
		r.ID = m.freeID()
		m.rules = append(m.rules, r)
	}
	return m.applyRules()
}

func (m *Model) saveSetting(key, value string) error {
	switch {
	case key == "default_proxy":
		if _, ok := m.cfg.ProxyByName(value); !ok {
			return fmt.Errorf("unknown proxy %q", value)
		}
		m.cfg.DefaultProxy = value
		return m.applyProxies()
	case strings.HasPrefix(key, "proxy:"):
		name := strings.TrimPrefix(key, "proxy:")
		for i := range m.cfg.Proxies {
			if m.cfg.Proxies[i].Name == name {
				m.cfg.Proxies[i].Addr = strings.TrimSpace(value)
				return m.applyProxies()
			}
		}
		return fmt.Errorf("unknown proxy %q", name)
	case key == "default_action":
		a, err := rule.ParseAction(value)
		if err != nil {
			return err
		}
		m.cfg.DefaultAction = strings.ToUpper(value)
		if err := m.eng.SetDefaultAction(a); err != nil {
			return err
		}
	case key == "tcp_relay_port":
		var p uint16
		if _, err := fmt.Sscanf(value, "%d", &p); err != nil || p == 0 {
			return fmt.Errorf("invalid port")
		}
		m.cfg.TCPRelayPort = p
	case key == "udp_relay_port":
		var p uint16
		if _, err := fmt.Sscanf(value, "%d", &p); err != nil || p == 0 {
			return fmt.Errorf("invalid port")
		}
		m.cfg.UDPRelayPort = p
	case key == "cgroup_path":
		m.cfg.CgroupPath = value
	case key == "log_level":
		lv := logLevelValue(value)
		if lv < 0 {
			return fmt.Errorf("log level must be OFF, BLOCK, PROXY or ALL")
		}
		m.cfg.LogLevel = lv
		if err := m.eng.SetLogLevel(uint32(lv)); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown setting")
	}
	return config.Save(m.cfgPath, *m.cfg)
}

func logLevelValue(s string) int {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "OFF":
		return 0
	case "BLOCK":
		return 1
	case "PROXY":
		return 2
	case "ALL":
		return 3
	}
	return -1
}

func (m *Model) applyRules() error {
	m.cfg.Rules = m.rules
	if err := m.eng.ApplyRules(m.rules); err != nil {
		m.errMsg = err.Error()
		return err
	}
	m.errMsg = ""
	return config.Save(m.cfgPath, *m.cfg)
}

func (m *Model) startEngine() tea.Cmd {
	if m.eng.Running() {
		m.status = "already running"
		return nil
	}
	if m.busy {
		return nil
	}
	m.busy = true
	m.status = "starting: loading bpf, attaching hooks, starting relays…"
	eng := m.eng
	return func() tea.Msg {
		return startedMsg{err: eng.Start()}
	}
}

func (m *Model) stopEngine() tea.Cmd {
	if !m.eng.Running() {
		m.status = "already stopped"
		return nil
	}
	if m.busy {
		return nil
	}
	m.busy = true
	m.status = "stopping: detaching bpf hooks and closing relays…"
	eng := m.eng
	tcpPort := m.cfg.TCPRelayPort
	udpPort := m.cfg.UDPRelayPort
	return func() tea.Msg {
		eng.Stop()
		return stoppedMsg{report: verifyStopped(eng, tcpPort, udpPort)}
	}
}

// verifyStopped checks the relays are actually gone (their ports are free
// again) and produces a human readable report.
func verifyStopped(eng *engine.Engine, tcpPort, udpPort uint16) string {
	var parts []string
	if ln, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", tcpPort)); err == nil {
		ln.Close()
		parts = append(parts, fmt.Sprintf("tcp relay :%d stopped", tcpPort))
	} else {
		parts = append(parts, fmt.Sprintf("tcp relay :%d STILL OPEN", tcpPort))
	}
	if pc, err := net.ListenPacket("udp4", fmt.Sprintf("127.0.0.1:%d", udpPort)); err == nil {
		pc.Close()
		parts = append(parts, fmt.Sprintf("udp relay :%d stopped", udpPort))
	} else {
		parts = append(parts, fmt.Sprintf("udp relay :%d STILL OPEN", udpPort))
	}
	if eng.Running() {
		parts = append(parts, "engine STILL RUNNING")
	} else {
		parts = append(parts, "bpf hooks detached")
	}
	return "stopped: " + strings.Join(parts, "; ")
}

func (m *Model) View() string {
	if m.fullLogs {
		return m.viewFullLogs()
	}
	var b strings.Builder
	b.WriteString(styleTitle.Render(" ebpfproxy · eBPF TCP/UDP process traffic manager ") + "\n")

	state := styleBad.Render("STOPPED")
	if m.eng.Running() {
		state = styleOK.Render("RUNNING")
	}
	proxy := ""
	if p, ok := m.cfg.ProxyByName(m.cfg.DefaultProxy); ok {
		proxy = p.Name + "=" + p.Addr
	}
	b.WriteString(fmt.Sprintf(" state=%s  proxy=%s  default=%s  proxies=%d\n\n",
		state, proxy, strings.ToUpper(m.cfg.DefaultAction), len(m.cfg.Proxies)))

	for i, name := range tabNames {
		if i == m.active {
			b.WriteString(styleTabOn.Render(name))
		} else {
			b.WriteString(styleTabOff.Render(name))
		}
	}
	b.WriteString("\n\n")

	switch m.active {
	case tabStatus:
		b.WriteString(m.viewStatus())
	case tabRules:
		b.WriteString(m.viewRules())
	case tabLogs:
		b.WriteString(m.viewLogs())
	case tabSettings:
		b.WriteString(m.viewSettings())
	}

	b.WriteString("\n")
	if m.errMsg != "" {
		b.WriteString(styleBad.Render(" ✗ "+m.errMsg) + "\n")
	} else if m.status != "" {
		b.WriteString(styleOK.Render(" "+m.status) + "\n")
	}
	b.WriteString(styleHelp.Render(" " + m.help()))

	out := b.String()
	if m.form != nil {
		return m.overlay(out)
	}
	return out
}

func (m *Model) help() string {
	base := "1-4/tab: tabs · s: start · x: stop · q: quit"
	switch m.active {
	case tabRules:
		return "↑/↓: select · k/j: move up/down · a: add · e/enter: edit · d: delete · space: toggle · " + base
	case tabSettings:
		return "↑/↓: select · enter: edit · a: add proxy · d: delete proxy · " + base
	case tabLogs:
		return "j/k or ↑/↓: scroll · enter/f: fullscreen · c: clear · " + base
	}
	return base
}

func (m *Model) viewStatus() string {
	st := m.eng.Stats()
	var b strings.Builder
	b.WriteString(styleHeader.Render("Counters") + "\n")
	rows := [][2]string{
		{"direct", fmt.Sprint(st[0])},
		{"proxied", fmt.Sprint(st[1])},
		{"blocked", fmt.Sprint(st[2])},
		{"tcp proxied", fmt.Sprint(st[3])},
		{"udp proxied", fmt.Sprint(st[4])},
	}
	for _, r := range rows {
		b.WriteString(fmt.Sprintf("  %-20s %s\n", r[0], r[1]))
	}
	b.WriteString("\n")
	b.WriteString(styleHeader.Render("Runtime") + "\n")
	b.WriteString(fmt.Sprintf("  %-20s %s\n", "tcp relay", fmt.Sprintf("127.0.0.1:%d", m.cfg.TCPRelayPort)))
	b.WriteString(fmt.Sprintf("  %-20s %s\n", "udp relay", fmt.Sprintf("127.0.0.1:%d", m.cfg.UDPRelayPort)))
	b.WriteString(fmt.Sprintf("  %-20s %s\n", "cgroup", m.cfg.CgroupPath))
	b.WriteString(fmt.Sprintf("  %-20s %s\n", "log level", logLevelName(m.cfg.LogLevel)))
	return b.String()
}

func (m *Model) viewRules() string {
	var b strings.Builder
	b.WriteString(styleHeader.Render(fmt.Sprintf("%-5s %-16s %-18s %-12s %-6s %-16s %s", "#", "PROCESS", "HOSTS", "PORTS", "PROTO", "ACTION", "ON")) + "\n")
	if len(m.rules) == 0 {
		b.WriteString(styleOverlay.Render("  no rules; press 'a' to add one (unmatched traffic is DIRECT by default)") + "\n")
		return b.String()
	}
	for i, r := range m.rules {
		on := "yes"
		if !r.Enabled {
			on = "no"
		}
		action := strings.ToUpper(r.Action)
		if r.Proxy != "" {
			action += "@" + r.Proxy
		}
		line := fmt.Sprintf("%-5d %-16s %-18s %-12s %-6s %-16s %s",
			i+1, truncate(r.Process, 16), truncate(r.Hosts, 18), truncate(r.Ports, 12),
			strings.ToUpper(r.Protocol), truncate(action, 16), on)
		if i == m.cursor {
			line = styleSel.Render(line)
		}
		b.WriteString(line + "\n")
	}
	b.WriteString(styleOverlay.Render("\n rules are checked top to bottom; the first match wins") + "\n")
	return b.String()
}

// window returns up to max log lines ending at the current scroll offset
// (0 = newest at the bottom).
func (m *Model) window(max int) []string {
	n := len(m.logs)
	if n == 0 || max <= 0 {
		return nil
	}
	off := m.logScroll
	if off > n-max {
		off = n - max
	}
	if off < 0 {
		off = 0
	}
	end := n - off
	start := end - max
	if start < 0 {
		start = 0
	}
	out := make([]string, end-start)
	copy(out, m.logs[start:end])
	return out
}

func (m *Model) viewLogs() string {
	max := m.height - 12
	if max < 3 {
		max = 3
	}
	lines := m.window(max)
	if len(lines) == 0 {
		return styleOverlay.Render(" no traffic events yet (set a log level in Settings; Enter for full screen)") + "\n"
	}
	hint := fmt.Sprintf(" lines %d/%d · scroll %d · enter: fullscreen", len(lines), len(m.logs), m.logScroll)
	return strings.Join(lines, "\n") + "\n" + styleOverlay.Render(hint) + "\n"
}

func (m *Model) viewFullLogs() string {
	max := m.height - 2
	if max < 1 {
		max = 1
	}
	lines := m.window(max)
	var b strings.Builder
	b.WriteString(styleHeader.Render(" Traffic logs · j/k: scroll · g/G: top/bottom · c: clear · q: back ") + "\n")
	if len(lines) == 0 {
		b.WriteString(styleOverlay.Render(" no traffic events yet") + "\n")
		return b.String()
	}
	return b.String() + strings.Join(lines, "\n") + "\n"
}

func logLevelName(l int) string {
	switch l {
	case 0:
		return "OFF"
	case 1:
		return "BLOCK"
	case 2:
		return "PROXY"
	case 3:
		return "ALL"
	}
	return fmt.Sprint(l)
}

func (m *Model) viewSettings() string {
	var b strings.Builder
	for i, f := range m.settingFields() {
		line := fmt.Sprintf("%-18s %s", f.label, f.value)
		if i == m.setCur {
			line = styleSel.Render("> " + line)
		} else {
			line = "  " + line
		}
		b.WriteString(line + "\n")
	}
	return b.String()
}

func (m *Model) overlay(bg string) string {
	f := m.form
	var b strings.Builder
	b.WriteString(styleHeader.Render(f.title) + "\n\n")
	for i, fld := range f.fields {
		val := fld.value
		if i == f.cur {
			val = styleFldOn.Render(withCursor(fld))
		} else {
			val = styleFldOff.Render(val)
		}
		line := fmt.Sprintf("%-10s %s", fld.label+":", val)
		if i == f.cur {
			line = "> " + line
		} else {
			line = "  " + line
		}
		b.WriteString(line + "\n")
	}
	if len(f.fields) == 1 && len(f.fields[0].cycle) > 0 {
		b.WriteString(styleHelp.Render("\n space cycles values") + "\n")
	}
	for _, fld := range f.fields {
		if fld.label == "proxy" {
			b.WriteString(styleHelp.Render(fmt.Sprintf("\n proxy: a name, empty = default (%s); list in Settings\n", m.cfg.DefaultProxy)))
			break
		}
	}
	b.WriteString(styleHelp.Render("\n tab: next · enter: save · esc: cancel") + "\n")
	return bg + "\n" + styleModal.Render(b.String())
}

func withCursor(f *field) string {
	rs := []rune(f.value)
	cur := f.cursor
	if cur > len(rs) {
		cur = len(rs)
	}
	left := string(rs[:cur])
	right := string(rs[cur:])
	return left + "▏" + right
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	if n <= 1 {
		return string(r[:n])
	}
	return string(r[:n-1]) + "…"
}
