package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/osintfw/osint/internal/config"
	"github.com/osintfw/osint/internal/modules/domain"
	"github.com/osintfw/osint/internal/modules/email"
	"github.com/osintfw/osint/internal/modules/file"
	"github.com/osintfw/osint/internal/modules/github"
	"github.com/osintfw/osint/internal/modules/ip"
	"github.com/osintfw/osint/internal/modules/ssl"
	"github.com/osintfw/osint/internal/modules/username"
	"github.com/osintfw/osint/internal/modules/web"
	"github.com/osintfw/osint/pkg/types"
)

var (
	titleStyle       = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#7D56F4")).MarginLeft(2)
	statusStyle      = lipgloss.NewStyle().Background(lipgloss.Color("#333333")).Foreground(lipgloss.Color("#FFFFFF"))
	activeTabStyle   = lipgloss.NewStyle().Bold(true).Background(lipgloss.Color("#7D56F4")).Foreground(lipgloss.Color("#FFFFFF")).Padding(0, 2)
	inactiveTabStyle = lipgloss.NewStyle().Padding(0, 2)
	moduleTitleStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#04B575"))
	errorStyle       = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF5555"))
	keyStyle         = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF79C6"))
	labelStyle       = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#8BE9FD"))
)

type keyMap struct {
	Up     key.Binding
	Down   key.Binding
	Left   key.Binding
	Right  key.Binding
	Search key.Binding
	Quit   key.Binding
	Enter  key.Binding
	Tab    key.Binding
}

func (k keyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Up, k.Down, k.Enter, k.Quit}
}

func (k keyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{k.Up, k.Down, k.Left, k.Right, k.Tab},
		{k.Enter, k.Search, k.Quit},
	}
}

var keys = keyMap{
	Up:     key.NewBinding(key.WithKeys("up", "k"), key.WithHelp("up/k", "up")),
	Down:   key.NewBinding(key.WithKeys("down", "j"), key.WithHelp("down/j", "down")),
	Left:   key.NewBinding(key.WithKeys("left", "h"), key.WithHelp("left/h", "prev tab")),
	Right:  key.NewBinding(key.WithKeys("right", "l"), key.WithHelp("right/l", "next tab")),
	Search: key.NewBinding(key.WithKeys("/"), key.WithHelp("/", "search")),
	Quit:   key.NewBinding(key.WithKeys("q", "ctrl+c"), key.WithHelp("q", "quit")),
	Enter:  key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "scan")),
	Tab:    key.NewBinding(key.WithKeys("tab"), key.WithHelp("tab", "next")),
}

type moduleItem struct {
	title       string
	description string
}

func (i moduleItem) FilterValue() string { return i.title }
func (i moduleItem) Title() string       { return i.title }
func (i moduleItem) Description() string { return i.description }

type Model struct {
	tabs        []string
	activeTab   int
	width       int
	height      int
	spinner     spinner.Model
	moduleList  list.Model
	viewport    viewport.Model
	input       textinput.Model
	results     []types.ModuleResult
	logs        []string
	status      string
	ready       bool
	help        help.Model
	keys        keyMap
	scanning    bool
	selectedMod string
	cfg         *config.Config
}

type scanMsg struct {
	result types.ModuleResult
}

func New(cfg *config.Config) Model {
	if cfg == nil {
		cfg = &config.Config{}
		cfg.Concurrency.Workers = 10
		cfg.Concurrency.Timeout = 30
	}

	s := spinner.New()
	s.Spinner = spinner.Dot

	items := []list.Item{
		moduleItem{title: "Domain", description: "DNS, WHOIS, RDAP, ASN"},
		moduleItem{title: "Web", description: "Headers, Tech, Content"},
		moduleItem{title: "SSL", description: "Certificates, TLS, Ciphers"},
		moduleItem{title: "IP", description: "Geo, Reverse DNS, ASN"},
		moduleItem{title: "Email", description: "Validation, MX, SPF, DMARC"},
		moduleItem{title: "Username", description: "Social platform checks"},
		moduleItem{title: "GitHub", description: "Profile, Repos, Orgs"},
		moduleItem{title: "File", description: "Hashes, Entropy, Metadata"},
	}

	l := list.New(items, list.NewDefaultDelegate(), 0, 0)
	l.Title = "Modules"
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(false)

	ti := textinput.New()
	ti.Placeholder = "Enter target and press Enter..."
	ti.CharLimit = 256
	ti.Width = 50

	return Model{
		tabs:      []string{"Dashboard", "Results", "Logs"},
		spinner:   s,
		moduleList: l,
		input:     ti,
		results:   make([]types.ModuleResult, 0),
		logs:      make([]string, 0),
		status:    "Ready -- select a module, type a target, press Enter",
		help:      help.New(),
		keys:      keys,
		cfg:       cfg,
	}
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(m.spinner.Tick, textinput.Blink)
}

func runModule(modName, target string, cfg *config.Config) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.Concurrency.Timeout)*time.Second)
		defer cancel()

		var res types.ModuleResult
		switch modName {
		case "Domain":
			res = domain.Run(ctx, target)
		case "Web":
			res = web.Run(ctx, target)
		case "SSL":
			res = ssl.Run(ctx, target)
		case "IP":
			res = ip.Run(ctx, target, cfg)
		case "Email":
			res = email.Run(ctx, target)
		case "Username":
			res = username.Run(ctx, target)
		case "GitHub":
			res = github.Run(ctx, target)
		case "File":
			res = file.Analyze(target)
		default:
			res = types.ModuleResult{
				Module: modName,
				Target: target,
				Error:  fmt.Errorf("unknown module: %s", modName),
			}
		}
		if res.Timestamp.IsZero() {
			res.Timestamp = time.Now()
		}
		return scanMsg{result: res}
	}
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		if !m.ready {
			m.viewport = viewport.New(msg.Width-36, msg.Height-12)
			m.ready = true
		} else {
			m.viewport.Width = msg.Width - 36
			m.viewport.Height = msg.Height - 12
		}
		m.moduleList.SetSize(34, msg.Height-12)
		m.input.Width = msg.Width - 6
		m.help.Width = msg.Width
		m.updateViewport()
		return m, nil

	case tea.KeyMsg:
		if key.Matches(msg, m.keys.Quit) {
			return m, tea.Quit
		}
		if key.Matches(msg, m.keys.Left) {
			m.activeTab--
			if m.activeTab < 0 {
				m.activeTab = len(m.tabs) - 1
			}
			m.updateViewport()
		}
		if key.Matches(msg, m.keys.Right) {
			m.activeTab = (m.activeTab + 1) % len(m.tabs)
			m.updateViewport()
		}
		if key.Matches(msg, m.keys.Enter) && m.input.Value() != "" && !m.scanning {
			if item, ok := m.moduleList.SelectedItem().(moduleItem); ok {
				m.selectedMod = item.title
				m.scanning = true
				m.status = fmt.Sprintf("Running %s on %s...", m.selectedMod, m.input.Value())
				m.logs = append(m.logs, fmt.Sprintf("[%s] Starting %s scan on %s", time.Now().Format("15:04:05"), m.selectedMod, m.input.Value()))
				cmds = append(cmds, runModule(m.selectedMod, m.input.Value(), m.cfg))
			}
		}
		if key.Matches(msg, m.keys.Search) {
			m.input.Focus()
		}

	case scanMsg:
		m.scanning = false
		m.results = append(m.results, msg.result)
		if msg.result.Error != nil {
			m.status = fmt.Sprintf("%s scan failed: %v", msg.result.Module, msg.result.Error)
			m.logs = append(m.logs, fmt.Sprintf("[%s] ERROR: %s -- %v", time.Now().Format("15:04:05"), msg.result.Module, msg.result.Error))
		} else {
			m.status = fmt.Sprintf("%s scan completed", msg.result.Module)
			m.logs = append(m.logs, fmt.Sprintf("[%s] OK: %s scan completed", time.Now().Format("15:04:05"), msg.result.Module))
		}
		m.updateViewport()
		m.input.SetValue("")
	}

	var cmd tea.Cmd
	m.spinner, cmd = m.spinner.Update(msg)
	cmds = append(cmds, cmd)

	m.moduleList, cmd = m.moduleList.Update(msg)
	cmds = append(cmds, cmd)

	m.viewport, cmd = m.viewport.Update(msg)
	cmds = append(cmds, cmd)

	m.input, cmd = m.input.Update(msg)
	cmds = append(cmds, cmd)

	return m, tea.Batch(cmds...)
}

func (m *Model) updateViewport() {
	switch m.activeTab {
	case 0:
		m.viewport.SetContent(m.dashboardView())
	case 1:
		m.viewport.SetContent(m.resultsView())
	case 2:
		m.viewport.SetContent(m.logsView())
	}
}

func (m Model) dashboardView() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("OSINT Framework Dashboard") + "\n\n")
	b.WriteString("Welcome to the interactive OSINT dashboard.\n\n")
	b.WriteString(labelStyle.Render("How to use:") + "\n")
	b.WriteString("  1. Select a module from the left panel using up/down\n")
	b.WriteString("  2. Type a target in the input field (press / to focus)\n")
	b.WriteString("  3. Press Enter to run the scan\n")
	b.WriteString("  4. View results in the Results tab\n\n")
	b.WriteString(labelStyle.Render("Modules:") + "\n")
	for _, item := range m.moduleList.Items() {
		if mi, ok := item.(moduleItem); ok {
			b.WriteString("  " + keyStyle.Render(mi.title) + " -- " + mi.description + "\n")
		}
	}
	return b.String()
}

func (m Model) resultsView() string {
	if len(m.results) == 0 {
		return "No results yet. Select a module, enter a target, and press Enter."
	}
	var b strings.Builder
	for _, r := range m.results {
		b.WriteString(moduleTitleStyle.Render(fmt.Sprintf("[%s] %s", r.Module, r.Target)) + "\n")
		b.WriteString(fmt.Sprintf("Time: %s\n", r.Timestamp.Format("15:04:05")))
		if r.Error != nil {
			b.WriteString(errorStyle.Render("Error: "+r.Error.Error()) + "\n")
		} else {
			b.WriteString(m.formatData(r.Data, 0))
		}
		b.WriteString(strings.Repeat("-", m.viewport.Width-2) + "\n\n")
	}
	return b.String()
}

func (m Model) logsView() string {
	if len(m.logs) == 0 {
		return "No logs yet."
	}
	return strings.Join(m.logs, "\n")
}

func (m Model) formatData(data map[string]interface{}, indent int) string {
	var b strings.Builder
	prefix := strings.Repeat("  ", indent)
	for k, v := range data {
		switch val := v.(type) {
		case map[string]interface{}:
			b.WriteString(fmt.Sprintf("%s%s:\n", prefix, labelStyle.Render(k)))
			b.WriteString(m.formatData(val, indent+1))
		case []interface{}:
			b.WriteString(fmt.Sprintf("%s%s:\n", prefix, labelStyle.Render(k)))
			for _, item := range val {
				b.WriteString(fmt.Sprintf("%s  - %v\n", prefix, item))
			}
		case []string:
			b.WriteString(fmt.Sprintf("%s%s:\n", prefix, labelStyle.Render(k)))
			for _, item := range val {
				b.WriteString(fmt.Sprintf("%s  - %s\n", prefix, item))
			}
		case map[string]string:
			b.WriteString(fmt.Sprintf("%s%s:\n", prefix, labelStyle.Render(k)))
			for kk, vv := range val {
				b.WriteString(fmt.Sprintf("%s  %s: %s\n", prefix, kk, vv))
			}
		default:
			b.WriteString(fmt.Sprintf("%s%s: %v\n", prefix, labelStyle.Render(k), val))
		}
	}
	return b.String()
}

func (m Model) View() string {
	if !m.ready {
		return "Initializing..."
	}

	header := lipgloss.JoinHorizontal(lipgloss.Top,
		titleStyle.Render("OSINT Framework"),
		"  ",
		m.spinner.View(),
	)

	var tabs []string
	for i, t := range m.tabs {
		if i == m.activeTab {
			tabs = append(tabs, activeTabStyle.Render(t))
		} else {
			tabs = append(tabs, inactiveTabStyle.Render(t))
		}
	}
	tabBar := lipgloss.JoinHorizontal(lipgloss.Top, tabs...)

	inputView := m.input.View()
	body := lipgloss.JoinHorizontal(lipgloss.Top, m.moduleList.View(), m.viewport.View())
	statusBar := statusStyle.Width(m.width).Render(m.status)
	helpView := m.help.View(m.keys)

	return lipgloss.JoinVertical(lipgloss.Left,
		header,
		tabBar,
		inputView,
		body,
		statusBar,
		helpView,
	)
}
