package tui

import (
	"encoding/json"
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
	"github.com/osintfw/osint/pkg/types"
)

var (
	titleStyle       = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#7D56F4")).MarginLeft(2)
	statusStyle      = lipgloss.NewStyle().Background(lipgloss.Color("#333333")).Foreground(lipgloss.Color("#FFFFFF"))
	activeTabStyle   = lipgloss.NewStyle().Bold(true).Background(lipgloss.Color("#7D56F4")).Foreground(lipgloss.Color("#FFFFFF")).Padding(0, 2)
	inactiveTabStyle = lipgloss.NewStyle().Padding(0, 2)
	moduleTitleStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#04B575"))
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
	Up:     key.NewBinding(key.WithKeys("up", "k"), key.WithHelp("↑/k", "up")),
	Down:   key.NewBinding(key.WithKeys("down", "j"), key.WithHelp("↓/j", "down")),
	Left:   key.NewBinding(key.WithKeys("left", "h"), key.WithHelp("←/h", "prev tab")),
	Right:  key.NewBinding(key.WithKeys("right", "l"), key.WithHelp("→/l", "next tab")),
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
	tabs       []string
	activeTab  int
	width      int
	height     int
	spinner    spinner.Model
	moduleList list.Model
	viewport   viewport.Model
	input      textinput.Model
	results    map[string]types.ModuleResult
	status     string
	ready      bool
	help       help.Model
	keys       keyMap
	scanning   bool
}

type scanMsg struct {
	result types.ModuleResult
}

func New() Model {
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
	ti.Focus()

	return Model{
		tabs:      []string{"Dashboard", "Results", "Logs"},
		spinner:   s,
		moduleList: l,
		input:     ti,
		results:   make(map[string]types.ModuleResult),
		status:    "Ready - Press / to focus search, q to quit",
		help:      help.New(),
		keys:      keys,
	}
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(m.spinner.Tick, textinput.Blink)
}

func runScan(target string) tea.Cmd {
	return func() tea.Msg {
		time.Sleep(500 * time.Millisecond)
		return scanMsg{result: types.ModuleResult{
			Module: "demo",
			Target: target,
			Data:   map[string]interface{}{"status": "scan completed"},
		}}
	}
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		if !m.ready {
			m.viewport = viewport.New(msg.Width-34, msg.Height-10)
			m.ready = true
		} else {
			m.viewport.Width = msg.Width - 34
			m.viewport.Height = msg.Height - 10
		}
		m.moduleList.SetSize(30, msg.Height-10)
		m.input.Width = msg.Width - 6
		m.help.Width = msg.Width
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
		}
		if key.Matches(msg, m.keys.Right) {
			m.activeTab = (m.activeTab + 1) % len(m.tabs)
		}
		if key.Matches(msg, m.keys.Enter) && m.input.Value() != "" {
			m.scanning = true
			m.status = "Scanning " + m.input.Value() + "..."
			cmds = append(cmds, runScan(m.input.Value()))
		}
		if key.Matches(msg, m.keys.Search) {
			m.input.Focus()
		}

	case scanMsg:
		m.scanning = false
		m.results[msg.result.Module] = msg.result
		m.status = fmt.Sprintf("Received %s results", msg.result.Module)
		m.updateViewport()
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
	var sb strings.Builder
	for mod, res := range m.results {
		sb.WriteString(moduleTitleStyle.Render(mod) + " - " + res.Target + "\n")
		if res.Error != nil {
			sb.WriteString("Error: " + res.Error.Error() + "\n")
		} else {
			data, _ := json.MarshalIndent(res.Data, "", "  ")
			sb.WriteString(string(data) + "\n")
		}
		sb.WriteString("\n")
	}
	m.viewport.SetContent(sb.String())
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
