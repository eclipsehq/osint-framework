package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/osintfw/osint/internal/config"
	"github.com/osintfw/osint/internal/logger"
	"github.com/osintfw/osint/internal/modules/domain"
	"github.com/osintfw/osint/internal/modules/email"
	"github.com/osintfw/osint/internal/modules/file"
	"github.com/osintfw/osint/internal/modules/ip"
	"github.com/osintfw/osint/internal/modules/ssl"
	"github.com/osintfw/osint/internal/modules/username"
	"github.com/osintfw/osint/internal/modules/web"
	"github.com/osintfw/osint/internal/output"
	"github.com/osintfw/osint/internal/runner"
	"github.com/osintfw/osint/internal/tui"
	"github.com/osintfw/osint/pkg/types"
	"github.com/spf13/cobra"
)

var (
	cfgPath string
	format  string
	outFile string
)

var cfg *config.Config
var log *slog.Logger

func main() {
	root := &cobra.Command{
		Use:   "osint",
		Short: "A production-quality OSINT framework",
		Long: `A modular, cross-platform open-source intelligence framework
for collecting publicly available information.`,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return initConfig()
		},
		SilenceUsage: true,
	}

	root.PersistentFlags().StringVarP(&cfgPath, "config", "c", "configs/config.yaml", "config file path")
	root.PersistentFlags().StringVarP(&format, "format", "f", "json", "output format (json, csv, markdown, html)")
	root.PersistentFlags().StringVarP(&outFile, "output", "o", "", "output file")

	root.AddCommand(domainCmd())
	root.AddCommand(ipCmd())
	root.AddCommand(emailCmd())
	root.AddCommand(usernameCmd())
	root.AddCommand(urlCmd())
	root.AddCommand(fileCmd())
	root.AddCommand(reportCmd())
	root.AddCommand(tuiCmd())

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func initConfig() error {
	var err error
	cfg, err = config.Load(cfgPath)
	if err != nil {
		cfg = &config.Config{}
		cfg.Concurrency.Workers = 10
		cfg.Concurrency.Timeout = 30
		cfg.Logging.Level = "info"
		cfg.Logging.Format = "json"
	}
	log = logger.Init(cfg.Logging.Level, cfg.Logging.Format)
	return nil
}

func domainCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "domain [target]",
		Short: "Run domain reconnaissance",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			target := args[0]
			r := runner.New(cfg.Concurrency.Workers, time.Duration(cfg.Concurrency.Timeout)*time.Second)
			tasks := []runner.Task{
				{Name: "domain", Fn: func(ctx context.Context) types.ModuleResult {
					return domain.Run(ctx, target)
				}},
			}
			handleResults(r.Run(context.Background(), tasks))
		},
	}
}

func ipCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ip [target]",
		Short: "Run IP reconnaissance",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			target := args[0]
			r := runner.New(cfg.Concurrency.Workers, time.Duration(cfg.Concurrency.Timeout)*time.Second)
			tasks := []runner.Task{
				{Name: "ip", Fn: func(ctx context.Context) types.ModuleResult {
					return ip.Run(ctx, target, cfg)
				}},
			}
			handleResults(r.Run(context.Background(), tasks))
		},
	}
}

func emailCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "email [target]",
		Short: "Run email reconnaissance",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			target := args[0]
			r := runner.New(cfg.Concurrency.Workers, time.Duration(cfg.Concurrency.Timeout)*time.Second)
			tasks := []runner.Task{
				{Name: "email", Fn: func(ctx context.Context) types.ModuleResult {
					return email.Run(ctx, target)
				}},
			}
			handleResults(r.Run(context.Background(), tasks))
		},
	}
}

func usernameCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "username [target]",
		Short: "Check username availability",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			target := args[0]
			r := runner.New(cfg.Concurrency.Workers, time.Duration(cfg.Concurrency.Timeout)*time.Second)
			tasks := []runner.Task{
				{Name: "username", Fn: func(ctx context.Context) types.ModuleResult {
					return username.Run(ctx, target)
				}},
			}
			handleResults(r.Run(context.Background(), tasks))
		},
	}
}

func urlCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "url [target]",
		Short: "Analyze URL (web + ssl)",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			target := args[0]
			r := runner.New(cfg.Concurrency.Workers, time.Duration(cfg.Concurrency.Timeout)*time.Second)
			tasks := []runner.Task{
				{Name: "web", Fn: func(ctx context.Context) types.ModuleResult {
					return web.Run(ctx, target)
				}},
				{Name: "ssl", Fn: func(ctx context.Context) types.ModuleResult {
					u, _ := url.Parse(target)
					if u != nil && u.Host != "" {
						return ssl.Run(ctx, u.Host)
					}
					return types.ModuleResult{Module: "ssl", Target: target, Error: fmt.Errorf("no host in URL")}
				}},
			}
			handleResults(r.Run(context.Background(), tasks))
		},
	}
}

func fileCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "file [path]",
		Short: "Analyze file",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			path := args[0]
			handleResults([]types.ModuleResult{file.Analyze(path)})
		},
	}
}

func reportCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "report [file]",
		Short: "Load and export a previous JSON report",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			data, err := os.ReadFile(args[0])
			if err != nil {
				log.Error("read failed", "error", err)
				return
			}
			var results []types.ModuleResult
			if err := json.Unmarshal(data, &results); err != nil {
				log.Error("parse failed", "error", err)
				return
			}
			handleResults(results)
		},
	}
}

func tuiCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "tui",
		Short: "Launch interactive TUI dashboard",
		Run: func(cmd *cobra.Command, args []string) {
			p := tea.NewProgram(tui.New(), tea.WithAltScreen())
			if _, err := p.Run(); err != nil {
				fmt.Fprintln(os.Stderr, "TUI error:", err)
				os.Exit(1)
			}
		},
	}
}

func handleResults(results []types.ModuleResult) {
	if outFile == "" {
		for _, r := range results {
			data, _ := json.MarshalIndent(r, "", "  ")
			fmt.Println(string(data))
		}
		return
	}
	ext := strings.ToLower(filepath.Ext(outFile))
	if ext == "" {
		outFile = outFile + "." + format
	}
	if err := output.Export(results, format, outFile); err != nil {
		log.Error("export failed", "error", err)
	} else {
		fmt.Println("Report saved to", outFile)
	}
}
