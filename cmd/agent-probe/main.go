package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/rbrus/agent-probe/mock"
	"github.com/rbrus/agent-probe/probes"
	"github.com/rbrus/agent-probe/reporter"
	"github.com/rbrus/agent-probe/scanner"
)

var (
	version      = "1.1.0"
	buildVersion = ""
	buildDate    = "2026-09-26"
)

func getVersion() string {
	if buildVersion != "" {
		return buildVersion
	}
	return version
}

const usageText = `agent-probe — Autonomous AI Agent Security & Red-Teaming CLI

Usage:
  agent-probe scan --target <URL> [options]    Scan an AI agent endpoint
  agent-probe target [options]                 Run a local attackable mock agent for testing
  agent-probe list                             List available security probes in this build
  agent-probe version                          Print version and build details

Scan Options:
  --target string         Target endpoint URL (e.g. http://localhost:8399/chat)
  --field string          JSON field containing user message (default: "message")
  --reply-path string     JSON path for agent reply (default: "reply")
  --openai                Enable OpenAI-compatible request/response mapping
  --model string          Model identifier when --openai is set (default: "gpt-4o-mini")
  --bearer string         Bearer token for target authentication
  --api-key-header string Header name for API key authentication (e.g. X-API-Key)
  --api-key-value string  API key value
  --timeout duration      Per-request timeout (default: 15s)
  --format string         Output format: terminal | md | json | sarif (default: "terminal")
  --output string, -o     File path to save the scan report
  --fail-on string        Exit 1 only for findings at or above: critical | high | medium | low (default: any)

Target Options:
  --port int              Port to listen on (default: 8399)
  --defense string        Defense posture: none | basic | hardened (default: "none")

Notice:
  Apache-2.0. Use only against systems you own or are authorized in writing to test.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usageText)
		os.Exit(2)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "scan":
		os.Exit(runScan(args))
	case "target":
		os.Exit(runTarget(args))
	case "list":
		os.Exit(runList())
	case "version", "--version", "-v":
		fmt.Printf("agent-probe version %s (built %s)\n", getVersion(), buildDate)
		os.Exit(0)
	case "help", "--help", "-h":
		fmt.Print(usageText)
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n%s", cmd, usageText)
		os.Exit(2)
	}
}

func runScan(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	targetURL := fs.String("target", "", "Target URL (required)")
	field := fs.String("field", "message", "JSON request message field")
	replyPath := fs.String("reply-path", "reply", "JSON response message path")
	isOpenAI := fs.Bool("openai", false, "OpenAI-compatible chat completion format")
	model := fs.String("model", "gpt-4o-mini", "Model identifier for OpenAI mode")
	bearer := fs.String("bearer", "", "Bearer token")
	apiKeyHeader := fs.String("api-key-header", "", "API key header name")
	apiKeyValue := fs.String("api-key-value", "", "API key header value")
	timeout := fs.Duration("timeout", 15*time.Second, "Request timeout")
	format := fs.String("format", "terminal", "Output format: terminal | md | json | sarif")
	outputPath := fs.String("output", "", "Output report file path")
	fs.StringVar(outputPath, "o", "", "Output report file path (shorthand)")
	failOn := fs.String("fail-on", "any", "Severity gate: critical | high | medium | low | any")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *targetURL == "" {
		fmt.Fprintln(os.Stderr, "[-] Error: --target is required. Example: agent-probe scan --target http://localhost:8399/chat")
		return 2
	}

	authHeader := ""
	authValue := ""
	if *bearer != "" {
		authHeader = "Authorization"
		authValue = "Bearer " + *bearer
	} else if *apiKeyHeader != "" && *apiKeyValue != "" {
		authHeader = *apiKeyHeader
		authValue = *apiKeyValue
	}

	clientCfg := scanner.TargetConfig{
		URL:        *targetURL,
		Field:      *field,
		ReplyPath:  *replyPath,
		AuthHeader: authHeader,
		AuthValue:  authValue,
		IsOpenAI:   *isOpenAI,
		Model:      *model,
		Timeout:    *timeout,
	}

	client := scanner.NewClient(clientCfg)
	runner := scanner.NewRunner(client, nil)

	fmt.Printf("[*] Initiating security probe sequence against: %s\n", *targetURL)
	ctx := context.Background()

	progress := func(cur, total int, res scanner.ProbeResult) {
		status := "PASS"
		if res.Verdict == scanner.VerdictVulnerable {
			status = "FAIL"
		} else if res.Verdict == scanner.VerdictError {
			status = "ERR"
		}
		fmt.Printf("    [%d/%d] %-18s (%-8s) => %s\n", cur, total, res.Probe.ID, res.Probe.Severity, status)
	}

	summary := runner.Run(ctx, progress)

	// Save or render report
	var reportBytes []byte
	switch strings.ToLower(*format) {
	case "md", "markdown":
		reportBytes = []byte(reporter.RenderMarkdown(summary))
	case "json":
		b, err := reporter.RenderJSON(summary)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Error rendering JSON: %v\n", err)
			return 2
		}
		reportBytes = b
	case "sarif":
		b, err := reporter.RenderSARIF(summary)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Error rendering SARIF: %v\n", err)
			return 2
		}
		reportBytes = b
	default:
		reporter.RenderTerminal(os.Stdout, summary)
	}

	if *outputPath != "" {
		if len(reportBytes) == 0 {
			reportBytes = []byte(reporter.RenderMarkdown(summary))
		}
		if err := os.WriteFile(*outputPath, reportBytes, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Error writing report to %s: %v\n", *outputPath, err)
		} else {
			fmt.Printf("[+] Report saved to %s\n", *outputPath)
		}
	} else if strings.ToLower(*format) != "terminal" {
		fmt.Println(string(reportBytes))
	}

	if summary.ErrorCount == summary.TotalProbes {
		fmt.Fprintf(os.Stderr, "[-] Connection failure: All %d probes failed to connect to %s\n", summary.TotalProbes, *targetURL)
		return 2
	}

	if shouldFail(summary, *failOn) {
		return 1
	}

	return 0
}

func shouldFail(s scanner.ScanSummary, failOn string) bool {
	if s.VulnerableCount == 0 {
		return false
	}
	failOn = strings.ToLower(failOn)
	if failOn == "any" || failOn == "none" {
		return s.VulnerableCount > 0
	}

	rank := map[string]int{
		"critical": 4,
		"high":     3,
		"medium":   2,
		"low":      1,
	}

	gateLevel := rank[failOn]
	for _, r := range s.Results {
		if r.Verdict == scanner.VerdictVulnerable {
			sev := strings.ToLower(string(r.Probe.Severity))
			if rank[sev] >= gateLevel {
				return true
			}
		}
	}
	return false
}

func runTarget(args []string) int {
	fs := flag.NewFlagSet("target", flag.ExitOnError)
	port := fs.Int("port", 8399, "Port to listen on")
	defense := fs.String("defense", "none", "Defense level: none | basic | hardened")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	srv := mock.NewMockServer(mock.DefenseLevel(*defense), *port)
	if err := srv.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Server error: %v\n", err)
		return 1
	}
	return 0
}

func runList() int {
	all := probes.All()
	fmt.Printf("\n%-18s | %-10s | %-32s | %s\n", "PROBE ID", "SEVERITY", "CATEGORY", "DESCRIPTION")
	fmt.Println(strings.Repeat("-", 100))
	for _, p := range all {
		fmt.Printf("%-18s | %-10s | %-32s | %s\n", p.ID, p.Severity, p.Category, p.Description)
	}
	fmt.Printf("\nTotal Probes: %d\n\n", len(all))
	return 0
}
