// Package reporter renders a scan summary as terminal text, Markdown, JSON, or SARIF.
package reporter

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/rbrus/agent-probe/scanner"
)

func RenderTerminal(w io.Writer, s scanner.ScanSummary) {
	fmt.Fprintf(w, "\n================================================================================\n")
	fmt.Fprintf(w, "                      AGENT PROBE SECURITY ASSESSMENT REPORT                    \n")
	fmt.Fprintf(w, "================================================================================\n")
	fmt.Fprintf(w, "Target:   %s\n", s.TargetURL)
	fmt.Fprintf(w, "Duration: %v (Probes: %d)\n", s.TotalDuration.Round(100*time.Millisecond), s.TotalProbes)
	fmt.Fprintf(w, "Summary:  Vulnerable: %d | Defended: %d | Errors: %d\n", s.VulnerableCount, s.DefendedCount, s.ErrorCount)
	if s.ControlCaptured {
		fmt.Fprintf(w, "Control:  benign baseline captured (matching signatures suppressed as false positives)\n")
	} else {
		fmt.Fprintf(w, "Control:  benign baseline NOT captured (no false-positive suppression this run)\n")
	}
	fmt.Fprintf(w, "--------------------------------------------------------------------------------\n")
	fmt.Fprintf(w, "%-18s | %-10s | %-12s | %-32s\n", "PROBE ID", "SEVERITY", "VERDICT", "CATEGORY")
	fmt.Fprintf(w, "--------------------------------------------------------------------------------\n")

	for _, r := range s.Results {
		verdictColor := "\033[32mDEFENDED\033[0m"
		switch r.Verdict {
		case scanner.VerdictVulnerable:
			verdictColor = "\033[31;1mVULNERABLE\033[0m"
		case scanner.VerdictError:
			verdictColor = "\033[33mERROR\033[0m"
		}

		fmt.Fprintf(w, "%-18s | %-10s | %-21s | %-32s\n",
			r.Probe.ID,
			r.Probe.Severity,
			verdictColor,
			r.Probe.Category,
		)
	}
	fmt.Fprintf(w, "================================================================================\n")

	if s.VulnerableCount > 0 {
		fmt.Fprintf(w, "\n[!] DETECTED VULNERABILITIES & REMEDIATION GUIDANCE:\n\n")
		for _, r := range s.Results {
			if r.Verdict == scanner.VerdictVulnerable {
				fmt.Fprintf(w, "  * [%s] %s (%s)\n", r.Probe.Severity, r.Probe.ID, r.Probe.Description)
				if r.MatchedSign != "" {
					fmt.Fprintf(w, "    Trigger Signature: %q\n", r.MatchedSign)
				}
				fmt.Fprintf(w, "    Remediation:       %s\n\n", r.Probe.Remediation)
			}
		}
	} else if s.ErrorCount == 0 {
		fmt.Fprintf(w, "\n[\u2713] All probes successfully defended. Target agent posture held.\n\n")
	}

	suppressed := 0
	for _, r := range s.Results {
		if r.Verdict == scanner.VerdictDefended && r.Note != "" {
			suppressed++
		}
	}
	if suppressed > 0 {
		fmt.Fprintf(w, "[i] %d probe(s) matched a signature that also appeared in the benign baseline and were suppressed as false positives.\n\n", suppressed)
	}
}

func RenderMarkdown(s scanner.ScanSummary) string {
	var sb strings.Builder
	sb.WriteString("# Agent Probe Security Assessment\n\n")
	sb.WriteString(fmt.Sprintf("- **Target:** `%s`\n", s.TargetURL))
	sb.WriteString(fmt.Sprintf("- **Duration:** `%v`\n", s.TotalDuration.Round(100*time.Millisecond)))
	sb.WriteString(fmt.Sprintf("- **Total Probes:** `%d`\n", s.TotalProbes))
	sb.WriteString(fmt.Sprintf("- **Status:** %d Vulnerabilities Detected | %d Defended | %d Errors\n", s.VulnerableCount, s.DefendedCount, s.ErrorCount))
	if s.ControlCaptured {
		sb.WriteString("- **Negative control:** benign baseline captured; signatures also present in it were suppressed as false positives.\n\n")
	} else {
		sb.WriteString("- **Negative control:** not captured this run; no false-positive suppression applied.\n\n")
	}

	sb.WriteString("## Findings Table\n\n")
	sb.WriteString("| Probe ID | Severity | Category | Verdict | Description |\n")
	sb.WriteString("|---|---|---|---|---|\n")

	for _, r := range s.Results {
		verdictBadge := "🟢 DEFENDED"
		if r.Verdict == scanner.VerdictVulnerable {
			verdictBadge = "🔴 **VULNERABLE**"
		} else if r.Verdict == scanner.VerdictError {
			verdictBadge = "🟡 ERROR"
		}
		sb.WriteString(fmt.Sprintf("| `%s` | %s | %s | %s | %s |\n",
			r.Probe.ID, r.Probe.Severity, r.Probe.Category, verdictBadge, r.Probe.Description))
	}

	if s.VulnerableCount > 0 {
		sb.WriteString("\n## Remediation Details\n\n")
		for _, r := range s.Results {
			if r.Verdict == scanner.VerdictVulnerable {
				sb.WriteString(fmt.Sprintf("### %s: %s\n", r.Probe.ID, r.Probe.Description))
				sb.WriteString(fmt.Sprintf("- **Category:** %s\n", r.Probe.Category))
				sb.WriteString(fmt.Sprintf("- **Severity:** %s\n", r.Probe.Severity))
				sb.WriteString(fmt.Sprintf("- **Evidence Snippet:**\n```\n%s\n```\n", r.Evidence))
				sb.WriteString(fmt.Sprintf("- **Remediation Action:** %s\n\n", r.Probe.Remediation))
			}
		}
	}

	return sb.String()
}

func RenderJSON(s scanner.ScanSummary) ([]byte, error) {
	return json.MarshalIndent(s, "", "  ")
}

func RenderSARIF(s scanner.ScanSummary) ([]byte, error) {
	type sarifMessage struct {
		Text string `json:"text"`
	}
	type sarifResult struct {
		RuleID  string       `json:"ruleId"`
		Level   string       `json:"level"`
		Message sarifMessage `json:"message"`
	}
	type sarifRule struct {
		ID               string       `json:"id"`
		Name             string       `json:"name"`
		ShortDescription sarifMessage `json:"shortDescription"`
	}
	type sarifDriver struct {
		Name    string      `json:"name"`
		Version string      `json:"version"`
		Rules   []sarifRule `json:"rules"`
	}
	type sarifTool struct {
		Driver sarifDriver `json:"driver"`
	}
	type sarifRun struct {
		Tool    sarifTool     `json:"tool"`
		Results []sarifResult `json:"results"`
	}
	type sarifReport struct {
		Version string     `json:"version"`
		Schema  string     `json:"$schema"`
		Runs    []sarifRun `json:"runs"`
	}

	var sarifResults []sarifResult
	var sarifRules []sarifRule

	for _, r := range s.Results {
		sarifRules = append(sarifRules, sarifRule{
			ID:   r.Probe.ID,
			Name: r.Probe.Category,
			ShortDescription: sarifMessage{
				Text: r.Probe.Description,
			},
		})

		if r.Verdict == scanner.VerdictVulnerable {
			level := "warning"
			if r.Probe.Severity == "CRITICAL" || r.Probe.Severity == "HIGH" {
				level = "error"
			}
			sarifResults = append(sarifResults, sarifResult{
				RuleID: r.Probe.ID,
				Level:  level,
				Message: sarifMessage{
					Text: fmt.Sprintf("%s: %s (Remediation: %s)", r.Probe.ID, r.Probe.Description, r.Probe.Remediation),
				},
			})
		}
	}

	rep := sarifReport{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:    "Agent-Probe",
						Version: "1.0.0",
						Rules:   sarifRules,
					},
				},
				Results: sarifResults,
			},
		},
	}

	return json.MarshalIndent(rep, "", "  ")
}
