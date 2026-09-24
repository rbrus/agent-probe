// Package scanner runs agent-probe's probe catalog against a Target and
// summarizes which probes the target defended and which it was vulnerable to.
package scanner

import (
	"context"
	"strings"
	"time"

	"github.com/rbrus/agent-probe/probes"
)

// Target is anything a probe can be sent to: it takes a payload and returns the
// agent's reply, the HTTP status (0 for non-HTTP transports), how long it took,
// and any transport error. The built-in Client implements it over HTTP/JSON;
// a custom transport (for example a redwire connector) can implement it too.
type Target interface {
	Send(ctx context.Context, payload string) (reply string, statusCode int, duration time.Duration, err error)
}

type Verdict string

const (
	VerdictVulnerable Verdict = "VULNERABLE"
	VerdictDefended   Verdict = "DEFENDED"
	VerdictError      Verdict = "ERROR"
)

type ProbeResult struct {
	Probe       probes.Probe  `json:"probe"`
	Verdict     Verdict       `json:"verdict"`
	Evidence    string        `json:"evidence"`
	MatchedSign string        `json:"matched_signature,omitempty"`
	StatusCode  int           `json:"status_code"`
	Duration    time.Duration `json:"duration_ms"`
	Error       string        `json:"error,omitempty"`
}

type ScanSummary struct {
	TargetURL       string        `json:"target_url"`
	StartTime       time.Time     `json:"start_time"`
	EndTime         time.Time     `json:"end_time"`
	TotalDuration   time.Duration `json:"total_duration"`
	TotalProbes     int           `json:"total_probes"`
	VulnerableCount int           `json:"vulnerable_count"`
	DefendedCount   int           `json:"defended_count"`
	ErrorCount      int           `json:"error_count"`
	Results         []ProbeResult `json:"results"`
}

type Runner struct {
	target    Target
	targetURL string
	probes    []probes.Probe
}

func NewRunner(target Target, probeList []probes.Probe) *Runner {
	if len(probeList) == 0 {
		probeList = probes.All()
	}
	url := ""
	if c, ok := target.(*Client); ok {
		url = c.cfg.URL
	}
	return &Runner{
		target:    target,
		targetURL: url,
		probes:    probeList,
	}
}

func (r *Runner) Run(ctx context.Context, progressFn func(current, total int, res ProbeResult)) ScanSummary {
	start := time.Now()
	summary := ScanSummary{
		TargetURL:   r.targetURL,
		StartTime:   start,
		TotalProbes: len(r.probes),
		Results:     make([]ProbeResult, 0, len(r.probes)),
	}

	for i, p := range r.probes {
		res := r.evaluateProbe(ctx, p)
		summary.Results = append(summary.Results, res)

		switch res.Verdict {
		case VerdictVulnerable:
			summary.VulnerableCount++
		case VerdictDefended:
			summary.DefendedCount++
		case VerdictError:
			summary.ErrorCount++
		}

		if progressFn != nil {
			progressFn(i+1, len(r.probes), res)
		}
	}

	summary.EndTime = time.Now()
	summary.TotalDuration = summary.EndTime.Sub(start)
	return summary
}

func (r *Runner) evaluateProbe(ctx context.Context, p probes.Probe) ProbeResult {
	res := ProbeResult{
		Probe: p,
	}

	respText, code, dur, err := r.target.Send(ctx, p.Payload)
	res.StatusCode = code
	res.Duration = dur

	if err != nil {
		res.Verdict = VerdictError
		res.Error = err.Error()
		return res
	}

	res.Evidence = truncate(respText, 400)
	lowerResp := strings.ToLower(respText)

	// Check if any refusal phrase is triggered
	hasRefusal := false
	for _, ref := range p.Refusals {
		if strings.Contains(lowerResp, strings.ToLower(ref)) {
			hasRefusal = true
			break
		}
	}

	// Check if any vulnerability signature is triggered
	for _, sig := range p.Signatures {
		if strings.Contains(respText, sig) || strings.Contains(lowerResp, strings.ToLower(sig)) {
			// If refusal is present, the agent is declining, so treat as defended
			if hasRefusal {
				continue
			}
			res.Verdict = VerdictVulnerable
			res.MatchedSign = sig
			return res
		}
	}

	// If no signatures matched, it held
	res.Verdict = VerdictDefended
	return res
}

func truncate(s string, maxLen int) string {
	s = strings.TrimSpace(s)
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
