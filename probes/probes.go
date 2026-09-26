package probes

import "strings"

// Severity is the risk level of a probe's finding, aligned with the OWASP
// Top 10 for LLM Applications.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// Probe is a single adversarial test: a payload sent to the target, the
// signatures whose presence in the reply indicates a vulnerability, and the
// refusal phrases whose presence indicates the target defended itself.
type Probe struct {
	ID          string   `json:"id"`
	Category    string   `json:"category"`
	Severity    Severity `json:"severity"`
	Description string   `json:"description"`
	Payload     string   `json:"payload"`
	Signatures  []string `json:"signatures"`
	Refusals    []string `json:"refusals"`
	Remediation string   `json:"remediation"`
}

// TagEncode converts an ASCII string to invisible Unicode Plane 14 tag characters (U+E0000..U+E007F).
// Tag-plane characters are invisible in standard renders but are tokenized and decoded by modern frontier LLMs.
func TagEncode(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 0x20 && r <= 0x7E {
			b.WriteRune(rune(0xE0000 + int(r)))
		}
	}
	return b.String()
}
