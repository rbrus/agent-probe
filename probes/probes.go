package probes

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
