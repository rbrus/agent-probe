package scanner

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/rbrus/agent-probe/mock"
	"github.com/rbrus/agent-probe/probes"
)

func TestScannerAgainstVulnerableMock(t *testing.T) {
	srv := mock.NewMockServer(mock.DefenseNone, 0)
	ts := httptest.NewServer(srv.Mux())
	defer ts.Close()

	cfg := TargetConfig{
		URL:       ts.URL + "/chat",
		Field:     "message",
		ReplyPath: "reply",
	}

	client := NewClient(cfg)
	runner := NewRunner(client, probes.All())

	summary := runner.Run(context.Background(), nil)
	t.Logf("Vulnerable Mock: vuln=%d, defended=%d, err=%d", summary.VulnerableCount, summary.DefendedCount, summary.ErrorCount)

	if summary.VulnerableCount == 0 {
		t.Fatal("expected vulnerable mock to produce vulnerabilities, got 0")
	}
}

func TestScannerAgainstHardenedMock(t *testing.T) {
	srv := mock.NewMockServer(mock.DefenseHardened, 0)
	ts := httptest.NewServer(srv.Mux())
	defer ts.Close()

	cfg := TargetConfig{
		URL:       ts.URL + "/chat",
		Field:     "message",
		ReplyPath: "reply",
	}

	client := NewClient(cfg)
	runner := NewRunner(client, probes.All())

	summary := runner.Run(context.Background(), nil)
	t.Logf("Hardened Mock: vuln=%d, defended=%d, err=%d", summary.VulnerableCount, summary.DefendedCount, summary.ErrorCount)

	if summary.VulnerableCount > 0 {
		for _, r := range summary.Results {
			if r.Verdict == VerdictVulnerable {
				t.Logf("Failed probe: %s (%s) evidence=%q matched=%q", r.Probe.ID, r.Probe.Description, r.Evidence, r.MatchedSign)
			}
		}
		t.Fatalf("expected hardened mock to have 0 vulnerabilities, got %d", summary.VulnerableCount)
	}
}
