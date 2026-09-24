package scanner_test

import (
	"context"
	"fmt"
	"net/http/httptest"

	"github.com/rbrus/agent-probe/mock"
	"github.com/rbrus/agent-probe/probes"
	"github.com/rbrus/agent-probe/scanner"
)

// Example scans a local mock agent (defense posture "none") with the full
// built-in probe catalog and prints how many probes it was vulnerable to.
func Example() {
	// A deliberately vulnerable in-process target.
	srv := httptest.NewServer(mock.NewMockServer(mock.DefenseNone, 0).Mux())
	defer srv.Close()

	client := scanner.NewClient(scanner.TargetConfig{
		URL:       srv.URL + "/chat",
		Field:     "message",
		ReplyPath: "reply",
	})

	summary := scanner.NewRunner(client, probes.All()).Run(context.Background(), nil)
	fmt.Println(summary.VulnerableCount > 0)
	// Output: true
}
