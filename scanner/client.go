package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type TargetConfig struct {
	URL        string
	Field      string // JSON key for request payload (default: "message")
	ReplyPath  string // JSON key for response text (default: "reply")
	AuthHeader string
	AuthValue  string
	IsOpenAI   bool
	Model      string // Used when IsOpenAI is true
	Timeout    time.Duration
}

type Client struct {
	cfg        TargetConfig
	httpClient *http.Client
}

func NewClient(cfg TargetConfig) *Client {
	if cfg.Field == "" {
		cfg.Field = "message"
	}
	if cfg.ReplyPath == "" {
		cfg.ReplyPath = "reply"
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 20 * time.Second
	}
	return &Client{
		cfg: cfg,
		httpClient: &http.Client{
			Timeout: cfg.Timeout,
		},
	}
}

func (c *Client) Send(ctx context.Context, payload string) (string, int, time.Duration, error) {
	var reqBody []byte
	var err error

	if c.cfg.IsOpenAI {
		model := c.cfg.Model
		if model == "" {
			model = "gpt-4o-mini"
		}
		bodyMap := map[string]any{
			"model": model,
			"messages": []map[string]string{
				{"role": "user", "content": payload},
			},
		}
		reqBody, err = json.Marshal(bodyMap)
	} else {
		bodyMap := map[string]any{
			c.cfg.Field: payload,
		}
		reqBody, err = json.Marshal(bodyMap)
	}

	if err != nil {
		return "", 0, 0, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.URL, bytes.NewReader(reqBody))
	if err != nil {
		return "", 0, 0, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Agent-Probe/1.0")

	if c.cfg.AuthHeader != "" && c.cfg.AuthValue != "" {
		req.Header.Set(c.cfg.AuthHeader, c.cfg.AuthValue)
	}

	start := time.Now()
	resp, err := c.httpClient.Do(req)
	duration := time.Since(start)

	if err != nil {
		return "", 0, duration, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", resp.StatusCode, duration, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode >= 400 && resp.StatusCode != http.StatusForbidden {
		return string(respBytes), resp.StatusCode, duration, fmt.Errorf("http error %d: %s", resp.StatusCode, string(respBytes))
	}

	extracted := c.extractResponseText(respBytes)
	return extracted, resp.StatusCode, duration, nil
}

func (c *Client) extractResponseText(body []byte) string {
	var raw any
	if err := json.Unmarshal(body, &raw); err != nil {
		// Plaintext fallback
		return string(body)
	}

	if c.cfg.IsOpenAI {
		if m, ok := raw.(map[string]any); ok {
			if choices, ok := m["choices"].([]any); ok && len(choices) > 0 {
				if choiceMap, ok := choices[0].(map[string]any); ok {
					if msg, ok := choiceMap["message"].(map[string]any); ok {
						if content, ok := msg["content"].(string); ok {
							return content
						}
					}
				}
			}
		}
	}

	// Dynamic path lookup (dot notation)
	parts := strings.Split(c.cfg.ReplyPath, ".")
	cur := raw
	for _, p := range parts {
		if m, ok := cur.(map[string]any); ok {
			cur = m[p]
		} else {
			break
		}
	}

	if s, ok := cur.(string); ok {
		return s
	}

	// If lookup failed, fallback to pretty json or string
	return string(body)
}
