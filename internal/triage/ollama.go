package triage

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type OllamaClient struct {
	Host   string
	Model  string
	client *http.Client
}

func NewOllamaClient(host, model string) *OllamaClient {
	return &OllamaClient{
		Host:  host,
		Model: model,
		client: &http.Client{
			Timeout: 120 * time.Second,
		},
	}
}

type ollamaRequest struct {
	Model    string          `json:"model"`
	Messages []ollamaMessage `json:"messages"`
	Stream   bool            `json:"stream"`
	Options  ollamaOptions   `json:"options"`
}

type ollamaMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ollamaOptions struct {
	Temperature float64 `json:"temperature"`
}

type ollamaResponse struct {
	Message ollamaMessage `json:"message"`
	Done    bool          `json:"done"`
}

type Finding struct {
	URL         string
	Method      string
	StatusCode  int
	Severity    string
	Category    string
	Description string
	Evidence    string
	NextSteps   string
}

const systemPrompt = `You are an expert bug bounty hunter analyzing HTTP traffic for security vulnerabilities.

For each HTTP exchange, respond ONLY with a JSON object in this exact format:
{
  "severity": "critical|high|medium|low|info|noise",
  "category": "short category e.g. IDOR, Auth Bypass, Info Disclosure, SSRF, SQLi, XSS, Open Redirect, Misconfiguration, Interesting Endpoint, noise",
  "description": "one sentence describing the finding",
  "evidence": "specific field, header, parameter, or response content that triggered this",
  "next_steps": "specific manual test to confirm or exploit"
}

Severity guide:
- critical: RCE, auth bypass, mass data exposure
- high: IDOR, SQLi, stored XSS, privilege escalation
- medium: reflected XSS, open redirect, sensitive info disclosure, CORS misconfiguration on authenticated endpoints
- low: missing security headers on main app, verbose error messages, minor info leakage
- info: interesting endpoints worth manual review, unusual parameters
- noise: anything that should be ignored

ALWAYS mark as noise if ANY of these are true:
- The URL host is a third-party domain unrelated to the primary target (analytics, ads, CDN, tracking pixels)
  Examples: bat.bing.com, google-analytics.com, trustarc.com, doubleclick.net, hotjar.com, segment.com, facebook.net, amplitude.com, mixpanel.com, googletagmanager.com, akamai.com, cloudfront.net, fastly.net
- Access-Control-Allow-Origin: * on a PUBLIC resource (JS files, CSS, images, tracking pixels, CDN assets)
  Note: CORS * is only a real issue on AUTHENTICATED endpoints that return sensitive user data
- Status 204 No Content — tracking pixels always return 204, never interesting
- Status 304 Not Modified on a static/public asset
- The response body is empty or contains only generic/public data
- The URL is clearly an analytics, telemetry, or advertising endpoint
- The request has no authentication headers (no Authorization, no session cookies for the target)

Only flag CORS as medium/high if ALL of these are true:
1. The endpoint is on the TARGET'S OWN DOMAIN
2. The endpoint returns sensitive/authenticated data
3. Access-Control-Allow-Credentials: true is also present OR the data is sensitive even without credentials

Be precise. When in doubt, mark as noise. The goal is actionable findings, not false positives.
Never return markdown, explanation, or anything outside the JSON object.`

func (c *OllamaClient) AnalyzeEntry(entry TrafficEntry) (*Finding, error) {
	prompt := buildPrompt(entry)

	req := ollamaRequest{
		Model: c.Model,
		Messages: []ollamaMessage{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: prompt},
		},
		Stream: false,
		Options: ollamaOptions{
			Temperature: 0.1,
		},
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("ollama: marshal request: %w", err)
	}

	resp, err := c.client.Post(
		fmt.Sprintf("%s/api/chat", c.Host),
		"application/json",
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, fmt.Errorf("ollama: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ollama: unexpected status %d", resp.StatusCode)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("ollama: read response: %w", err)
	}

	var ollamaResp ollamaResponse
	if err := json.Unmarshal(respBody, &ollamaResp); err != nil {
		return nil, fmt.Errorf("ollama: parse response: %w", err)
	}

	finding, err := parseFinding(ollamaResp.Message.Content, entry)
	if err != nil {
		return nil, fmt.Errorf("ollama: parse finding: %w", err)
	}

	return finding, nil
}

func (c *OllamaClient) Ping() error {
	resp, err := c.client.Get(fmt.Sprintf("%s/api/tags", c.Host))
	if err != nil {
		return fmt.Errorf("ollama not reachable at %s — is it running? try: ollama serve", c.Host)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ollama: unexpected status %d", resp.StatusCode)
	}

	var tags struct {
		Models []struct {
			Name string `json:"name"`
		} `json:"models"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tags); err != nil {
		return nil
	}

	for _, m := range tags.Models {
		if strings.HasPrefix(m.Name, c.Model) {
			return nil
		}
	}

	return fmt.Errorf("model '%s' not found in Ollama — run: ollama pull %s", c.Model, c.Model)
}

func buildPrompt(e TrafficEntry) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("METHOD: %s\n", e.Method))
	sb.WriteString(fmt.Sprintf("URL: %s\n", e.URL))
	sb.WriteString(fmt.Sprintf("STATUS: %d\n", e.StatusCode))

	if len(e.QueryParams) > 0 {
		sb.WriteString("QUERY PARAMS:\n")
		for k, v := range e.QueryParams {
			sb.WriteString(fmt.Sprintf("  %s=%s\n", k, v))
		}
	}

	if len(e.RequestHeaders) > 0 {
		sb.WriteString("REQUEST HEADERS:\n")
		for k, v := range e.RequestHeaders {
			sb.WriteString(fmt.Sprintf("  %s: %s\n", k, v))
		}
	}

	if e.RequestBody != "" {
		sb.WriteString(fmt.Sprintf("REQUEST BODY:\n%s\n", e.RequestBody))
	}

	if len(e.ResponseHeaders) > 0 {
		sb.WriteString("RESPONSE HEADERS:\n")
		for k, v := range e.ResponseHeaders {
			sb.WriteString(fmt.Sprintf("  %s: %s\n", k, v))
		}
	}

	if e.ResponseBody != "" {
		sb.WriteString(fmt.Sprintf("RESPONSE BODY:\n%s\n", e.ResponseBody))
	}

	return sb.String()
}

func parseFinding(content string, entry TrafficEntry) (*Finding, error) {
	content = strings.TrimSpace(content)
	content = strings.TrimPrefix(content, "```json")
	content = strings.TrimPrefix(content, "```")
	content = strings.TrimSuffix(content, "```")
	content = strings.TrimSpace(content)

	// strip qwen3 thinking tags if present
	if idx := strings.LastIndex(content, "</think>"); idx != -1 {
		content = strings.TrimSpace(content[idx+8:])
	}

	var raw struct {
		Severity    string `json:"severity"`
		Category    string `json:"category"`
		Description string `json:"description"`
		Evidence    string `json:"evidence"`
		NextSteps   string `json:"next_steps"`
	}

	if err := json.Unmarshal([]byte(content), &raw); err != nil {
		return nil, fmt.Errorf("could not parse model output: %w\nraw: %s", err, content)
	}

	return &Finding{
		URL:         entry.URL,
		Method:      entry.Method,
		StatusCode:  entry.StatusCode,
		Severity:    strings.ToLower(raw.Severity),
		Category:    raw.Category,
		Description: raw.Description,
		Evidence:    raw.Evidence,
		NextSteps:   raw.NextSteps,
	}, nil
}