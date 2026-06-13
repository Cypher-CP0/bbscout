package triage

import (
	"encoding/json"
	"fmt"
	"sync"
)

// MultiAgentTriager runs a two-stage pipeline:
// Stage 1: Generator (ovftank/unisast) — drafts initial finding
// Stage 2: Checker (xploiter/pentester) — validates and formats final ticket
type MultiAgentTriager struct {
	generator *OllamaClient // ovftank/unisast
	checker   *OllamaClient // xploiter/pentester
}

const generatorPrompt = `You are a security tool performing initial triage of HTTP traffic.
Analyze the HTTP exchange and identify potential security vulnerabilities.
Be liberal — flag anything suspicious for further review.

Respond ONLY with a JSON object:
{
  "severity": "critical|high|medium|low|info|noise",
  "category": "IDOR|Auth Bypass|XSS|SSRF|Info Disclosure|Misconfiguration|Interesting Endpoint|noise",
  "description": "one sentence describing the potential issue",
  "evidence": "specific field, header, or value that triggered this",
  "confidence": "high|medium|low"
}

Mark as noise if: third-party domain, public static asset, 204/304 status, no auth headers, empty response.`

const checkerPrompt = `You are a senior bug bounty analyst reviewing a security finding.
You have been given the original HTTP traffic and a draft finding from an automated tool.
Your job is to validate the finding and produce a final submission-ready ticket.

Review the draft finding critically:
1. Is the evidence actually present in the traffic?
2. Is this genuinely exploitable or a false positive?
3. Is the severity correctly calibrated per CVSS?
4. What specific next steps would confirm or exploit this?

If the finding is a false positive, set severity to "noise" with a clear explanation.

Respond ONLY with a JSON object:
{
  "severity": "critical|high|medium|low|info|noise",
  "category": "short category name",
  "description": "clear one-sentence description of the vulnerability",
  "evidence": "exact evidence from the traffic",
  "next_steps": "specific actionable steps to confirm or exploit",
  "false_positive_reason": "if noise, explain why"
}`

// NewMultiAgentTriager creates a two-stage triage pipeline.
// host is the Ollama server (local or Azure via SSH tunnel).
func NewMultiAgentTriager(host string) *MultiAgentTriager {
	return &MultiAgentTriager{
		generator: NewOllamaClient(host, "ovftank/unisast"),
		checker:   NewOllamaClient(host, "xploiter/pentester"),
	}
}

// Ping checks both models are reachable.
func (m *MultiAgentTriager) Ping() error {
	if err := m.generator.Ping(); err != nil {
		return fmt.Errorf("generator (ovftank/unisast) unreachable: %w", err)
	}
	if err := m.checker.Ping(); err != nil {
		return fmt.Errorf("checker (xploiter/pentester) unreachable: %w", err)
	}
	return nil
}

// Analyze runs an entry through the two-stage pipeline.
func (m *MultiAgentTriager) Analyze(entry TrafficEntry) (*Finding, error) {
	// Stage 1 — Generator drafts finding
	draft, err := m.generator.analyzeWithPrompt(entry, generatorPrompt)
	if err != nil {
		return nil, fmt.Errorf("generator failed: %w", err)
	}

	// skip checker for obvious noise
	if draft.Severity == "noise" {
		return draft, nil
	}

	// only run checker on low confidence or potentially interesting findings
	if draft.Severity == "info" {
		return draft, nil
	}

	// Stage 2 — Checker validates the draft
	final, err := m.checker.verifyFinding(entry, draft, checkerPrompt)
	if err != nil {
		// fallback to draft if checker fails
		return draft, nil
	}

	return final, nil
}

// AnalyzeBatch runs multiple entries concurrently through the pipeline.
// Uses keep_alive:0 pattern — generator processes all entries first,
// then checker processes surviving findings — minimizing model switches.
func (m *MultiAgentTriager) AnalyzeBatch(entries []TrafficEntry, concurrency int) ([]*Finding, error) {
	fmt.Printf("[multi-agent] stage 1/2 — generator analyzing %d entries\n", len(entries))

	// Stage 1 — all entries through generator concurrently
	type genResult struct {
		entry   TrafficEntry
		finding *Finding
		err     error
	}

	genResults := make([]genResult, len(entries))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for i, entry := range entries {
		wg.Add(1)
		go func(idx int, e TrafficEntry) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			f, err := m.generator.analyzeWithPrompt(e, generatorPrompt)
			genResults[idx] = genResult{entry: e, finding: f, err: err}
		}(i, entry)
	}
	wg.Wait()

	// collect non-noise findings for stage 2
	var toVerify []genResult
	noiseCount := 0
	for _, r := range genResults {
		if r.err != nil || r.finding == nil || r.finding.Severity == "noise" || r.finding.Severity == "info" {
			noiseCount++
			continue
		}
		toVerify = append(toVerify, r)
	}

	fmt.Printf("[multi-agent] generator: %d potential findings, %d noise\n",
		len(toVerify), noiseCount)

	if len(toVerify) == 0 {
		return nil, nil
	}

	// Stage 2 — checker validates survivors
	fmt.Printf("[multi-agent] stage 2/2 — checker validating %d findings\n", len(toVerify))

	var findings []*Finding
	var mu sync.Mutex
	var wg2 sync.WaitGroup

	for _, r := range toVerify {
		wg2.Add(1)
		go func(gr genResult) {
			defer wg2.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			final, err := m.checker.verifyFinding(gr.entry, gr.finding, checkerPrompt)
			if err != nil {
				// fallback to generator draft
				final = gr.finding
			}
			if final != nil && final.Severity != "noise" {
				mu.Lock()
				findings = append(findings, final)
				mu.Unlock()
			}
		}(r)
	}
	wg2.Wait()

	fmt.Printf("[multi-agent] final findings: %d\n", len(findings))
	return findings, nil
}

// analyzeWithPrompt sends an entry to Ollama with a custom system prompt.
func (c *OllamaClient) analyzeWithPrompt(entry TrafficEntry, systemPrompt string) (*Finding, error) {
	prompt := buildPrompt(entry)

	type ollamaReq struct {
		Model    string          `json:"model"`
		Messages []ollamaMessage `json:"messages"`
		Stream   bool            `json:"stream"`
		Options  ollamaOptions   `json:"options"`
		KeepAlive string         `json:"keep_alive"`
	}

	req := ollamaReq{
		Model: c.Model,
		Messages: []ollamaMessage{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: prompt},
		},
		Stream:    false,
		Options:   ollamaOptions{Temperature: 0.1},
		KeepAlive: "0", // unload immediately after response
	}

	respBody, err := c.doRequest(req)
	if err != nil {
		return nil, err
	}

	var ollamaResp ollamaResponse
	if err := json.Unmarshal(respBody, &ollamaResp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	return parseFinding(ollamaResp.Message.Content, entry)
}

// verifyFinding sends the original entry + draft finding to the checker model.
func (c *OllamaClient) verifyFinding(entry TrafficEntry, draft *Finding, systemPrompt string) (*Finding, error) {
	draftJSON, _ := json.MarshalIndent(map[string]string{
		"severity":    draft.Severity,
		"category":    draft.Category,
		"description": draft.Description,
		"evidence":    draft.Evidence,
	}, "", "  ")

	prompt := fmt.Sprintf("DRAFT FINDING:\n%s\n\nORIGINAL TRAFFIC:\n%s",
		string(draftJSON),
		buildPrompt(entry),
	)

	type ollamaReq struct {
		Model    string          `json:"model"`
		Messages []ollamaMessage `json:"messages"`
		Stream   bool            `json:"stream"`
		Options  ollamaOptions   `json:"options"`
		KeepAlive string         `json:"keep_alive"`
	}

	req := ollamaReq{
		Model: c.Model,
		Messages: []ollamaMessage{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: prompt},
		},
		Stream:    false,
		Options:   ollamaOptions{Temperature: 0.1},
		KeepAlive: "0",
	}

	respBody, err := c.doRequest(req)
	if err != nil {
		return nil, err
	}

	var ollamaResp ollamaResponse
	if err := json.Unmarshal(respBody, &ollamaResp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	return parseFinding(ollamaResp.Message.Content, entry)
}