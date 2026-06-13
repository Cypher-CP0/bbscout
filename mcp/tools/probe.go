package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/spf13/viper"

	"github.com/Cypher-CP0/bbscout/internal/probe"
	"github.com/Cypher-CP0/bbscout/internal/triage"
	"github.com/Cypher-CP0/bbscout/mcp/util"
)

// RegisterProbe registers the probe tool with the MCP server.
func RegisterProbe(s *server.MCPServer) {
	s.AddTool(
		mcp.NewTool("probe",
			mcp.WithDescription(`Probe a list of URLs or hosts with HTTP requests and analyze responses for security issues.
Automatically captures request/response pairs and feeds them through AI triage.
Use this after recon/scan to deeply analyze interesting endpoints without manual Caido browsing.
Supports probing specific URLs or sweeping a host with common security paths (/admin, /api, /.env, etc).`),
			mcp.WithArray("urls",
				mcp.Required(),
				mcp.Description("List of URLs or hosts to probe e.g. [\"https://api.example.com\", \"https://admin.example.com\"]"),
			),
			mcp.WithString("target",
				mcp.Required(),
				mcp.Description("Target domain for scoping and output e.g. example.com"),
			),
			mcp.WithBoolean("common_paths",
				mcp.Description("Also probe common security paths on each host (/admin, /api, /.env, /debug etc). Default true."),
			),
			mcp.WithBoolean("multi_agent",
				mcp.Description("Use Azure multi-model triage (ovftank/unisast + xploiter/pentester). Default false = local Ollama."),
			),
			mcp.WithString("multi_agent_host",
				mcp.Description("Ollama host for Azure models e.g. http://localhost:11435 (SSH tunnel to Azure VM)"),
			),
			mcp.WithInteger("concurrency",
				mcp.Description("Parallel HTTP probes. Default 5."),
			),
		),
		handleProbe,
	)
}

func handleProbe(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := req.Params.Arguments.(map[string]interface{})

	target := args["target"].(string)
	commonPaths := true
	if v, ok := args["common_paths"].(bool); ok {
		commonPaths = v
	}
	multiAgent, _ := args["multi_agent"].(bool)
	multiAgentHost, _ := args["multi_agent_host"].(string)
	if multiAgentHost == "" {
		multiAgentHost = viper.GetString("ollama.host")
	}
	concurrency := 5
	if v, ok := args["concurrency"].(float64); ok {
		concurrency = int(v)
	}

	// extract URLs
	rawURLs, ok := args["urls"].([]interface{})
	if !ok || len(rawURLs) == 0 {
		return util.ErrorResult("urls parameter is required and must be non-empty"), nil
	}
	var urls []string
	for _, u := range rawURLs {
		if s, ok := u.(string); ok {
			urls = append(urls, s)
		}
	}

	outputDir := filepath.Join(viper.GetString("output_dir"), target)
	os.MkdirAll(outputDir, 0755)

	opts := probe.DefaultOptions()
	opts.Timeout = 15 * time.Second

	fmt.Printf("[probe] probing %d URLs (common_paths: %v, concurrency: %d)\n",
		len(urls), commonPaths, concurrency)

	// ── Concurrent probing ────────────────────────────────────────────────────
	var allResults []probe.Result
	var mu sync.Mutex
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	probeURL := func(u string) {
		defer wg.Done()
		sem <- struct{}{}
		defer func() { <-sem }()

		result := probe.Probe(u, opts)
		if result.Error == "" {
			mu.Lock()
			allResults = append(allResults, result)
			mu.Unlock()
			fmt.Printf("[probe] %d %s\n", result.StatusCode, u)
		}

		// probe common paths on each host
		if commonPaths {
			pathResults := probe.ProbeCommonPaths(u, opts)
			mu.Lock()
			allResults = append(allResults, pathResults...)
			mu.Unlock()
			for _, r := range pathResults {
				fmt.Printf("[probe] %d %s\n", r.StatusCode, r.URL)
			}
		}
	}

	for _, u := range urls {
		wg.Add(1)
		go probeURL(u)
	}
	wg.Wait()

	if len(allResults) == 0 {
		return util.JSONResult(map[string]interface{}{
			"target":  target,
			"message": "no successful probe responses",
			"urls":    urls,
		}), nil
	}

	fmt.Printf("[probe] captured %d responses — running triage\n", len(allResults))

	// ── Convert probe results to TrafficEntry for triage ─────────────────────
	entries := make([]triage.TrafficEntry, 0, len(allResults))
	for _, r := range allResults {
		entries = append(entries, triage.TrafficEntry{
			Method:          r.Method,
			URL:             r.URL,
			RequestHeaders:  r.RequestHeaders,
			QueryParams:     map[string]string{},
			RequestBody:     "",
			StatusCode:      r.StatusCode,
			ResponseHeaders: r.ResponseHeaders,
			ResponseBody:    r.ResponseBody,
			ContentType:     r.ContentType,
		})
	}

	// ── Heuristic scoring ─────────────────────────────────────────────────────
	var toAnalyze []triage.TrafficEntry
	for _, e := range entries {
		// lower threshold for probe results — we deliberately chose these URLs
		if triage.QuickScore(e) >= 1 {
			toAnalyze = append(toAnalyze, e)
		}
	}

	fmt.Printf("[probe] %d entries passing score threshold\n", len(toAnalyze))

	if len(toAnalyze) == 0 {
		return util.JSONResult(map[string]interface{}{
			"target":        target,
			"probed":        len(allResults),
			"message":       "all responses scored as noise — no interesting findings",
			"probe_summary": buildProbeSummary(allResults),
		}), nil
	}

	// ── Triage ────────────────────────────────────────────────────────────────
	reportFile := filepath.Join(outputDir, "probe-triage-report.md")
	var findings []*triage.Finding

	if multiAgent {
		fmt.Println("[probe] using multi-agent triage (Azure)")
		triager := triage.NewMultiAgentTriager(multiAgentHost)
		if err := triager.Ping(); err != nil {
			return util.ErrorResult(fmt.Sprintf(
				"multi-agent models unreachable at %s: %v\n"+
					"Start SSH tunnel: ssh -i ~/.ssh/bbscout-key2.pem -L 11435:localhost:11434 prabhat@57.158.26.172 -N &",
				multiAgentHost, err,
			)), nil
		}
		var err error
		findings, err = triager.AnalyzeBatch(toAnalyze, 2) // low concurrency for CPU VM
		if err != nil {
			return util.ErrorResult(fmt.Sprintf("multi-agent triage failed: %v", err)), nil
		}
	} else {
		fmt.Println("[probe] using single-model triage (local Ollama)")
		client := triage.NewOllamaClient(viper.GetString("ollama.host"), viper.GetString("ollama.model"))
		if err := client.Ping(); err != nil {
			return util.ErrorResult(fmt.Sprintf("ollama unavailable: %v", err)), nil
		}

		type result struct {
			finding *triage.Finding
			err     error
		}
		results := make([]result, len(toAnalyze))
		sem2 := make(chan struct{}, 3)
		done := make(chan struct{}, len(toAnalyze))

		for i, entry := range toAnalyze {
			go func(idx int, e triage.TrafficEntry) {
				sem2 <- struct{}{}
				defer func() { <-sem2 }()
				f, err := client.AnalyzeEntry(e)
				results[idx] = result{finding: f, err: err}
				done <- struct{}{}
			}(i, entry)
		}
		for range toAnalyze {
			<-done
		}

		for _, r := range results {
			if r.err == nil && r.finding != nil && r.finding.Severity != "noise" {
				findings = append(findings, r.finding)
			}
		}
	}

	// ── Write report ──────────────────────────────────────────────────────────
	triage.WriteFindingsMarkdown(findings, target, reportFile)

	// ── Build summary for orchestrator ────────────────────────────────────────
	severityCounts := map[string]int{}
	var findingDetails []map[string]string
	for _, f := range findings {
		severityCounts[f.Severity]++
		findingDetails = append(findingDetails, map[string]string{
			"severity":    f.Severity,
			"category":    f.Category,
			"url":         f.URL,
			"method":      f.Method,
			"description": f.Description,
			"evidence":    f.Evidence,
			"next_steps":  f.NextSteps,
		})
	}

	return util.JSONResult(map[string]interface{}{
		"target":          target,
		"urls_probed":     len(urls),
		"responses":       len(allResults),
		"analyzed":        len(toAnalyze),
		"findings":        len(findings),
		"severity_counts": severityCounts,
		"finding_details": findingDetails,
		"probe_summary":   buildProbeSummary(allResults),
		"report_file":     reportFile,
	}), nil
}

// buildProbeSummary creates a concise summary of probe results for the orchestrator.
func buildProbeSummary(results []probe.Result) []map[string]interface{} {
	var summary []map[string]interface{}
	for _, r := range results {
		if r.Error != "" {
			continue
		}
		entry := map[string]interface{}{
			"url":          r.URL,
			"status":       r.StatusCode,
			"content_type": r.ContentType,
		}
		// flag interesting status codes
		if r.StatusCode == 200 || r.StatusCode == 301 || r.StatusCode == 302 {
			entry["note"] = statusNote(r)
		}
		// flag interesting content
		if containsInteresting(r.ResponseBody) {
			entry["interesting_content"] = true
		}
		summary = append(summary, entry)
	}
	return summary
}

func statusNote(r probe.Result) string {
	switch r.StatusCode {
	case 200:
		ct := strings.ToLower(r.ContentType)
		if strings.Contains(ct, "json") {
			return "returns JSON — API endpoint"
		}
		if strings.Contains(ct, "html") && len(r.ResponseBody) > 100 {
			return "returns HTML page"
		}
		return "accessible"
	case 301, 302:
		loc := r.ResponseHeaders["location"]
		return fmt.Sprintf("redirects to: %s", loc)
	default:
		return ""
	}
}

func containsInteresting(body string) bool {
	lower := strings.ToLower(body)
	keywords := []string{
		"password", "secret", "token", "api_key", "apikey",
		"private", "internal", "debug", "error", "exception",
		"stack trace", "traceback", "database", "mysql", "postgres",
		"mongodb", "redis", "aws_access", "aws_secret",
	}
	for _, kw := range keywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

// buildProbeToolResult is a helper for the show summary in the terminal.
func buildProbeToolResult(findings int, analyzed int, responses int) string {
	b, _ := json.Marshal(map[string]interface{}{
		"responses": responses,
		"analyzed":  analyzed,
		"findings":  findings,
	})
	return string(b)
}