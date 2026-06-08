package tools

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/spf13/viper"

	"github.com/Cypher-CP0/bbscout/internal/triage"
	"github.com/Cypher-CP0/bbscout/mcp/util"
)

// RegisterTriage registers the triage tool with the MCP server.
func RegisterTriage(s *server.MCPServer) {
	s.AddTool(
		mcp.NewTool("triage",
			mcp.WithDescription(`AI-powered triage of HTTP traffic from Caido or Burp Suite exports.
Parses the export, applies heuristic scoring to filter noise,
then runs Ollama analysis on interesting entries.
Returns severity-ranked findings with next steps.`),
			mcp.WithString("input_file",
				mcp.Required(),
				mcp.Description("Path to Caido JSON export file"),
			),
			mcp.WithString("target",
				mcp.Required(),
				mcp.Description("Target domain to filter traffic by e.g. launchdarkly.com"),
			),
			mcp.WithInteger("concurrency",
				mcp.Description("Parallel Ollama requests. Default 5."),
			),
			mcp.WithInteger("threshold",
				mcp.Description("Min heuristic score to reach Ollama. Default 3. Lower = more entries analyzed."),
			),
			mcp.WithString("model",
				mcp.Description("Ollama model override. Uses config default if not set."),
			),
		),
		handleTriage,
	)
}
 
func handleTriage(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := req.Params.Arguments.(map[string]interface{})
	inputFile := args["input_file"].(string)
	target := args["target"].(string)
 
	concurrency := 5
	if v, ok := args["concurrency"].(float64); ok {
		concurrency = int(v)
	}
	threshold := triage.ScoreThreshold
	if v, ok := args["threshold"].(float64); ok {
		threshold = int(v)
	}
	model := viper.GetString("ollama.model")
	if v, ok := args["model"].(string); ok && v != "" {
		model = v
	}
 
	outputDir := filepath.Join(viper.GetString("output_dir"), target)
	os.MkdirAll(outputDir, 0755)
	reportFile := filepath.Join(outputDir, "triage-report.md")
 
	// ── Parse ─────────────────────────────────────────────────────────────────
	entries, err := triage.ParseHAR(inputFile)
	if err != nil {
		return util.ErrorResult(fmt.Sprintf("parse failed: %v", err)), nil
	}
 
	// ── Filter known noise ────────────────────────────────────────────────────
	filtered := triage.FilterEntries(entries)
 
	// ── Scope to target domain ────────────────────────────────────────────────
	var scoped []triage.TrafficEntry
	for _, e := range filtered {
		if strings.Contains(strings.ToLower(e.URL), strings.ToLower(target)) {
			scoped = append(scoped, e)
		}
	}
 
	if len(scoped) == 0 {
		return util.JSONResult(map[string]interface{}{
			"target":      target,
			"message":     "no entries found for target after filtering",
			"total_in":    len(entries),
			"after_filter": len(filtered),
		}), nil
	}
 
	// ── Heuristic scoring ─────────────────────────────────────────────────────
	var toAnalyze []triage.TrafficEntry
	autoNoise := 0
	for _, e := range scoped {
		if triage.QuickScore(e) >= threshold {
			toAnalyze = append(toAnalyze, e)
		} else {
			autoNoise++
		}
	}
 
	// ── Ollama availability check ─────────────────────────────────────────────
	client := triage.NewOllamaClient(viper.GetString("ollama.host"), model)
	if err := client.Ping(); err != nil {
		return util.ErrorResult(fmt.Sprintf("ollama unavailable: %v — run: ollama serve", err)), nil
	}
 
	// ── Concurrent Ollama analysis ────────────────────────────────────────────
	type result struct {
		finding *triage.Finding
		err     error
	}
	results := make([]result, len(toAnalyze))
	sem := make(chan struct{}, concurrency)
	done := make(chan struct{}, len(toAnalyze))
 
	for i, entry := range toAnalyze {
		go func(idx int, e triage.TrafficEntry) {
			sem <- struct{}{}
			defer func() { <-sem }()
			f, err := client.AnalyzeEntry(e)
			results[idx] = result{finding: f, err: err}
			done <- struct{}{}
		}(i, entry)
	}
	for range toAnalyze {
		<-done
	}
 
	// ── Collect findings ──────────────────────────────────────────────────────
	var findings []*triage.Finding
	errors := 0
	for _, r := range results {
		if r.err != nil {
			errors++
			continue
		}
		if r.finding != nil && r.finding.Severity != "noise" {
			findings = append(findings, r.finding)
		}
	}
 
	// ── Write markdown report ─────────────────────────────────────────────────
	triage.WriteFindingsMarkdown(findings, target, reportFile)
 
	// ── Build summary for Claude ──────────────────────────────────────────────
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
		"total_in":        len(entries),
		"after_filter":    len(scoped),
		"auto_noise":      autoNoise,
		"analyzed":        len(toAnalyze),
		"findings":        len(findings),
		"errors":          errors,
		"severity_counts": severityCounts,
		"finding_details": findingDetails,
		"report_file":     reportFile,
	}), nil
}