package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/spf13/viper"

	"github.com/Cypher-CP0/bbscout/internal/scan"
	"github.com/Cypher-CP0/bbscout/mcp/util"
)

// RegisterScan registers the scan tool with the MCP server.
func RegisterScan(s *server.MCPServer) {
	s.AddTool(
		mcp.NewTool("scan",
			mcp.WithDescription(`Run nuclei template scanning and subdomain takeover detection.
Nuclei checks for known CVEs, misconfigs, and exposed files.
Subzy checks for subdomain takeover vulnerabilities.
Returns full findings content so the orchestrator can reason about them.`),
			mcp.WithString("target",
				mcp.Required(),
				mcp.Description("Target domain e.g. launchdarkly.com"),
			),
			mcp.WithString("severity",
				mcp.Description("Nuclei severity filter. Default: low,medium,high,critical"),
			),
			mcp.WithBoolean("use_urls",
				mcp.Description("Scan urls-interesting.txt instead of live.txt (deeper). Default false."),
			),
			mcp.WithBoolean("skip_subzy",
				mcp.Description("Skip subdomain takeover check. Default false."),
			),
			mcp.WithInteger("rate_limit",
				mcp.Description("Nuclei requests per second. Default 150."),
			),
		),
		handleScan,
	)
}

func handleScan(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := req.Params.Arguments.(map[string]interface{})

	target := args["target"].(string)
	severity, _ := args["severity"].(string)
	useURLs, _ := args["use_urls"].(bool)
	skipSubzy, _ := args["skip_subzy"].(bool)
	rateLimit := 150
	if v, ok := args["rate_limit"].(float64); ok {
		rateLimit = int(v)
	}

	outputDir := filepath.Join(viper.GetString("output_dir"), target)

	// pick input file
	nucleiInput := filepath.Join(outputDir, "live.txt")
	if useURLs {
		nucleiInput = filepath.Join(outputDir, "urls-interesting.txt")
	}
	if _, err := os.Stat(nucleiInput); os.IsNotExist(err) {
		return util.ErrorResult(fmt.Sprintf("%s not found — run recon first", filepath.Base(nucleiInput))), nil
	}

	nucleiFile := filepath.Join(outputDir, "nuclei-findings.json")
	subzyFile := filepath.Join(outputDir, "subzy-findings.txt")

	// run nuclei + subzy in parallel
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		scan.RunNuclei(scan.NucleiOptions{
			Binary:    viper.GetString("tools.nuclei"),
			InputFile: nucleiInput,
			OutputDir: outputDir,
			Severity:  severity,
			Templates: viper.GetString("nuclei.templates"),
			RateLimit: rateLimit,
		})
	}()

	if !skipSubzy {
		resolvedFile := filepath.Join(outputDir, "resolved-hosts.txt")
		if _, err := os.Stat(resolvedFile); err == nil {
			wg.Add(1)
			go func() {
				defer wg.Done()
				scan.RunSubzy(scan.SubzyOptions{
					Binary:    viper.GetString("tools.subzy"),
					InputFile: resolvedFile,
					OutputDir: outputDir,
				})
			}()
		}
	}

	wg.Wait()

	// ── Read actual nuclei findings ───────────────────────────────────────────
	nucleiFindings := readNucleiFindings(nucleiFile)
	nucleiCount := len(nucleiFindings)

	// ── Read subzy vulnerable hosts ───────────────────────────────────────────
	vulnerableHosts := readSubzyVulnerable(subzyFile)
	vulnerableCount := len(vulnerableHosts)

	// ── Build result with full content ────────────────────────────────────────
	result := map[string]interface{}{
		"target":              target,
		"nuclei_findings":     nucleiCount,
		"nuclei_file":         nucleiFile,
		"takeover_candidates": vulnerableCount,
		"subzy_file":          subzyFile,
		"input_used":          nucleiInput,
	}

	// include actual findings so orchestrator can reason about them
	if nucleiCount > 0 {
		result["nuclei_details"] = nucleiFindings
	} else {
		result["nuclei_details"] = []interface{}{}
		result["nuclei_note"] = "No findings — target may be behind WAF/CDN (e.g. Cloudflare) blocking automated scanners. Manual testing recommended."
	}

	if vulnerableCount > 0 {
		result["vulnerable_hosts"] = vulnerableHosts
	} else {
		result["vulnerable_hosts"] = []interface{}{}
	}

	// include interesting hosts from live.txt for orchestrator context
	liveFile := filepath.Join(outputDir, "live.txt")
	interestingHosts := findInterestingFromFile(liveFile)
	// always include field so orchestrator can check it
	result["interesting_hosts_for_manual_testing"] = interestingHosts
	if len(interestingHosts) > 0 {
		result["probe_recommended"] = true
		result["probe_note"] = "Call probe tool with these URLs and multi_agent=true, multi_agent_host=http://localhost:11435"
	}

	// include sample of interesting URLs for context
	urlsFile := filepath.Join(outputDir, "urls-interesting.txt")
	urlCount, _ := util.CountLines(urlsFile)
	if urlCount > 0 {
		result["interesting_urls_count"] = urlCount
		result["interesting_urls_sample"] = readSampleLines(urlsFile, 20)
		result["interesting_urls_file"] = urlsFile
	}

	return util.JSONResult(result), nil
}

// readNucleiFindings parses the nuclei JSON output file.
// Each line is a separate JSON object.
func readNucleiFindings(path string) []map[string]interface{} {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var findings []map[string]interface{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var finding map[string]interface{}
		if err := json.Unmarshal([]byte(line), &finding); err != nil {
			continue
		}
		// extract key fields for orchestrator
		summary := map[string]interface{}{
			"template":    finding["template-id"],
			"name":        finding["info"],
			"severity":    getSeverity(finding),
			"host":        finding["host"],
			"matched":     finding["matched-at"],
			"description": getDescription(finding),
			"reference":   getReference(finding),
		}
		findings = append(findings, summary)
	}
	return findings
}

// readSubzyVulnerable extracts vulnerable hosts from subzy output.
func readSubzyVulnerable(path string) []map[string]interface{} {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var vulnerable []map[string]interface{}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.Contains(line, "[ VULNERABLE ]") {
			continue
		}
		// parse: [ VULNERABLE ]  -  subdomain.example.com  [ Service ]
		parts := strings.Split(line, "-")
		if len(parts) < 2 {
			continue
		}
		host := strings.TrimSpace(parts[1])
		service := ""
		if idx := strings.Index(line, "["); idx != -1 {
			if end := strings.Index(line[idx+1:], "]"); end != -1 {
				last := strings.LastIndex(line, "[")
				if last != idx {
					service = strings.Trim(line[last+1:], "] ")
				}
			}
		}
		vulnerable = append(vulnerable, map[string]interface{}{
			"host":    host,
			"service": service,
			"note":    "Verify manually — confirm CNAME points to unclaimed service before reporting",
		})
	}
	return vulnerable
}

// readSampleLines returns the first n non-empty lines from a file.
func readSampleLines(path string, n int) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var lines []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		lines = append(lines, line)
		if len(lines) >= n {
			break
		}
	}
	return lines
}

// findInterestingFromFile finds security-relevant subdomains in a live hosts file.
func findInterestingFromFile(liveFile string) []string {
	data, err := os.ReadFile(liveFile)
	if err != nil {
		return nil
	}
	keywords := []string{
		"admin", "api", "internal", "dev", "staging", "stg",
		"origin", "beta", "test", "debug", "partner", "dashboard",
		"management", "console", "portal", "backend", "private",
		"nft", "cs", "pay", "auth", "login", "account",
	}
	var interesting []string
	seen := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || seen[line] {
			continue
		}
		lower := strings.ToLower(line)
		for _, kw := range keywords {
			if strings.Contains(lower, kw) {
				interesting = append(interesting, line)
				seen[line] = true
				break
			}
		}
	}
	return interesting
}

func getSeverity(finding map[string]interface{}) string {
	if info, ok := finding["info"].(map[string]interface{}); ok {
		if sev, ok := info["severity"].(string); ok {
			return sev
		}
	}
	return "unknown"
}

func getDescription(finding map[string]interface{}) string {
	if info, ok := finding["info"].(map[string]interface{}); ok {
		if desc, ok := info["description"].(string); ok {
			return desc
		}
		if name, ok := info["name"].(string); ok {
			return name
		}
	}
	return ""
}

func getReference(finding map[string]interface{}) interface{} {
	if info, ok := finding["info"].(map[string]interface{}); ok {
		if ref, ok := info["reference"]; ok {
			return ref
		}
	}
	return nil
}