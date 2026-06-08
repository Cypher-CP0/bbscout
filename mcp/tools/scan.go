package tools

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
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
Returns findings count and file paths.`),
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
 
	nucleiCount, _ := util.CountLines(nucleiFile)
	vulnerableCount, _ := util.CountVulnerable(subzyFile)
 
	return util.JSONResult(map[string]interface{}{
		"target":              target,
		"nuclei_findings":     nucleiCount,
		"nuclei_file":         nucleiFile,
		"takeover_candidates": vulnerableCount,
		"subzy_file":          subzyFile,
		"input_used":          nucleiInput,
	}), nil
}