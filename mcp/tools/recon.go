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

	"github.com/Cypher-CP0/bbscout/internal/recon"
	"github.com/Cypher-CP0/bbscout/mcp/util"
)

// RegisterRecon registers the recon tool with the MCP server.
func RegisterRecon(s *server.MCPServer) {
	s.AddTool(
		mcp.NewTool("recon",
			mcp.WithDescription(`Run full recon pipeline on a target domain.
Discovers subdomains via subfinder + assetfinder + crt.sh,
resolves DNS, scans ports, probes live HTTP services.
Returns live host count and list of interesting subdomains.`),
			mcp.WithString("target",
				mcp.Required(),
				mcp.Description("Target domain e.g. launchdarkly.com"),
			),
			mcp.WithArray("scope",
				mcp.Description("In-scope subdomains only. If set, only these are processed."),
			),
			mcp.WithBoolean("skip_ports",
				mcp.Description("Skip naabu port scan. Default false."),
			),
			mcp.WithBoolean("skip_screenshots",
				mcp.Description("Skip gowitness screenshots. Default true."),
			),
		),
		handleRecon,
	)
}

func handleRecon(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := req.Params.Arguments.(map[string]interface{})
	target := args["target"].(string)
	skipPorts, _ := args["skip_ports"].(bool)
	skipScreenshots := true
	if v, ok := args["skip_screenshots"].(bool); ok {
		skipScreenshots = v
	}
	scope := util.ExtractScope(args["scope"])

	outputDir := filepath.Join(viper.GetString("output_dir"), target)
	os.MkdirAll(outputDir, 0755)

	// ── Stage 1: subdomain discovery (parallel) ───────────────────────────────
	var wg sync.WaitGroup
	var subFiles []string
	var mu sync.Mutex

	wg.Add(1)
	go func() {
		defer wg.Done()
		f, err := recon.RunSubfinder(recon.SubfinderOptions{
			Binary:    viper.GetString("tools.subfinder"),
			Target:    target,
			OutputDir: outputDir,
		})
		if err == nil {
			mu.Lock()
			subFiles = append(subFiles, f)
			mu.Unlock()
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		f, err := recon.RunAssetfinder(viper.GetString("tools.assetfinder"), target, outputDir)
		if err == nil {
			mu.Lock()
			subFiles = append(subFiles, f)
			mu.Unlock()
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		f, err := recon.RunCrtSh(target, outputDir)
		if err == nil {
			mu.Lock()
			subFiles = append(subFiles, f)
			mu.Unlock()
		}
	}()

	wg.Wait()

	// ── Stage 2: merge subdomains ─────────────────────────────────────────────
	mergedSubs := filepath.Join(outputDir, "subdomains-all.txt")
	subCount, _ := recon.MergeAndDedup(subFiles, mergedSubs)

	// ── Stage 3: DNS resolution ───────────────────────────────────────────────
	_, hostsFile, err := recon.RunDnsx(recon.DnsxOptions{
		Binary:    viper.GetString("tools.dnsx"),
		InputFile: mergedSubs,
		OutputDir: outputDir,
	})
	if err != nil {
		return util.ErrorResult(fmt.Sprintf("dnsx failed: %v", err)), nil
	}

	// apply scope filter if provided
	if len(scope) > 0 {
		hostsFile = util.FilterByScope(hostsFile, scope, outputDir)
	}

	// ── Stage 4: port scan (optional) ────────────────────────────────────────
	if !skipPorts {
		recon.RunNaabu(recon.NaabuOptions{
			Binary:    viper.GetString("tools.naabu"),
			InputFile: hostsFile,
			OutputDir: outputDir,
		})
	}

	// ── Stage 5: httpx ────────────────────────────────────────────────────────
	_, liveFile, err := recon.RunHttpx(recon.HttpxOptions{
		Binary:    viper.GetString("tools.httpx"),
		InputFile: hostsFile,
		OutputDir: outputDir,
	})
	if err != nil {
		return util.ErrorResult(fmt.Sprintf("httpx failed: %v", err)), nil
	}

	// ── Stage 6: screenshots (optional) ──────────────────────────────────────
	if !skipScreenshots {
		recon.RunGowitness(recon.GoWitnessOptions{
			Binary:    viper.GetString("tools.gowitness"),
			InputFile: liveFile,
			ScreenshotDir: outputDir + "/screenshots",
		})
	}

	liveCount, _ := util.CountLines(liveFile)
	interesting := util.FindInterestingHosts(liveFile)

	return util.JSONResult(map[string]interface{}{
		"target":            target,
		"subdomains_found":  subCount,
		"live_hosts":        liveCount,
		"interesting_hosts": interesting,
		"live_file":         liveFile,
		"output_dir":        outputDir,
		"scope_applied":     len(scope) > 0,
	}), nil
}