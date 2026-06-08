package tools

import (
	"context"
	"os"
	"path/filepath"
	"sync"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/spf13/viper"

	"github.com/Cypher-CP0/bbscout/internal/crawl"
	"github.com/Cypher-CP0/bbscout/mcp/util"
)

// RegisterCrawl registers the crawl tool with the MCP server.
func RegisterCrawl(s *server.MCPServer) {
	s.AddTool(
		mcp.NewTool("crawl",
			mcp.WithDescription(`Crawl live hosts to discover URLs and API endpoints.
Runs katana (active JS crawl) + gau (historical URLs) + waybackurls in parallel.
Returns total URL count and path to interesting URLs file.`),
			mcp.WithString("target",
				mcp.Required(),
				mcp.Description("Target domain e.g. launchdarkly.com"),
			),
			mcp.WithInteger("depth",
				mcp.Description("Katana crawl depth. Default 3."),
			),
			mcp.WithBoolean("skip_gau",
				mcp.Description("Skip gau historical URLs. Default false."),
			),
			mcp.WithBoolean("skip_wayback",
				mcp.Description("Skip waybackurls. Default false."),
			),
		),
		handleCrawl,
	)
}
 
func handleCrawl(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := req.Params.Arguments.(map[string]interface{})
	target := args["target"].(string)
	depth := 3
	if v, ok := args["depth"].(float64); ok {
		depth = int(v)
	}
	skipGau, _ := args["skip_gau"].(bool)
	skipWayback, _ := args["skip_wayback"].(bool)
 
	outputDir := filepath.Join(viper.GetString("output_dir"), target)
	liveFile := filepath.Join(outputDir, "live.txt")
 
	if _, err := os.Stat(liveFile); os.IsNotExist(err) {
		return util.ErrorResult("live.txt not found — run recon first"), nil
	}
 
	var urlFiles []string
	var wg sync.WaitGroup
	var mu sync.Mutex
 
	// katana — always runs
	wg.Add(1)
	go func() {
		defer wg.Done()
		f, err := crawl.RunKatana(crawl.KatanaOptions{
			Binary:    viper.GetString("tools.katana"),
			InputFile: liveFile,
			OutputDir: outputDir,
			Depth:     depth,
		})
		if err == nil {
			mu.Lock()
			urlFiles = append(urlFiles, f)
			mu.Unlock()
		}
	}()
 
	// gau — optional
	if !skipGau {
		wg.Add(1)
		go func() {
			defer wg.Done()
			hostsFile := filepath.Join(outputDir, "resolved-hosts.txt")
			if _, err := os.Stat(hostsFile); os.IsNotExist(err) {
				hostsFile = liveFile
			}
			f, err := crawl.RunGau(crawl.GauOptions{
				Binary:    viper.GetString("tools.gau"),
				InputFile: hostsFile,
				OutputDir: outputDir,
			})
			if err == nil {
				mu.Lock()
				urlFiles = append(urlFiles, f)
				mu.Unlock()
			}
		}()
	}
 
	// waybackurls — optional
	if !skipWayback {
		wg.Add(1)
		go func() {
			defer wg.Done()
			hostsFile := filepath.Join(outputDir, "resolved-hosts.txt")
			if _, err := os.Stat(hostsFile); os.IsNotExist(err) {
				hostsFile = liveFile
			}
			f, err := crawl.RunWaybackurls(crawl.WaybackOptions{
				Binary:    viper.GetString("tools.waybackurls"),
				InputFile: hostsFile,
				OutputDir: outputDir,
			})
			if err == nil {
				mu.Lock()
				urlFiles = append(urlFiles, f)
				mu.Unlock()
			}
		}()
	}
 
	wg.Wait()
 
	mergedFile := filepath.Join(outputDir, "urls-all.txt")
	total, _ := crawl.MergeAndDedup(urlFiles, mergedFile)
	interestingFile, _ := crawl.FilterInteresting(mergedFile, outputDir)
	interestingCount, _ := util.CountLines(interestingFile)
 
	return util.JSONResult(map[string]interface{}{
		"target":           target,
		"total_urls":       total,
		"interesting_urls": interestingCount,
		"interesting_file": interestingFile,
		"all_urls_file":    mergedFile,
	}), nil
}