package cmd

import (
	"fmt"
	"os"
	"sync"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/Cypher-CP0/bbscout/internal/crawl"
)

var crawlCmd = &cobra.Command{
	Use:   "crawl",
	Short: "Crawl live hosts with katana + gau + waybackurls",
	Example: `  bbscout crawl --target example.com
  bbscout crawl --target example.com --depth 5
  bbscout crawl --target example.com --skip-wayback`,
	RunE: runCrawl,
}

func init() {
	rootCmd.AddCommand(crawlCmd)
	crawlCmd.Flags().StringP("target", "t", "", "target domain (required)")
	crawlCmd.Flags().Int("depth", 3, "katana crawl depth")
	crawlCmd.Flags().Bool("skip-wayback", false, "skip waybackurls (faster)")
	crawlCmd.Flags().Bool("skip-gau", false, "skip gau (faster)")
	crawlCmd.MarkFlagRequired("target")
}

func runCrawl(cmd *cobra.Command, args []string) error {
	target, _ := cmd.Flags().GetString("target")
	depth, _ := cmd.Flags().GetInt("depth")
	skipWayback, _ := cmd.Flags().GetBool("skip-wayback")
	skipGau, _ := cmd.Flags().GetBool("skip-gau")

	baseOutput := viper.GetString("output_dir")
	outputDir := fmt.Sprintf("%s/%s", baseOutput, target)

	// live.txt from recon must exist
	liveFile := fmt.Sprintf("%s/live.txt", outputDir)
	if _, err := os.Stat(liveFile); os.IsNotExist(err) {
		return fmt.Errorf("live.txt not found at %s — run 'bbscout recon --target %s' first", liveFile, target)
	}

	fmt.Printf("\n[bbscout] starting crawl on %s\n", target)
	fmt.Printf("[bbscout] input  → %s\n", liveFile)
	fmt.Printf("[bbscout] output → %s\n\n", outputDir)

	// ── STAGE 1: Crawl (parallel) ────────────────────────────────────────────

	fmt.Println("[stage 1/3] crawling live hosts")

	var wg sync.WaitGroup
	var mu sync.Mutex
	var urlFiles []string

	addFile := func(path string) {
		mu.Lock()
		urlFiles = append(urlFiles, path)
		mu.Unlock()
	}

	// katana — active JS crawl
	wg.Add(1)
	go func() {
		defer wg.Done()
		f, err := crawl.RunKatana(crawl.KatanaOptions{
			Binary:    viper.GetString("tools.katana"),
			InputFile: liveFile,
			OutputDir: outputDir,
			Depth:     depth,
		})
		if err != nil {
			fmt.Println("[warn] katana:", err)
			return
		}
		addFile(f)
	}()

	// gau — historical URLs
	if !skipGau {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// gau runs per-host so use resolved-hosts.txt for clean input
			hostsFile := fmt.Sprintf("%s/resolved-hosts.txt", outputDir)
			if _, err := os.Stat(hostsFile); os.IsNotExist(err) {
				hostsFile = liveFile // fall back to live.txt
			}
			f, err := crawl.RunGau(crawl.GauOptions{
				Binary:    viper.GetString("tools.gau"),
				InputFile: hostsFile,
				OutputDir: outputDir,
			})
			if err != nil {
				fmt.Println("[warn] gau:", err)
				return
			}
			addFile(f)
		}()
	}

	// waybackurls — wayback machine
	if !skipWayback {
		wg.Add(1)
		go func() {
			defer wg.Done()
			hostsFile := fmt.Sprintf("%s/resolved-hosts.txt", outputDir)
			if _, err := os.Stat(hostsFile); os.IsNotExist(err) {
				hostsFile = liveFile
			}
			f, err := crawl.RunWaybackurls(crawl.WaybackOptions{
				Binary:    viper.GetString("tools.waybackurls"),
				InputFile: hostsFile,
				OutputDir: outputDir,
			})
			if err != nil {
				fmt.Println("[warn] waybackurls:", err)
				return
			}
			addFile(f)
		}()
	}

	wg.Wait()

	if len(urlFiles) == 0 {
		return fmt.Errorf("all crawlers failed — check tool installations")
	}

	// ── STAGE 2: Merge + dedup ───────────────────────────────────────────────

	fmt.Println("\n[stage 2/3] merging and deduplicating URLs")

	mergedFile := fmt.Sprintf("%s/urls-all.txt", outputDir)
	total, err := crawl.MergeAndDedup(urlFiles, mergedFile)
	if err != nil {
		return fmt.Errorf("merge: %w", err)
	}
	if total == 0 {
		fmt.Println("[bbscout] no URLs found")
		return nil
	}

	// ── STAGE 3: Filter interesting URLs ────────────────────────────────────

	fmt.Println("\n[stage 3/3] filtering out static assets")

	interestingFile, err := crawl.FilterInteresting(mergedFile, outputDir)
	if err != nil {
		fmt.Println("[warn] filter:", err)
		interestingFile = mergedFile
	}

	// ── Summary ──────────────────────────────────────────────────────────────

	fmt.Printf(`
[bbscout] crawl complete for %s

  all URLs          → %s
  interesting URLs  → %s

next steps:
  bbscout scan   --target %s
  bbscout triage --input <burp-export.har>
`, target, mergedFile, interestingFile, target)

	return nil
}