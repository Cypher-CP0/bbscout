package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/Cypher-CP0/bbscout/internal/scan"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run nuclei + subzy on live hosts",
	Example: `  bbscout scan --target example.com
  bbscout scan --target example.com --severity high,critical
  bbscout scan --target example.com --skip-subzy
  bbscout scan --target example.com --urls`,
	RunE: runScan,
}

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.Flags().StringP("target", "t", "", "target domain (required)")
	scanCmd.Flags().String("severity", "", "nuclei severity filter (default: low,medium,high,critical)")
	scanCmd.Flags().Bool("skip-subzy", false, "skip subdomain takeover check")
	scanCmd.Flags().Bool("urls", false, "scan urls-interesting.txt instead of live.txt (post-crawl)")
	scanCmd.Flags().Int("rate-limit", 150, "nuclei requests per second")
	scanCmd.MarkFlagRequired("target")
}

func runScan(cmd *cobra.Command, args []string) error {
	target, _ := cmd.Flags().GetString("target")
	severity, _ := cmd.Flags().GetString("severity")
	skipSubzy, _ := cmd.Flags().GetBool("skip-subzy")
	useURLs, _ := cmd.Flags().GetBool("urls")
	rateLimit, _ := cmd.Flags().GetInt("rate-limit")

	baseOutput := viper.GetString("output_dir")
	outputDir := fmt.Sprintf("%s/%s", baseOutput, target)

	// pick input — live hosts from recon, or interesting URLs from crawl
	var nucleiInput string
	if useURLs {
		nucleiInput = fmt.Sprintf("%s/urls-interesting.txt", outputDir)
		if _, err := os.Stat(nucleiInput); os.IsNotExist(err) {
			return fmt.Errorf("urls-interesting.txt not found — run 'bbscout crawl --target %s' first", target)
		}
	} else {
		nucleiInput = fmt.Sprintf("%s/live.txt", outputDir)
		if _, err := os.Stat(nucleiInput); os.IsNotExist(err) {
			return fmt.Errorf("live.txt not found — run 'bbscout recon --target %s' first", target)
		}
	}

	// subzy needs the resolved hosts file
	resolvedFile := fmt.Sprintf("%s/resolved-hosts.txt", outputDir)
	if _, err := os.Stat(resolvedFile); os.IsNotExist(err) {
		resolvedFile = fmt.Sprintf("%s/resolved.txt", outputDir)
	}

	fmt.Printf("\n[bbscout] starting scan on %s\n", target)
	fmt.Printf("[bbscout] nuclei input → %s\n", nucleiInput)
	fmt.Printf("[bbscout] output       → %s\n\n", outputDir)

	// ── Run nuclei + subzy in parallel ───────────────────────────────────────

	fmt.Println("[stage 1/2] running nuclei + subzy in parallel")

	var wg sync.WaitGroup
	var mu sync.Mutex
	var findingFiles []string

	addFile := func(path string) {
		mu.Lock()
		findingFiles = append(findingFiles, path)
		mu.Unlock()
	}

	// nuclei
	wg.Add(1)
	go func() {
		defer wg.Done()
		f, err := scan.RunNuclei(scan.NucleiOptions{
			Binary:    viper.GetString("tools.nuclei"),
			InputFile: nucleiInput,
			OutputDir: outputDir,
			Severity:  severity,
			Templates: viper.GetString("nuclei.templates"),
			RateLimit: rateLimit,
		})
		if err != nil {
			fmt.Println("[warn] nuclei:", err)
			return
		}
		addFile(f)
	}()

	// subzy
	if !skipSubzy {
		if _, err := os.Stat(resolvedFile); err == nil {
			wg.Add(1)
			go func() {
				defer wg.Done()
				f, err := scan.RunSubzy(scan.SubzyOptions{
					Binary:    viper.GetString("tools.subzy"),
					InputFile: resolvedFile,
					OutputDir: outputDir,
				})
				if err != nil {
					fmt.Println("[warn] subzy:", err)
					return
				}
				addFile(f)
			}()
		} else {
			fmt.Println("[warn] resolved hosts file not found, skipping subzy")
		}
	}

	wg.Wait()

	// ── Summary ──────────────────────────────────────────────────────────────

	fmt.Println("\n[stage 2/2] summarizing findings")

	nucleiOut := fmt.Sprintf("%s/nuclei-findings.json", outputDir)
	subzyOut := fmt.Sprintf("%s/subzy-findings.txt", outputDir)

	nucleiCount := 0
	subzyCount := 0

	if f, err := os.Stat(nucleiOut); err == nil && f.Size() > 0 {
		nucleiCount, _ = countLines(nucleiOut)
	}
	if f, err := os.Stat(subzyOut); err == nil && f.Size() > 0 {
		subzyCount, _ = countVulnerable(subzyOut)
	}

	fmt.Printf(`
[bbscout] scan complete for %s

  nuclei findings   → %s (%d)
  takeover targets  → %s (%d)

next steps:
  bbscout triage --input <burp-export.har>
  bbscout report --target %s
`, target,
		nucleiOut, nucleiCount,
		subzyOut, subzyCount,
		target,
	)

	if subzyCount > 0 {
		fmt.Printf("\n[!] %d potential subdomain takeover(s) found — check %s\n", subzyCount, subzyOut)
	}

	return nil
}

func countLines(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	count := 0
	buf := make([]byte, 32*1024)
	for {
		n, readErr := f.Read(buf)
		for i := 0; i < n; i++ {
			if buf[i] == '\n' {
				count++
			}
		}
		if readErr != nil {
			break
		}
	}
	return count, nil
}

// countVulnerable counts only lines containing "[ VULNERABLE ]" in subzy output.
func countVulnerable(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	count := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), "[ VULNERABLE ]") {
			count++
		}
	}
	return count, scanner.Err()
}