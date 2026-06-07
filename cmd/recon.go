package cmd

import (
	"fmt"
	"os"
	"sync"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/Cypher-CP0/bbscout/internal/recon"
)

var reconCmd = &cobra.Command{
	Use:   "recon",
	Short: "Run full recon pipeline on a target domain",
	Example: `  bbscout recon --target example.com
  bbscout recon --target example.com --ports top-100
  bbscout recon --target example.com --skip-screenshots`,
	RunE: runRecon,
}

func init() {
	rootCmd.AddCommand(reconCmd)
	reconCmd.Flags().StringP("target", "t", "", "target domain (required)")
	reconCmd.Flags().String("ports", "top-1000", "ports for naabu scan (e.g. top-100, 80,443,8080)")
	reconCmd.Flags().Bool("skip-screenshots", false, "skip gowitness screenshots")
	reconCmd.Flags().Bool("skip-ports", false, "skip naabu port scan, go straight to httpx on port 80/443")
	reconCmd.MarkFlagRequired("target")
}

func runRecon(cmd *cobra.Command, args []string) error {
	target, _ := cmd.Flags().GetString("target")
	ports, _ := cmd.Flags().GetString("ports")
	skipScreenshots, _ := cmd.Flags().GetBool("skip-screenshots")
	skipPorts, _ := cmd.Flags().GetBool("skip-ports")

	baseOutput := viper.GetString("output_dir")
	outputDir := fmt.Sprintf("%s/%s", baseOutput, target)

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	fmt.Printf("\n[bbscout] starting recon on %s\n", target)
	fmt.Printf("[bbscout] output → %s\n\n", outputDir)

	// ── STAGE 1: Subdomain enumeration (parallel) ────────────────────────────

	fmt.Println("[stage 1/5] subdomain enumeration")

	var wg sync.WaitGroup
	var mu sync.Mutex
	var subFiles []string

	addFile := func(path string) {
		mu.Lock()
		subFiles = append(subFiles, path)
		mu.Unlock()
	}

	// subfinder
	wg.Add(1)
	go func() {
		defer wg.Done()
		f, err := recon.RunSubfinder(recon.SubfinderOptions{
			Binary:    viper.GetString("tools.subfinder"),
			Target:    target,
			OutputDir: outputDir,
		})
		if err != nil {
			fmt.Println("[warn] subfinder:", err)
			return
		}
		addFile(f)
	}()

	// assetfinder
	wg.Add(1)
	go func() {
		defer wg.Done()
		f, err := recon.RunAssetfinder(
			viper.GetString("tools.assetfinder"),
			target,
			outputDir,
		)
		if err != nil {
			fmt.Println("[warn] assetfinder:", err)
			return
		}
		addFile(f)
	}()

	// crt.sh — pure Go, no binary
	wg.Add(1)
	go func() {
		defer wg.Done()
		f, err := recon.RunCrtSh(target, outputDir)
		if err != nil {
			fmt.Println("[warn] crt.sh:", err)
			return
		}
		addFile(f)
	}()

	wg.Wait()

	// ── STAGE 2: Merge + dedup ───────────────────────────────────────────────

	fmt.Println("\n[stage 2/5] merging and deduplicating subdomains")

	mergedFile := fmt.Sprintf("%s/subdomains-all.txt", outputDir)
	total, err := recon.MergeAndDedup(subFiles, mergedFile)
	if err != nil {
		return fmt.Errorf("merge: %w", err)
	}
	if total == 0 {
		fmt.Println("[bbscout] no subdomains found, exiting")
		return nil
	}

	// ── STAGE 3: DNS resolution ──────────────────────────────────────────────

	fmt.Println("\n[stage 3/5] resolving subdomains with dnsx")

	resolvedFile, plainHostsFile, err := recon.RunDnsx(recon.DnsxOptions{
		Binary:    viper.GetString("tools.dnsx"),
		InputFile: mergedFile,
		OutputDir: outputDir,
	})
	if err != nil {
		return fmt.Errorf("dnsx: %w", err)
	}

	// ── STAGE 4: Port scan + HTTP probe ─────────────────────────────────────

	fmt.Println("\n[stage 4/5] port scanning + HTTP probing")

	httpxInput := plainHostsFile

	if !skipPorts {
		portsFile, err := recon.RunNaabu(recon.NaabuOptions{
			Binary:    viper.GetString("tools.naabu"),
			InputFile: plainHostsFile,
			OutputDir: outputDir,
			Ports:     ports,
		})
		if err != nil {
			fmt.Println("[warn] naabu:", err)
			fmt.Println("[warn] falling back to plain hosts for httpx")
		} else {
			httpxInput = portsFile
		}
	}

	_, liveFile, err := recon.RunHttpx(recon.HttpxOptions{
		Binary:    viper.GetString("tools.httpx"),
		InputFile: httpxInput,
		OutputDir: outputDir,
	})
	if err != nil {
		return fmt.Errorf("httpx: %w", err)
	}

	// ── STAGE 5: Screenshots ─────────────────────────────────────────────────

	if !skipScreenshots {
		fmt.Println("\n[stage 5/5] taking screenshots with gowitness")

		screenshotDir := fmt.Sprintf("%s/screenshots", outputDir)
		if err := recon.RunGowitness(recon.GoWitnessOptions{
			Binary:        viper.GetString("tools.gowitness"),
			InputFile:     liveFile,
			ScreenshotDir: screenshotDir,
		}); err != nil {
			fmt.Println("[warn] gowitness:", err)
		}
	} else {
		fmt.Println("\n[stage 5/5] screenshots skipped")
	}

	// ── Summary ──────────────────────────────────────────────────────────────

	fmt.Printf(`
[bbscout] recon complete for %s

  subdomains found  → %s
  resolved hosts    → %s
  plain hosts       → %s
  live HTTP         → %s
  screenshots       → %s/screenshots/

next steps:
  bbscout crawl  --target %s
  bbscout scan   --target %s
`, target,
		mergedFile,
		resolvedFile,
		plainHostsFile,
		liveFile,
		outputDir,
		target,
		target,
	)

	return nil
}