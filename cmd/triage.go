package cmd

import (
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/Cypher-CP0/bbscout/internal/triage"
)

var triageCmd = &cobra.Command{
	Use:   "triage",
	Short: "AI triage of Caido/Burp exports via local Ollama",
	Example: `  bbscout triage --input export.json --target mercari.com
  bbscout triage --input export.json --target mercari.com --concurrency 8
  bbscout triage --input export.json --target mercari.com --threshold 2`,
	RunE: runTriage,
}

func init() {
	rootCmd.AddCommand(triageCmd)
	triageCmd.Flags().StringP("input", "i", "", "Caido/Burp JSON export to analyze (required)")
	triageCmd.Flags().StringP("target", "t", "", "target domain — only analyze requests to this domain")
	triageCmd.Flags().String("model", "", "Ollama model to use (overrides config)")
	triageCmd.Flags().Bool("no-noise", true, "exclude noise findings from output")
	triageCmd.Flags().String("output", "", "output markdown report path (optional)")
	triageCmd.Flags().Int("concurrency", 5, "parallel Ollama requests")
	triageCmd.Flags().Int("threshold", triage.ScoreThreshold, "min heuristic score to send to Ollama (lower = more entries)")
	triageCmd.Flags().Bool("multi-agent", false, "use two-stage multi-model pipeline (ovftank/unisast + xploiter/pentester)")
	triageCmd.Flags().String("multi-agent-host", "", "Ollama host for multi-agent models (default: same as ollama.host)")
	triageCmd.MarkFlagRequired("input")
}

func runTriage(cmd *cobra.Command, args []string) error {
	inputFile, _ := cmd.Flags().GetString("input")
	target, _ := cmd.Flags().GetString("target")
	modelOverride, _ := cmd.Flags().GetString("model")
	noNoise, _ := cmd.Flags().GetBool("no-noise")
	outputFile, _ := cmd.Flags().GetString("output")
	concurrency, _ := cmd.Flags().GetInt("concurrency")
	threshold, _ := cmd.Flags().GetInt("threshold")

	model := viper.GetString("ollama.model")
	if modelOverride != "" {
		model = modelOverride
	}
	ollamaHost := viper.GetString("ollama.host")

	if target == "" {
		target = "unknown"
	}
	if outputFile == "" {
		outputFile = fmt.Sprintf("./output/%s/triage-report.md", target)
	}

	fmt.Printf("\n[bbscout] starting triage\n")
	fmt.Printf("[bbscout] input       → %s\n", inputFile)
	fmt.Printf("[bbscout] target      → %s\n", target)
	fmt.Printf("[bbscout] model       → %s @ %s\n", model, ollamaHost)
	fmt.Printf("[bbscout] concurrency → %d\n", concurrency)
	fmt.Printf("[bbscout] threshold   → %d (min score to reach Ollama)\n\n", threshold)

	// ── Ollama check ─────────────────────────────────────────────────────────

	client := triage.NewOllamaClient(ollamaHost, model)

	fmt.Println("[stage 1/5] checking Ollama connection")
	if err := client.Ping(); err != nil {
		return fmt.Errorf("%w\n\nstart Ollama with:\n  ollama serve\n  ollama pull %s", err, model)
	}
	fmt.Printf("[ollama] connected — model: %s\n", model)

	// ── Parse ─────────────────────────────────────────────────────────────────

	fmt.Println("\n[stage 2/5] parsing export file")
	entries, err := triage.ParseHAR(inputFile)
	if err != nil {
		return fmt.Errorf("parse: %w", err)
	}

	// ── Domain filter + static noise filter ───────────────────────────────────

	fmt.Println("\n[stage 3/5] filtering entries")
	filtered := triage.FilterEntries(entries)

	if target != "unknown" {
		before := len(filtered)
		scoped := make([]triage.TrafficEntry, 0)
		for _, e := range filtered {
			if strings.Contains(strings.ToLower(e.URL), strings.ToLower(target)) {
				scoped = append(scoped, e)
			}
		}
		filtered = scoped
		fmt.Printf("[filter] scoped to %d entries for %s (from %d)\n", len(filtered), target, before)
	}

	if len(filtered) == 0 {
		fmt.Println("[triage] no entries after domain filter — try without --target")
		return nil
	}

	// ── Quick score — skip boring entries before Ollama ───────────────────────

	fmt.Println("\n[stage 4/5] heuristic scoring")
	var toAnalyze []triage.TrafficEntry
	autoNoise := 0

	for _, e := range filtered {
		score := triage.QuickScore(e)
		if score >= threshold {
			toAnalyze = append(toAnalyze, e)
		} else {
			autoNoise++
		}
	}

	fmt.Printf("[scorer] %d entries scored above threshold (auto-skipped %d as noise)\n",
		len(toAnalyze), autoNoise)

	if len(toAnalyze) == 0 {
		fmt.Println("[triage] no entries passed scoring — try lowering --threshold")
		return nil
	}

	// ── Multi-agent or single model analysis ─────────────────────────────────

	multiAgent, _ := cmd.Flags().GetBool("multi-agent")
	multiAgentHost, _ := cmd.Flags().GetString("multi-agent-host")
	if multiAgentHost == "" {
		multiAgentHost = ollamaHost
	}

	if multiAgent {
		return runMultiAgentTriage(toAnalyze, target, outputFile, multiAgentHost, concurrency, noNoise)
	}

	// ── Single model Ollama analysis ─────────────────────────────────────────

	fmt.Printf("\n[stage 5/5] analyzing %d entries with Ollama (concurrency: %d)\n", len(toAnalyze), concurrency)
	fmt.Println("[triage] press Ctrl+C to stop early\n")

	type result struct {
		finding *triage.Finding
		err     error
	}

	results := make([]result, len(toAnalyze))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	done := 0

	for i, entry := range toAnalyze {
		wg.Add(1)
		go func(idx int, e triage.TrafficEntry) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			finding, err := client.AnalyzeEntry(e)

			mu.Lock()
			done++
			fmt.Printf("\r[triage] %d/%d — %s %s        ",
				done, len(toAnalyze), e.Method, truncateURL(e.URL, 50))
			mu.Unlock()

			results[idx] = result{finding: finding, err: err}
		}(i, entry)
	}

	wg.Wait()
	fmt.Println()

	// collect
	findings := make([]*triage.Finding, 0)
	errors := 0
	for _, r := range results {
		if r.err != nil {
			errors++
			continue
		}
		if r.finding == nil {
			continue
		}
		if noNoise && r.finding.Severity == "noise" {
			continue
		}
		findings = append(findings, r.finding)
	}

	if errors > 0 {
		fmt.Printf("[warn] %d entries failed Ollama analysis\n", errors)
	}

	if len(findings) == 0 {
		fmt.Println("[triage] no findings — try lowering --threshold or browsing more authenticated endpoints")
		return nil
	}

	// ── Report ────────────────────────────────────────────────────────────────

	triage.PrintSummary(findings)

	os.MkdirAll(fmt.Sprintf("./output/%s", target), 0755)

	if err := triage.WriteFindingsMarkdown(findings, target, outputFile); err != nil {
		fmt.Println("[warn] could not write report:", err)
	} else {
		fmt.Printf("[triage] report saved → %s\n", outputFile)
	}

	return nil
}

func truncateURL(url string, max int) string {
	if len(url) <= max {
		return url
	}
	return url[:max] + "..."
}

func runMultiAgentTriage(
	toAnalyze []triage.TrafficEntry,
	target, outputFile, multiAgentHost string,
	concurrency int,
	noNoise bool,
) error {
	fmt.Printf("\n[stage 5/5] multi-agent triage — %d entries\n", len(toAnalyze))
	fmt.Println("[multi-agent] generator: ovftank/unisast")
	fmt.Println("[multi-agent] checker:   xploiter/pentester")
	fmt.Printf("[multi-agent] host:      %s\n\n", multiAgentHost)

	triager := triage.NewMultiAgentTriager(multiAgentHost)

	if err := triager.Ping(); err != nil {
		return fmt.Errorf("multi-agent models not reachable: %w\n\nMake sure SSH tunnel is running:\n  ssh -i ~/.ssh/bbscout-key2.pem -L 11435:localhost:11434 prabhat@57.158.26.172 -N &", err)
	}

	findings, err := triager.AnalyzeBatch(toAnalyze, concurrency)
	if err != nil {
		return fmt.Errorf("multi-agent analysis: %w", err)
	}

	if noNoise {
		var clean []*triage.Finding
		for _, f := range findings {
			if f.Severity != "noise" {
				clean = append(clean, f)
			}
		}
		findings = clean
	}

	if len(findings) == 0 {
		fmt.Println("[multi-agent] no findings after analysis")
		return nil
	}

	triage.PrintSummary(findings)
	os.MkdirAll(fmt.Sprintf("./output/%s", target), 0755)
	if err := triage.WriteFindingsMarkdown(findings, target, outputFile); err != nil {
		fmt.Println("[warn] could not write report:", err)
	} else {
		fmt.Printf("[triage] report saved → %s\n", outputFile)
	}

	return nil
}