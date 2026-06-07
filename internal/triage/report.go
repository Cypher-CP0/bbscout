package triage

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// severityOrder for sorting findings by importance
var severityOrder = map[string]int{
	"critical": 0,
	"high":     1,
	"medium":   2,
	"low":      3,
	"info":     4,
	"noise":    5,
}

// severityEmoji for markdown report
var severityEmoji = map[string]string{
	"critical": "🔴",
	"high":     "🟠",
	"medium":   "🟡",
	"low":      "🔵",
	"info":     "⚪",
	"noise":    "⬛",
}

// WriteFindingsMarkdown writes triage findings to a markdown file.
func WriteFindingsMarkdown(findings []*Finding, target, outputPath string) error {
	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("report: create file: %w", err)
	}
	defer f.Close()

	// count by severity
	counts := map[string]int{}
	for _, finding := range findings {
		if finding.Severity != "noise" {
			counts[finding.Severity]++
		}
	}

	fmt.Fprintf(f, "# bbscout triage report — %s\n\n", target)
	fmt.Fprintf(f, "generated: %s\n\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Fprintf(f, "## summary\n\n")
	fmt.Fprintf(f, "| severity | count |\n|---|---|\n")
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if counts[sev] > 0 {
			fmt.Fprintf(f, "| %s %s | %d |\n", severityEmoji[sev], sev, counts[sev])
		}
	}
	fmt.Fprintln(f)

	// group by severity
	groups := map[string][]*Finding{}
	for _, finding := range findings {
		if finding.Severity != "noise" {
			groups[finding.Severity] = append(groups[finding.Severity], finding)
		}
	}

	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		group := groups[sev]
		if len(group) == 0 {
			continue
		}

		fmt.Fprintf(f, "## %s %s findings\n\n", severityEmoji[sev], sev)

		for i, finding := range group {
			fmt.Fprintf(f, "### %d. %s\n\n", i+1, finding.Category)
			fmt.Fprintf(f, "- **url:** `%s`\n", finding.URL)
			fmt.Fprintf(f, "- **method:** `%s`\n", finding.Method)
			fmt.Fprintf(f, "- **status:** `%d`\n", finding.StatusCode)
			fmt.Fprintf(f, "- **description:** %s\n", finding.Description)
			fmt.Fprintf(f, "- **evidence:** %s\n", finding.Evidence)
			fmt.Fprintf(f, "- **next steps:** %s\n\n", finding.NextSteps)
			fmt.Fprintln(f, "---")
			fmt.Fprintln(f)
		}
	}

	return nil
}

// PrintSummary prints a quick terminal summary of findings.
func PrintSummary(findings []*Finding) {
	counts := map[string]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}

	total := len(findings) - counts["noise"]
	fmt.Printf("\n[triage] analyzed %d exchanges → %d actionable findings\n\n", len(findings), total)

	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if counts[sev] > 0 {
			fmt.Printf("  %s %-8s %d\n", severityEmoji[sev], sev, counts[sev])
		}
	}

	// print non-noise findings
	fmt.Println()
	for _, sev := range []string{"critical", "high", "medium"} {
		for _, f := range findings {
			if f.Severity != sev {
				continue
			}
			fmt.Printf("%s [%s] %s %s\n",
				severityEmoji[sev],
				strings.ToUpper(f.Category),
				f.Method,
				f.URL,
			)
			fmt.Printf("   %s\n", f.Description)
			fmt.Printf("   next: %s\n\n", f.NextSteps)
		}
	}
}