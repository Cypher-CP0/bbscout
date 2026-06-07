package scan

import (
	"fmt"
	"os"
	"os/exec"
)

type NucleiOptions struct {
	Binary       string
	InputFile    string // live hosts or URLs
	OutputDir    string
	Severity     string // comma separated: low,medium,high,critical
	Templates    string // path to templates dir, empty = default
	RateLimit    int    // requests per second
	BulkSize     int    // parallel templates per host
	Concurrency  int    // parallel hosts
}

// RunNuclei runs nuclei template-based scanning against live hosts.
// Writes JSON results to <outputDir>/nuclei-findings.json and returns the path.
func RunNuclei(opts NucleiOptions) (string, error) {
	outputFile := fmt.Sprintf("%s/nuclei-findings.json", opts.OutputDir)

	severity := opts.Severity
	if severity == "" {
		severity = "low,medium,high,critical"
	}

	rateLimit := opts.RateLimit
	if rateLimit == 0 {
		rateLimit = 150
	}

	bulkSize := opts.BulkSize
	if bulkSize == 0 {
		bulkSize = 25
	}

	concurrency := opts.Concurrency
	if concurrency == 0 {
		concurrency = 25
	}

	fmt.Printf("[nuclei] scanning %s (severity: %s)\n", opts.InputFile, severity)

	args := []string{
		"-l", opts.InputFile,
		"-o", outputFile,
		"-je", outputFile, // JSON export
		"-severity", severity,
		"-rate-limit", fmt.Sprintf("%d", rateLimit),
		"-bulk-size", fmt.Sprintf("%d", bulkSize),
		"-concurrency", fmt.Sprintf("%d", concurrency),
		"-silent",
		"-no-color",
		"-stats",              // show progress stats
		"-update-templates",   // keep templates fresh
	}

	// custom templates dir
	if opts.Templates != "" {
		args = append(args, "-t", opts.Templates)
	}

	cmd := exec.Command(opts.Binary, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		// nuclei exits non-zero when it finds vulns — that's a success for us
		// only treat it as error if the output file wasn't created
		if _, statErr := os.Stat(outputFile); os.IsNotExist(statErr) {
			return "", fmt.Errorf("nuclei: %w", err)
		}
	}

	count, _ := lineCount(outputFile)
	fmt.Printf("[nuclei] found %d findings\n", count)

	return outputFile, nil
}