package crawl

import (
	"fmt"
	"os"
	"os/exec"
)

type KatanaOptions struct {
	Binary    string
	InputFile string // file containing live URLs
	OutputDir string
	Depth     int    // crawl depth, default 3
	JSCrawl   bool   // crawl JS files for endpoints
}

// RunKatana actively crawls all live hosts, finding endpoints, forms, JS files.
// Writes results to <outputDir>/katana-urls.txt and returns the path.
func RunKatana(opts KatanaOptions) (string, error) {
	outputFile := fmt.Sprintf("%s/katana-urls.txt", opts.OutputDir)

	depth := opts.Depth
	if depth == 0 {
		depth = 3
	}

	fmt.Printf("[katana] crawling live hosts from %s (depth: %d)\n", opts.InputFile, depth)

	args := []string{
		"-list", opts.InputFile,
		"-o", outputFile,
		"-silent",
		"-depth", fmt.Sprintf("%d", depth),
		"-js-crawl",           // extract endpoints from JS files
		"-known-files", "all", // robots.txt, sitemap.xml etc
		"-automatic-form-fill", // fill forms to find more endpoints
		"-concurrency", "10",
		"-parallelism", "10",
		"-timeout", "10",
		"-retry", "2",
	}

	cmd := exec.Command(opts.Binary, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("katana: %w", err)
	}

	count, _ := lineCount(outputFile)
	fmt.Printf("[katana] found %d URLs\n", count)

	return outputFile, nil
}