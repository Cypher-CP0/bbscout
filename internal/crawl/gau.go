package crawl

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

type GauOptions struct {
	Binary    string
	InputFile string // file containing live hosts (plain hostnames or URLs)
	OutputDir string
}

// RunGau pulls historical URLs from Wayback Machine, Common Crawl, and OTX.
// Runs against the root domain (with --subs flag to include subdomains)
// rather than looping per-host — much faster for large targets.
// Writes results to <outputDir>/gau-urls.txt and returns the path.
func RunGau(opts GauOptions) (string, error) {
	outputFile := fmt.Sprintf("%s/gau-urls.txt", opts.OutputDir)

	// extract root domain from input file name or use first host
	// gau --subs covers all subdomains so we just need the root
	hosts, err := readLines(opts.InputFile)
	if err != nil {
		return "", fmt.Errorf("gau: read input: %w", err)
	}
	if len(hosts) == 0 {
		return "", fmt.Errorf("gau: no hosts in input file")
	}

	// find the shortest hostname — likely the root domain
	root := hosts[0]
	for _, h := range hosts {
		h = strings.TrimPrefix(h, "https://")
		h = strings.TrimPrefix(h, "http://")
		if idx := strings.Index(h, ":"); idx != -1 {
			h = h[:idx]
		}
		if idx := strings.Index(h, "/"); idx != -1 {
			h = h[:idx]
		}
		if len(h) < len(root) {
			root = h
		}
	}

	fmt.Printf("[gau] fetching historical URLs for %s (including subdomains)\n", root)

	out, err := os.Create(outputFile)
	if err != nil {
		return "", fmt.Errorf("gau: create output: %w", err)
	}
	defer out.Close()

	args := []string{
		"--subs",
		"--retries", "2",
		"--timeout", "30",
		"--threads", "5",
		root,
	}

	cmd := exec.Command(opts.Binary, args...)
	cmd.Stdout = out
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("gau: %w", err)
	}

	count, _ := lineCount(outputFile)
	fmt.Printf("[gau] found %d historical URLs\n", count)

	return outputFile, nil
}