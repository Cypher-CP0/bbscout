package crawl

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

type WaybackOptions struct {
	Binary    string
	InputFile string
	OutputDir string
}

// RunWaybackurls pulls URLs from the Wayback Machine for the root domain.
// Writes results to <outputDir>/wayback-urls.txt and returns the path.
func RunWaybackurls(opts WaybackOptions) (string, error) {
	outputFile := fmt.Sprintf("%s/wayback-urls.txt", opts.OutputDir)

	hosts, err := readLines(opts.InputFile)
	if err != nil {
		return "", fmt.Errorf("waybackurls: read input: %w", err)
	}
	if len(hosts) == 0 {
		return "", fmt.Errorf("waybackurls: no hosts in input file")
	}

	// find root domain — shortest hostname
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

	fmt.Printf("[waybackurls] fetching archived URLs for %s\n", root)

	out, err := os.Create(outputFile)
	if err != nil {
		return "", fmt.Errorf("waybackurls: create output: %w", err)
	}
	defer out.Close()

	// waybackurls reads from stdin
	cmd := exec.Command(opts.Binary)
	cmd.Stdin = strings.NewReader(root)
	cmd.Stdout = out
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("waybackurls: %w", err)
	}

	count, _ := lineCount(outputFile)
	fmt.Printf("[waybackurls] found %d archived URLs\n", count)

	return outputFile, nil
}