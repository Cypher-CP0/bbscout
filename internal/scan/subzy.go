package scan

import (
	"fmt"
	"os"
	"os/exec"
)

type SubzyOptions struct {
	Binary    string
	InputFile string // resolved subdomains file
	OutputDir string
}

// RunSubzy checks all resolved subdomains for takeover vulnerabilities.
// A subdomain is takeover-vulnerable when its CNAME points to an unclaimed
// third-party service (GitHub Pages, Heroku, Shopify, etc).
// Writes results to <outputDir>/subzy-findings.txt and returns the path.
func RunSubzy(opts SubzyOptions) (string, error) {
	outputFile := fmt.Sprintf("%s/subzy-findings.txt", opts.OutputDir)

	fmt.Printf("[subzy] checking subdomains for takeover vulnerabilities\n")

	args := []string{
		"run",
		"--targets", opts.InputFile,
		"--output", outputFile,
		"--hide_fails",  // only show vulnerable ones
		"--verify_ssl",
		"--concurrency", "20",
	}

	cmd := exec.Command(opts.Binary, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		// subzy exits non-zero with no findings — check if file exists
		if _, statErr := os.Stat(outputFile); os.IsNotExist(statErr) {
			// create empty file so pipeline doesn't break
			f, _ := os.Create(outputFile)
			if f != nil {
				f.Close()
			}
			fmt.Println("[subzy] no takeover vulnerabilities found")
			return outputFile, nil
		}
	}

	count, _ := lineCount(outputFile)
	if count == 0 {
		fmt.Println("[subzy] no takeover vulnerabilities found")
	} else {
		fmt.Printf("[subzy] found %d potential takeover targets\n", count)
	}

	return outputFile, nil
}