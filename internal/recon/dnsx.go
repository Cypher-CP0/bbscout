package recon

import (
	"fmt"
	"os"
	"os/exec"
)

type DnsxOptions struct {
	Binary    string
	InputFile string
	OutputDir string
}

// RunDnsx resolves subdomains from the merged list, filtering out dead ones.
// Writes full DNS output to resolved.txt and plain hostnames to resolved-hosts.txt.
// Returns both paths: (fullOutput, plainHosts, error)
func RunDnsx(opts DnsxOptions) (string, string, error) {
	outputFile := fmt.Sprintf("%s/resolved.txt", opts.OutputDir)
	plainFile := fmt.Sprintf("%s/resolved-hosts.txt", opts.OutputDir)

	fmt.Printf("[dnsx] resolving subdomains from %s\n", opts.InputFile)

	args := []string{
		"-l", opts.InputFile,
		"-o", outputFile,
		"-silent",
		"-resp",
		"-a",
		"-cname",
		"-retry", "3",
	}

	cmd := exec.Command(opts.Binary, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return "", "", fmt.Errorf("dnsx: %w", err)
	}

	// also write plain hostnames (just the subdomain, no DNS record info)
	// dnsx -resp output format: "hostname [RECORD_TYPE] [value]"
	// we need just the hostname for httpx/naabu
	if err := extractPlainHostnames(outputFile, plainFile); err != nil {
		return "", "", fmt.Errorf("dnsx: extract hostnames: %w", err)
	}

	count, _ := lineCount(plainFile)
	fmt.Printf("[dnsx] resolved %d live subdomains\n", count)

	return outputFile, plainFile, nil
}