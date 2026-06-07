package recon

import (
	"fmt"
	"os"
	"os/exec"
)

type HttpxOptions struct {
	Binary    string
	InputFile string
	OutputDir string
}

// RunHttpx probes all open ports for live HTTP/HTTPS services.
// Writes rich JSON output to <outputDir>/live-hosts.json and a plain
// host list to <outputDir>/live.txt — returns both paths.
func RunHttpx(opts HttpxOptions) (jsonOut string, plainOut string, err error) {
	jsonOut = fmt.Sprintf("%s/live-hosts.json", opts.OutputDir)
	plainOut = fmt.Sprintf("%s/live.txt", opts.OutputDir)

	fmt.Printf("[httpx] probing live HTTP services from %s\n", opts.InputFile)

	args := []string{
		"-l", opts.InputFile,
		"-o", jsonOut,
		"-silent",
		"-json",               // rich JSON output per host
		"-status-code",        // include HTTP status
		"-title",              // page title
		"-tech-detect",        // tech stack fingerprint
		"-content-length",     // response size
		"-follow-redirects",
		"-threads", "50",
	}

	cmd := exec.Command(opts.Binary, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err = cmd.Run(); err != nil {
		return "", "", fmt.Errorf("httpx: %w", err)
	}

	// also write a plain URL list from the JSON for tools that just need URLs
	if err = extractURLsFromHttpxJSON(jsonOut, plainOut); err != nil {
		return jsonOut, "", fmt.Errorf("httpx: extract urls: %w", err)
	}

	count, _ := lineCount(plainOut)
	fmt.Printf("[httpx] found %d live HTTP services\n", count)

	return jsonOut, plainOut, nil
}