package recon

import (
	"fmt"
	"os"
	"os/exec"
)

type NaabuOptions struct {
	Binary    string
	InputFile string
	OutputDir string
	// Ports to scan — defaults to top 1000 if empty
	Ports string
}

// RunNaabu runs a fast port scan on all resolved hosts.
// Writes results to <outputDir>/ports.txt and returns the path.
func RunNaabu(opts NaabuOptions) (string, error) {
	outputFile := fmt.Sprintf("%s/ports.txt", opts.OutputDir)

	fmt.Printf("[naabu] port scanning resolved hosts\n")

	args := []string{
		"-l", opts.InputFile,
		"-o", outputFile,
		"-silent",
		"-top-ports", "1000",
		"-rate", "1000",
		"-c", "25",
	}

	// override with specific ports if provided
	if opts.Ports != "" && opts.Ports != "top-1000" {
		args = []string{
			"-l", opts.InputFile,
			"-o", outputFile,
			"-silent",
			"-p", opts.Ports,
			"-rate", "1000",
			"-c", "25",
		}
	}

	cmd := exec.Command(opts.Binary, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("naabu: %w", err)
	}

	count, _ := lineCount(outputFile)
	fmt.Printf("[naabu] found %d open ports\n", count)

	return outputFile, nil
}