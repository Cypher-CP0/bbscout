package recon

import (
	"fmt"
	"os"
	"os/exec"
)

type SubfinderOptions struct {
	Binary    string
	Target    string
	OutputDir string
}

// RunSubfinder runs subfinder passively against the target domain.
// Writes results to <outputDir>/subdomains-subfinder.txt and returns the path.
func RunSubfinder(opts SubfinderOptions) (string, error) {
	outputFile := fmt.Sprintf("%s/subdomains-subfinder.txt", opts.OutputDir)

	args := []string{
		"-d", opts.Target,
		"-o", outputFile,
		"-silent",
		"-all", // use all sources
	}

	fmt.Printf("[subfinder] running on %s\n", opts.Target)

	cmd := exec.Command(opts.Binary, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("subfinder: %w", err)
	}

	count, _ := lineCount(outputFile)
	fmt.Printf("[subfinder] found %d subdomains\n", count)

	return outputFile, nil
}