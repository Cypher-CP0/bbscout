package recon

import (
	"fmt"
	"os"
	"os/exec"
)

// RunAssetfinder runs assetfinder against the target domain.
// Writes results to <outputDir>/subdomains-assetfinder.txt and returns the path.
func RunAssetfinder(binary, target, outputDir string) (string, error) {
	outputFile := fmt.Sprintf("%s/subdomains-assetfinder.txt", outputDir)

	fmt.Printf("[assetfinder] running on %s\n", target)

	// assetfinder writes to stdout, so we pipe it to a file ourselves
	out, err := os.Create(outputFile)
	if err != nil {
		return "", fmt.Errorf("assetfinder: create output file: %w", err)
	}
	defer out.Close()

	cmd := exec.Command(binary, "--subs-only", target)
	cmd.Stdout = out
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("assetfinder: %w", err)
	}

	count, _ := lineCount(outputFile)
	fmt.Printf("[assetfinder] found %d subdomains\n", count)

	return outputFile, nil
}