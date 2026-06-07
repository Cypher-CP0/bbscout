package recon

import (
	"fmt"
	"os"
	"os/exec"
)

type GoWitnessOptions struct {
	Binary      string
	InputFile   string
	ScreenshotDir string
}

// RunGowitness takes screenshots of all live HTTP services.
// Screenshots are saved to <screenshotDir>/ as PNG files.
func RunGowitness(opts GoWitnessOptions) error {
	if err := os.MkdirAll(opts.ScreenshotDir, 0755); err != nil {
		return fmt.Errorf("gowitness: create screenshot dir: %w", err)
	}

	fmt.Printf("[gowitness] screenshotting live hosts from %s\n", opts.InputFile)

	args := []string{
		"file",
		"-f", opts.InputFile,
		"--screenshot-path", opts.ScreenshotDir,
		"--threads", "4",
		"--timeout", "10",
	}

	cmd := exec.Command(opts.Binary, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("gowitness: %w", err)
	}

	fmt.Printf("[gowitness] screenshots saved to %s\n", opts.ScreenshotDir)
	return nil
}