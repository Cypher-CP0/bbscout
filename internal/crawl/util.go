package crawl

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// readLines reads all non-empty lines from a file.
func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

// lineCount returns the number of non-empty lines in a file.
func lineCount(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	count := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) != "" {
			count++
		}
	}
	return count, scanner.Err()
}

// MergeAndDedup reads multiple URL files, deduplicates, and writes to outputFile.
// Returns the number of unique URLs.
func MergeAndDedup(files []string, outputFile string) (int, error) {
	seen := map[string]bool{}

	for _, file := range files {
		f, err := os.Open(file)
		if err != nil {
			continue // skip missing files silently
		}

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				seen[line] = true
			}
		}
		f.Close()
	}

	out, err := os.Create(outputFile)
	if err != nil {
		return 0, fmt.Errorf("merge: create output: %w", err)
	}
	defer out.Close()

	w := bufio.NewWriter(out)
	for line := range seen {
		fmt.Fprintln(w, line)
	}
	w.Flush()

	fmt.Printf("[merge] %d unique URLs after dedup\n", len(seen))
	return len(seen), nil
}

// FilterInteresting filters URLs by extension — drops static assets that
// are never interesting for bug bounty (images, fonts, stylesheets, etc).
// Returns the path to the filtered file.
func FilterInteresting(inputFile, outputDir string) (string, error) {
	outputFile := fmt.Sprintf("%s/urls-interesting.txt", outputDir)

	skipExtensions := map[string]bool{
		".png": true, ".jpg": true, ".jpeg": true, ".gif": true,
		".svg": true, ".ico": true, ".webp": true, ".bmp": true,
		".woff": true, ".woff2": true, ".ttf": true, ".eot": true,
		".otf": true, ".css": true, ".map": true,
	}

	lines, err := readLines(inputFile)
	if err != nil {
		return "", err
	}

	out, err := os.Create(outputFile)
	if err != nil {
		return "", err
	}
	defer out.Close()

	w := bufio.NewWriter(out)
	kept := 0

	for _, line := range lines {
		// get extension from URL (ignore query string)
		url := line
		if idx := strings.Index(url, "?"); idx != -1 {
			url = url[:idx]
		}
		if idx := strings.LastIndex(url, "."); idx != -1 {
			ext := strings.ToLower(url[idx:])
			if skipExtensions[ext] {
				continue
			}
		}
		fmt.Fprintln(w, line)
		kept++
	}

	w.Flush()
	fmt.Printf("[filter] %d interesting URLs (dropped static assets)\n", kept)

	return outputFile, nil
}