package recon

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

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

// MergeAndDedup reads multiple files, deduplicates lines, and writes
// the unique sorted set to outputFile. Returns the number of unique entries.
func MergeAndDedup(files []string, outputFile string) (int, error) {
	seen := map[string]bool{}

	for _, file := range files {
		f, err := os.Open(file)
		if err != nil {
			// skip missing files silently — a tool may have found nothing
			continue
		}

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(strings.ToLower(scanner.Text()))
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

	fmt.Printf("[merge] %d unique subdomains after dedup\n", len(seen))
	return len(seen), nil
}

// extractPlainHostnames reads dnsx -resp output (format: "host [TYPE] [value]")
// and writes just the unique hostnames to outputFile for use with httpx/naabu.
func extractPlainHostnames(inputFile, outputFile string) error {
	f, err := os.Open(inputFile)
	if err != nil {
		return err
	}
	defer f.Close()

	out, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer out.Close()

	seen := map[string]bool{}
	w := bufio.NewWriter(out)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		// format is: "hostname [A] [1.2.3.4]" — take first field
		host := strings.Fields(line)[0]
		if !seen[host] {
			seen[host] = true
			fmt.Fprintln(w, host)
		}
	}
	return w.Flush()
}

// httpxEntry represents a single line from httpx -json output.
type httpxEntry struct {
	URL string `json:"url"`
}

// extractURLsFromHttpxJSON reads httpx JSON output and writes a plain URL list.
func extractURLsFromHttpxJSON(jsonFile, outputFile string) error {
	f, err := os.Open(jsonFile)
	if err != nil {
		return err
	}
	defer f.Close()

	out, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer out.Close()

	w := bufio.NewWriter(out)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var entry httpxEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			continue
		}
		if entry.URL != "" {
			fmt.Fprintln(w, entry.URL)
		}
	}
	return w.Flush()
}