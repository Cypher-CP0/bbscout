package recon

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

type crtEntry struct {
	NameValue string `json:"name_value"`
}

// RunCrtSh queries crt.sh certificate transparency logs for the target domain.
// Writes results to <outputDir>/subdomains-crtsh.txt and returns the path.
func RunCrtSh(target, outputDir string) (string, error) {
	outputFile := fmt.Sprintf("%s/subdomains-crtsh.txt", outputDir)

	fmt.Printf("[crt.sh] querying certificate transparency logs for %s\n", target)

	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", target)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return "", fmt.Errorf("crt.sh: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("crt.sh: unexpected status %d", resp.StatusCode)
	}

	var entries []crtEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return "", fmt.Errorf("crt.sh: decode response: %w", err)
	}

	out, err := os.Create(outputFile)
	if err != nil {
		return "", fmt.Errorf("crt.sh: create output file: %w", err)
	}
	defer out.Close()

	seen := map[string]bool{}
	for _, e := range entries {
		// crt.sh returns multi-line name values (wildcard + base) separated by \n
		for _, name := range strings.Split(e.NameValue, "\n") {
			name = strings.TrimSpace(strings.ToLower(name))
			// skip wildcards like *.example.com
			if name == "" || strings.HasPrefix(name, "*") {
				continue
			}
			if !seen[name] {
				seen[name] = true
				fmt.Fprintln(out, name)
			}
		}
	}

	fmt.Printf("[crt.sh] found %d subdomains\n", len(seen))

	return outputFile, nil
}