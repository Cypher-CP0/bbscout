package util

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
)

// JSONResult wraps any value as a text MCP tool result.
func JSONResult(v interface{}) *mcp.CallToolResult {
	b, _ := json.MarshalIndent(v, "", "  ")
	return mcp.NewToolResultText(string(b))
}

// ErrorResult wraps an error message as a text MCP tool result.
func ErrorResult(msg string) *mcp.CallToolResult {
	b, _ := json.MarshalIndent(map[string]string{"error": msg}, "", "  ")
	return mcp.NewToolResultText(string(b))
}

// ExtractScope pulls []string out of an MCP array argument.
func ExtractScope(v interface{}) []string {
	if v == nil {
		return nil
	}
	raw, ok := v.([]interface{})
	if !ok {
		return nil
	}
	var scope []string
	for _, s := range raw {
		if str, ok := s.(string); ok {
			scope = append(scope, strings.ToLower(str))
		}
	}
	return scope
}

// FilterByScope reads a hosts file and keeps only lines matching scope domains.
// Writes filtered output to resolved-scoped.txt and returns its path.
func FilterByScope(inputFile string, scope []string, outputDir string) string {
	scopedFile := filepath.Join(outputDir, "resolved-scoped.txt")
	data, err := os.ReadFile(inputFile)
	if err != nil {
		return inputFile
	}
	out, err := os.Create(scopedFile)
	if err != nil {
		return inputFile
	}
	defer out.Close()

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		for _, s := range scope {
			if strings.Contains(strings.ToLower(line), s) {
				fmt.Fprintln(out, line)
				break
			}
		}
	}
	return scopedFile
}

// FindInterestingHosts scans a live hosts file for security-relevant subdomains.
func FindInterestingHosts(liveFile string) []string {
	data, err := os.ReadFile(liveFile)
	if err != nil {
		return nil
	}
	keywords := []string{
		"admin", "api", "internal", "dev", "staging", "stg",
		"origin", "beta", "test", "debug", "partner", "dashboard",
		"management", "console", "portal", "backend", "private",
	}
	var interesting []string
	seen := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || seen[line] {
			continue
		}
		lower := strings.ToLower(line)
		for _, kw := range keywords {
			if strings.Contains(lower, kw) {
				interesting = append(interesting, line)
				seen[line] = true
				break
			}
		}
	}
	return interesting
}

// CountLines returns the number of non-empty lines in a file.
func CountLines(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) != "" {
			count++
		}
	}
	return count, nil
}

// CountVulnerable counts lines containing "[ VULNERABLE ]" in subzy output.
func CountVulnerable(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, "[ VULNERABLE ]") {
			count++
		}
	}
	return count, nil
}