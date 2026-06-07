package triage

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
)

// CaidoEntry matches Caido's JSON export format
type CaidoEntry struct {
	ID       int    `json:"id"`
	Host     string `json:"host"`
	Method   string `json:"method"`
	Path     string `json:"path"`
	Port     int    `json:"port"`
	Raw      string `json:"raw"`    // base64 encoded full HTTP request
	IsTLS    bool   `json:"is_tls"`
	Query    string `json:"query"`
	Response *CaidoResponse `json:"response"`
}

type CaidoResponse struct {
	ID         int    `json:"id"`
	StatusCode int    `json:"status_code"`
	Raw        string `json:"raw"` // base64 encoded full HTTP response
}

// TrafficEntry is our normalized representation sent to Ollama
type TrafficEntry struct {
	Method          string
	URL             string
	RequestHeaders  map[string]string
	QueryParams     map[string]string
	RequestBody     string
	StatusCode      int
	ResponseHeaders map[string]string
	ResponseBody    string
	ContentType     string
}

// ParseHAR reads a Caido JSON export and returns normalized traffic entries.
func ParseHAR(path string) ([]TrafficEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("caido: read file: %w", err)
	}

	var entries []CaidoEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("caido: parse JSON: %w", err)
	}

	if len(entries) == 0 {
		return nil, fmt.Errorf("caido: no entries found in file")
	}

	result := make([]TrafficEntry, 0, len(entries))

	for _, e := range entries {
		entry := TrafficEntry{
			Method: e.Method,
		}

		// build full URL
		scheme := "http"
		if e.IsTLS {
			scheme = "https"
		}
		if e.Query != "" {
			entry.URL = fmt.Sprintf("%s://%s%s?%s", scheme, e.Host, e.Path, e.Query)
		} else {
			entry.URL = fmt.Sprintf("%s://%s%s", scheme, e.Host, e.Path)
		}

		// parse query params
		entry.QueryParams = make(map[string]string)
		if e.Query != "" {
			params, err := url.ParseQuery(e.Query)
			if err == nil {
				for k, v := range params {
					if len(v) > 0 {
						entry.QueryParams[k] = v[0]
					}
				}
			}
		}

		// decode raw request
		if e.Raw != "" {
			decoded, err := base64.StdEncoding.DecodeString(e.Raw)
			if err == nil {
				headers, body := parseRawHTTP(string(decoded))
				entry.RequestHeaders = filterHeaders(headers, []string{
					"accept-encoding", "accept-language", "cache-control",
					"connection", "pragma", "sec-fetch-dest", "sec-fetch-mode",
					"sec-fetch-site", "sec-fetch-user", "upgrade-insecure-requests",
				})
				entry.RequestBody = truncate(body, 500)
			}
		}

		// decode raw response
		if e.Response != nil {
			entry.StatusCode = e.Response.StatusCode
			if e.Response.Raw != "" {
				decoded, err := base64.StdEncoding.DecodeString(e.Response.Raw)
				if err == nil {
					headers, body := parseRawHTTP(string(decoded))
					entry.ResponseHeaders = filterHeaders(headers, []string{
						"date", "expires", "last-modified", "etag", "age",
					})
					entry.ResponseBody = truncate(body, 800)
					if ct, ok := headers["content-type"]; ok {
						entry.ContentType = ct
					}
				}
			}
		}

		result = append(result, entry)
	}

	fmt.Printf("[caido] parsed %d HTTP exchanges from %s\n", len(result), path)
	return result, nil
}

// parseRawHTTP splits a raw HTTP message into headers map and body string.
func parseRawHTTP(raw string) (map[string]string, string) {
	headers := make(map[string]string)

	// find header/body split — \r\n\r\n or \n\n
	var headerPart, body string
	if idx := strings.Index(raw, "\r\n\r\n"); idx != -1 {
		headerPart = raw[:idx]
		body = raw[idx+4:]
	} else if idx := strings.Index(raw, "\n\n"); idx != -1 {
		headerPart = raw[:idx]
		body = raw[idx+2:]
	} else {
		headerPart = raw
	}

	// parse header lines (skip the first line which is the request/status line)
	lines := strings.Split(headerPart, "\n")
	for i, line := range lines {
		if i == 0 {
			continue // skip GET /path HTTP/1.1 or HTTP/1.1 200 OK
		}
		line = strings.TrimRight(line, "\r")
		if idx := strings.Index(line, ":"); idx != -1 {
			key := strings.ToLower(strings.TrimSpace(line[:idx]))
			val := strings.TrimSpace(line[idx+1:])
			headers[key] = val
		}
	}

	return headers, strings.TrimSpace(body)
}

// FilterEntries removes noise — static assets, analytics, non-mercari domains etc.
func FilterEntries(entries []TrafficEntry) []TrafficEntry {
	skipExtensions := map[string]bool{
		".png": true, ".jpg": true, ".jpeg": true, ".gif": true,
		".svg": true, ".ico": true, ".webp": true, ".woff": true,
		".woff2": true, ".ttf": true, ".css": true, ".map": true,
	}

	skipDomains := []string{
		// analytics & tracking
		"google-analytics.com", "googletagmanager.com", "doubleclick.net",
		"hotjar.com", "segment.com", "mixpanel.com", "amplitude.com",
		"facebook.net", "fbcdn.net", "twitter.com", "t.co",
		"bat.bing.com", "bing.com/action", "clarity.ms",
		// consent & privacy
		"trustarc.com", "consent.trustarc.com", "cookielaw.org",
		"onetrust.com", "cookiebot.com",
		// CDN & infra
		"cloudflare.com", "cdn.jsdelivr.net", "cdnjs.cloudflare.com",
		"akamai.com", "akamaized.net", "fastly.net", "cloudfront.net",
		// google services (non-target)
		"play.google.com", "www.google.com", "lh3.google.com",
		"lh3.googleusercontent.com", "ogads-pa.clients6.google.com",
		"clients6.google.com", "apis.google.com", "accounts.google.com",
		// ad networks
		"googlesyndication.com", "adservice.google.com",
		"amazon-adsystem.com", "criteo.com", "taboola.com",
	}

	skipContentTypes := []string{
		"image/", "font/", "text/css", "application/font",
	}

	filtered := make([]TrafficEntry, 0)

	for _, e := range entries {
		urlLower := strings.ToLower(e.URL)

		skip := false
		for _, domain := range skipDomains {
			if strings.Contains(urlLower, domain) {
				skip = true
				break
			}
		}
		if skip {
			continue
		}

		urlWithoutQuery := urlLower
		if idx := strings.Index(urlWithoutQuery, "?"); idx != -1 {
			urlWithoutQuery = urlWithoutQuery[:idx]
		}

		if idx := strings.LastIndex(urlWithoutQuery, "."); idx != -1 {
			ext := urlWithoutQuery[idx:]
			if skipExtensions[ext] {
				continue
			}
		}

		skip = false
		for _, ct := range skipContentTypes {
			if strings.HasPrefix(e.ContentType, ct) {
				skip = true
				break
			}
		}
		if skip {
			continue
		}

		// skip static JS
		if strings.HasSuffix(urlWithoutQuery, ".js") && e.StatusCode == 200 {
			continue
		}

		filtered = append(filtered, e)
	}

	fmt.Printf("[caido] filtered to %d interesting exchanges (from %d total)\n",
		len(filtered), len(entries))

	return filtered
}

// filterHeaders returns headers map excluding boring/noisy ones
func filterHeaders(headers map[string]string, skip []string) map[string]string {
	skipSet := make(map[string]bool)
	for _, s := range skip {
		skipSet[strings.ToLower(s)] = true
	}
	result := make(map[string]string)
	for k, v := range headers {
		if !skipSet[k] {
			result[k] = v
		}
	}
	return result
}

// truncate cuts a string to maxLen chars
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}