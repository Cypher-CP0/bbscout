package probe

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Result holds a captured HTTP request/response pair.
type Result struct {
	URL            string
	Method         string
	StatusCode     int
	RequestHeaders map[string]string
	ResponseHeaders map[string]string
	ResponseBody   string
	ContentType    string
	Error          string
}

// Options controls probe behavior.
type Options struct {
	Timeout    time.Duration
	UserAgent  string
	FollowRedirects bool
	MaxBodySize int64
}

var defaultHeaders = map[string]string{
	"Accept":          "application/json, text/html, */*",
	"Accept-Language": "en-US,en;q=0.9",
	"Connection":      "keep-alive",
}

// DefaultOptions returns sensible defaults.
func DefaultOptions() Options {
	return Options{
		Timeout:         15 * time.Second,
		UserAgent:       "Mozilla/5.0 (compatible; bbscout/0.1)",
		FollowRedirects: false,
		MaxBodySize:     50 * 1024, // 50KB max response body
	}
}

// Probe makes an HTTP request to a URL and returns the captured result.
func Probe(targetURL string, opts Options) Result {
	result := Result{
		URL:    targetURL,
		Method: "GET",
	}

	// validate URL
	parsed, err := url.Parse(targetURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		result.Error = fmt.Sprintf("invalid URL: %v", err)
		return result
	}

	client := &http.Client{
		Timeout: opts.Timeout,
	}

	// don't follow redirects — capture them as findings
	if !opts.FollowRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		result.Error = err.Error()
		return result
	}

	// set headers
	req.Header.Set("User-Agent", opts.UserAgent)
	for k, v := range defaultHeaders {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode

	// capture response headers
	result.ResponseHeaders = make(map[string]string)
	for k, v := range resp.Header {
		result.ResponseHeaders[strings.ToLower(k)] = strings.Join(v, ", ")
	}
	result.ContentType = resp.Header.Get("Content-Type")

	// capture request headers
	result.RequestHeaders = make(map[string]string)
	for k, v := range req.Header {
		result.RequestHeaders[strings.ToLower(k)] = strings.Join(v, ", ")
	}

	// read body (limited)
	body, err := io.ReadAll(io.LimitReader(resp.Body, opts.MaxBodySize))
	if err == nil {
		result.ResponseBody = string(body)
	}

	return result
}

// ProbeCommonPaths probes a host with common security-relevant paths.
func ProbeCommonPaths(baseURL string, opts Options) []Result {
	paths := []string{
		"/",
		"/api",
		"/api/v1",
		"/api/v2",
		"/api/v3",
		"/admin",
		"/admin/",
		"/debug",
		"/health",
		"/healthz",
		"/metrics",
		"/status",
		"/version",
		"/info",
		"/config",
		"/env",
		"/actuator",
		"/actuator/env",
		"/actuator/health",
		"/swagger",
		"/swagger-ui",
		"/swagger-ui.html",
		"/swagger.json",
		"/openapi.json",
		"/api-docs",
		"/graphql",
		"/graphiql",
		"/.env",
		"/.git/config",
		"/robots.txt",
		"/sitemap.xml",
		"/crossdomain.xml",
		"/security.txt",
		"/.well-known/security.txt",
	}

	baseURL = strings.TrimRight(baseURL, "/")
	var results []Result

	for _, path := range paths {
		result := Probe(baseURL+path, opts)
		// only keep interesting responses
		if isInteresting(result) {
			results = append(results, result)
		}
	}

	return results
}

// isInteresting filters out uninteresting probe results.
func isInteresting(r Result) bool {
	if r.Error != "" {
		return false
	}
	// skip redirects to login pages (not interesting for recon)
	if r.StatusCode == 301 || r.StatusCode == 302 {
		return true // keep redirects — destination might be interesting
	}
	// skip 404s
	if r.StatusCode == 404 {
		return false
	}
	// skip empty responses
	if r.StatusCode == 204 {
		return false
	}
	return true
}