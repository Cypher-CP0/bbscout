package triage

import (
	"regexp"
	"strings"
)

var (
	reNumericID   = regexp.MustCompile(`/\d{3,}`)          // /123, /456789 etc
	reUUID        = regexp.MustCompile(`/[0-9a-f-]{32,}`)  // UUIDs in path
	reAPIPath     = regexp.MustCompile(`/api/|/v\d+/|/graphql|/gql|/rpc`)
	reSensitiveKw = regexp.MustCompile(`(?i)token|secret|key|password|auth|session|admin|internal|debug|config|backup|export|upload|private`)
)

// QuickScore scores a traffic entry 0-10 based on heuristics.
// Entries scoring below the threshold skip Ollama entirely and are marked noise.
func QuickScore(e TrafficEntry) int {
	score := 0
	url := strings.ToLower(e.URL)

	// ── Positive signals ─────────────────────────────────────────────────────

	// authenticated request — most valuable signal
	if hasAuthHeader(e.RequestHeaders) {
		score += 4
	}

	// has a request body — mutation, form submission, API call
	if strings.TrimSpace(e.RequestBody) != "" {
		score += 3
	}

	// non-GET method — writes are more interesting
	switch e.Method {
	case "POST", "PUT", "PATCH", "DELETE":
		score += 2
	}

	// numeric ID or UUID in path — IDOR candidate
	if reNumericID.MatchString(e.URL) || reUUID.MatchString(e.URL) {
		score += 2
	}

	// API endpoint pattern
	if reAPIPath.MatchString(url) {
		score += 2
	}

	// sensitive keywords in URL
	if reSensitiveKw.MatchString(url) {
		score += 2
	}

	// interesting query params
	if hasInterestingParams(e.QueryParams) {
		score += 1
	}

	// response has content (not empty/redirect)
	if strings.TrimSpace(e.ResponseBody) != "" && len(e.ResponseBody) > 20 {
		score += 1
	}

	// JSON response — API, more likely to have structured data worth analyzing
	if strings.Contains(strings.ToLower(e.ContentType), "json") {
		score += 1
	}

	// ── Negative signals ─────────────────────────────────────────────────────

	// boring status codes
	switch e.StatusCode {
	case 301, 302, 303, 307, 308:
		score -= 4 // redirects — nothing to analyze
	case 304:
		score -= 5 // not modified — cached static asset
	case 204:
		score -= 3 // no content — tracking pixels etc
	case 404, 410:
		score -= 2 // not found — usually not interesting
	}

	// static file extensions in path
	if hasStaticExtension(url) {
		score -= 4
	}

	// very large responses are usually HTML pages, not APIs
	if len(e.ResponseBody) > 10000 {
		score -= 2
	}

	// no auth + GET + no params = public page, skip
	if e.Method == "GET" && !hasAuthHeader(e.RequestHeaders) && len(e.QueryParams) == 0 && e.RequestBody == "" {
		score -= 2
	}

	return score
}

// ScoreThreshold is the minimum score to send to Ollama.
// Entries below this are auto-marked as noise.
const ScoreThreshold = 3

// hasAuthHeader checks if the request has authentication headers.
func hasAuthHeader(headers map[string]string) bool {
	authHeaders := []string{
		"authorization", "x-auth-token", "x-api-key",
		"x-access-token", "x-session-token", "bearer",
		"x-user-id", "x-user-token",
	}
	for _, h := range authHeaders {
		if _, ok := headers[h]; ok {
			return true
		}
	}
	// check cookie for session tokens
	if cookie, ok := headers["cookie"]; ok {
		cookieLower := strings.ToLower(cookie)
		for _, kw := range []string{"session", "token", "auth", "jwt", "sid"} {
			if strings.Contains(cookieLower, kw) {
				return true
			}
		}
	}
	return false
}

// hasInterestingParams checks query params for IDOR/injection candidates.
func hasInterestingParams(params map[string]string) bool {
	interesting := []string{
		"id", "user_id", "userid", "uid", "account",
		"order_id", "orderid", "item_id", "itemid",
		"token", "key", "secret", "redirect", "url",
		"file", "path", "cmd", "exec", "query",
	}
	for k := range params {
		kl := strings.ToLower(k)
		for _, kw := range interesting {
			if kl == kw || strings.HasSuffix(kl, "_"+kw) || strings.HasPrefix(kl, kw+"_") {
				return true
			}
		}
	}
	return false
}

// hasStaticExtension returns true for clearly static file types.
func hasStaticExtension(url string) bool {
	// strip query string
	if idx := strings.Index(url, "?"); idx != -1 {
		url = url[:idx]
	}
	staticExts := []string{
		".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
		".ico", ".woff", ".woff2", ".ttf", ".eot", ".otf",
		".map", ".webp", ".bmp", ".mp4", ".mp3", ".pdf",
	}
	for _, ext := range staticExts {
		if strings.HasSuffix(url, ext) {
			return true
		}
	}
	return false
}