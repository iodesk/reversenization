package pages

import (
	"bytes"
	"embed"
	"html/template"
	"log"
	"net/http"
	"regexp"
	"strings"
	texttemplate "text/template"
	"time"

	"github.com/google/uuid"
)

//go:embed *.html
var htmlFiles embed.FS

var (
	blockedTmpl   *template.Template
	defaultTmpl   *template.Template
	challengeTmpl *texttemplate.Template
)

func init() {
	blockedTmpl = mustLoad("blocked.html")
	defaultTmpl = mustLoad("default.html")
	challengeTmpl = mustLoadText("challenge.html")
}

func mustLoad(name string) *template.Template {
	raw, err := htmlFiles.ReadFile(name)
	if err != nil {
		panic("pages: failed to read " + name + ": " + err.Error())
	}
	return template.Must(template.New(name).Parse(string(raw)))
}

func mustLoadText(name string) *texttemplate.Template {
	raw, err := htmlFiles.ReadFile(name)
	if err != nil {
		panic("pages: failed to read " + name + ": " + err.Error())
	}
	return texttemplate.Must(texttemplate.New(name).Parse(string(raw)))
}

var (
	reComments   = regexp.MustCompile(`<!--.*?-->`)
	reWhitespace = regexp.MustCompile(`\s{2,}`)
	reTagSpace   = regexp.MustCompile(`>\s+<`)
)

func minifyHTML(s string) string {
	// Split by script tags to preserve JS content
	parts := strings.SplitAfter(s, "<script>")
	if len(parts) == 1 {
		// No script tag, minify everything
		return minifyPart(s)
	}

	var result strings.Builder
	for i, part := range parts {
		if i == 0 {
			// Before first <script> — safe to minify
			result.WriteString(minifyPart(part))
			continue
		}
		// This part starts after <script>, find </script>
		endIdx := strings.Index(part, "</script>")
		if endIdx == -1 {
			// No closing tag, keep as-is
			result.WriteString(part)
			continue
		}
		// JS content — keep as-is
		result.WriteString(part[:endIdx])
		// After </script> — safe to minify
		result.WriteString("</script>")
		result.WriteString(minifyPart(part[endIdx+len("</script>"):]))
	}
	return result.String()
}

func minifyPart(s string) string {
	s = reComments.ReplaceAllString(s, "")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\t", " ")
	s = reWhitespace.ReplaceAllString(s, " ")
	s = reTagSpace.ReplaceAllString(s, "><")
	return strings.TrimSpace(s)
}

type BlockedPageData struct {
	Reason    string
	IP        string
	Timestamp string
	RayID     string
	Host      string
}

type DefaultPageData struct {
	Host string
}

func ServeDefaultPage(w http.ResponseWriter, host string) {
	var buf bytes.Buffer
	if err := defaultTmpl.Execute(&buf, DefaultPageData{Host: host}); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	w.WriteHeader(http.StatusOK)
	w.Write(buf.Bytes())
}

func humanizeReason(r string) string {
	if r == "" {
		return "Security Policy Violation"
	}
	switch {
	case strings.HasPrefix(r, "owasp_crs_rule:"):
		return "Web Attack Detected"
	case strings.HasPrefix(r, "bot_score:"):
		return "Bot Traffic Detected"
	case strings.HasPrefix(r, "ip_access_rule:"):
		desc := strings.TrimPrefix(r, "ip_access_rule:")
		if desc != "" {
			return desc
		}
		return "IP Access Denied"
	case strings.HasPrefix(r, "rule:"):
		parts := strings.SplitN(r, ":", 3)
		if len(parts) == 3 && parts[2] != "" {
			return parts[2]
		}
		return "Custom Rule Matched"
	case r == "rate_limit_exceeded":
		return "Too Many Requests"
	case r == "flood_protection_active":
		return "Flood Protection Active"
	case r == "basic_access_limit":
		return "Access Limit Reached"
	case r == "under_attack_mode":
		return "Under Attack Mode"
	default:
		return "Security Policy Violation"
	}
}

func ServeBlockedPage(w http.ResponseWriter, ip, host, reason string) {
	data := BlockedPageData{
		Reason:    humanizeReason(reason),
		IP:        ip,
		Timestamp: time.Now().Format("2006-01-02 15:04:05 MST"),
		RayID:     generateRayID(),
		Host:      host,
	}
	var buf bytes.Buffer
	if err := blockedTmpl.Execute(&buf, data); err != nil {
		http.Error(w, "Access Denied", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	w.WriteHeader(http.StatusForbidden)
	w.Write(buf.Bytes())
}

type ChallengePageData struct {
	ChallengeID string
	Type        string
	Target      int
	MaxAttempts int
	Timeout     int
	Host        string
}

func ServeChallengePage(w http.ResponseWriter, data ChallengePageData) {
	var buf bytes.Buffer
	if err := challengeTmpl.Execute(&buf, data); err != nil {
		log.Printf("[PAGES] Challenge template execute error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	w.Header().Set("Cache-Control", "private, no-store, no-cache, must-revalidate, max-age=0")
	w.Header().Set("CDN-Cache-Control", "no-store")
	w.Header().Set("Cloudflare-CDN-Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	w.Header().Set("Set-Cookie", "checking=1; Path=/; Max-Age=60; HttpOnly")
	w.WriteHeader(http.StatusForbidden)
	w.Write(buf.Bytes())
}

func generateRayID() string {
	id := uuid.New()
	return id.String()[:13]
}
