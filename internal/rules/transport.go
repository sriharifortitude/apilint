package rules

import (
	"fmt"
	"strings"

	"github.com/sriharifortitude/apilint/internal/spec"
)

func init() {
	register(unencryptedServerURL{})
	register(missingRateLimitEvidence{})
}

// --- unencrypted-server-url ------------------------------------------------------

type unencryptedServerURL struct{}

func (unencryptedServerURL) ID() string         { return "unencrypted-server-url" }
func (unencryptedServerURL) Severity() Severity { return Medium }
func (unencryptedServerURL) Description() string {
	return "a documented server URL uses plain http://, not https://"
}

func (r unencryptedServerURL) Check(doc *spec.Document) []Finding {
	var out []Finding
	for i, url := range doc.Servers() {
		if !strings.HasPrefix(url, "http://") {
			continue
		}
		if isLocalURL(url) {
			continue
		}
		out = append(out, Finding{
			RuleID:      r.ID(),
			Severity:    r.Severity(),
			Location:    fmt.Sprintf("servers[%d]", i),
			Message:     fmt.Sprintf("server URL %q is plain HTTP", url),
			Remediation: "use https:// -- credentials, tokens and response bodies otherwise cross the network unencrypted",
		})
	}
	return out
}

func isLocalURL(url string) bool {
	for _, host := range []string{"http://localhost", "http://127.0.0.1", "http://[::1]"} {
		if strings.HasPrefix(url, host) {
			return true
		}
	}
	return false
}

// --- missing-rate-limit-evidence -------------------------------------------------

type missingRateLimitEvidence struct{}

func (missingRateLimitEvidence) ID() string         { return "missing-rate-limit-evidence" }
func (missingRateLimitEvidence) Severity() Severity { return Low }
func (missingRateLimitEvidence) Description() string {
	return "no operation in the document documents a 429 Too Many Requests response, which is at least weak evidence rate limiting was never designed for"
}

func (r missingRateLimitEvidence) Check(doc *spec.Document) []Finding {
	for _, op := range doc.Operations() {
		if _, ok := op.Responses["429"]; ok {
			return nil
		}
	}
	ops := doc.Operations()
	if len(ops) == 0 {
		return nil
	}
	return []Finding{{
		RuleID:   r.ID(),
		Severity: r.Severity(),
		Location: "(whole document)",
		Message:  "no operation anywhere documents a 429 response",
		Remediation: "if rate limiting exists, document it with a 429 response on at least the endpoints it protects; " +
			"if it doesn't exist yet, this is a heuristic prompt to add it, not proof its absence is a bug",
	}}
}
