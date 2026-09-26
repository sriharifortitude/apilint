package rules

import (
	"fmt"

	"github.com/sriharifortitude/apilint/internal/spec"
)

func init() {
	register(missingSecurityRequirement{})
	register(danglingSecuritySchemeReference{})
	register(weakHTTPBasicAuth{})
	register(apiKeyInQueryString{})
}

// --- missing-security-requirement --------------------------------------------

type missingSecurityRequirement struct{}

func (missingSecurityRequirement) ID() string { return "missing-security-requirement" }
func (missingSecurityRequirement) Severity() Severity {
	return High // the per-operation severity is decided in Check; this is the floor
}
func (missingSecurityRequirement) Description() string {
	return "an operation with no security requirement of its own and no global default -- unlike an operation that explicitly declares itself public"
}

func (r missingSecurityRequirement) Check(doc *spec.Document) []Finding {
	var out []Finding
	for _, op := range doc.Operations() {
		_, ok := op.EffectiveSecurity(doc)
		if ok {
			continue // has its own requirement (even an explicit empty one) or inherits a global default
		}
		severity := High
		message := "no security requirement anywhere applies to this operation"
		if op.HasPathParameter() {
			severity = Critical
			message += " -- and it takes a path parameter, so a missing authorization check here is a broken-object-level-authorization (BOLA/IDOR) risk, not just a generically open endpoint"
		}
		out = append(out, Finding{
			RuleID:   r.ID(),
			Severity: severity,
			Location: opLocation(op),
			Message:  message,
			Remediation: "add a \"security\" requirement to this operation, or a global default -- " +
				"or, if this endpoint is genuinely public, declare that explicitly with \"security: []\"",
		})
	}
	return out
}

// --- dangling-security-scheme-reference --------------------------------------

type danglingSecuritySchemeReference struct{}

func (danglingSecuritySchemeReference) ID() string         { return "dangling-security-scheme-reference" }
func (danglingSecuritySchemeReference) Severity() Severity { return Critical }
func (danglingSecuritySchemeReference) Description() string {
	return "a security requirement names a scheme that is not defined in components.securitySchemes"
}

func (r danglingSecuritySchemeReference) Check(doc *spec.Document) []Finding {
	var out []Finding
	seen := map[string]bool{}

	check := func(location string, requirements []any) {
		for _, req := range requirements {
			reqMap, ok := req.(map[string]any)
			if !ok {
				continue
			}
			for name := range reqMap {
				key := location + "|" + name
				if seen[key] {
					continue
				}
				if _, defined := doc.SecurityScheme(name); !defined {
					seen[key] = true
					out = append(out, Finding{
						RuleID:   r.ID(),
						Severity: r.Severity(),
						Location: location,
						Message:  fmt.Sprintf("security requirement names scheme %q, which is not defined in components.securitySchemes", name),
						Remediation: fmt.Sprintf(
							"define %q under components.securitySchemes, or fix the typo if this was meant to reference an existing scheme", name,
						),
					})
				}
			}
		}
	}

	if global, ok := doc.GlobalSecurity(); ok {
		check("(global security)", global)
	}
	for _, op := range doc.Operations() {
		if op.HasOwnSecurity {
			check(opLocation(op), op.OwnSecurity)
		}
	}
	return out
}

// --- weak-http-basic-auth -----------------------------------------------------

type weakHTTPBasicAuth struct{}

func (weakHTTPBasicAuth) ID() string         { return "weak-http-basic-auth" }
func (weakHTTPBasicAuth) Severity() Severity { return High }
func (weakHTTPBasicAuth) Description() string {
	return "an HTTP Basic authentication scheme -- credentials sent in cleartext-equivalent base64 on every request"
}

func (r weakHTTPBasicAuth) Check(doc *spec.Document) []Finding {
	return checkSecuritySchemes(doc, func(name string, scheme map[string]any) *Finding {
		if scheme["type"] != "http" || scheme["scheme"] != "basic" {
			return nil
		}
		return &Finding{
			RuleID:      r.ID(),
			Severity:    r.Severity(),
			Location:    fmt.Sprintf("components.securitySchemes.%s", name),
			Message:     "HTTP Basic sends the username and password on every request, reversibly encoded, not encrypted by the scheme itself",
			Remediation: "use a bearer token (OAuth2/OIDC access token, or a signed API key scheme) instead of HTTP Basic for anything beyond a quick internal tool",
		}
	})
}

// --- api-key-in-query-string ----------------------------------------------------

type apiKeyInQueryString struct{}

func (apiKeyInQueryString) ID() string         { return "api-key-in-query-string" }
func (apiKeyInQueryString) Severity() Severity { return High }
func (apiKeyInQueryString) Description() string {
	return "an API key sent as a query string parameter -- it ends up in server logs, browser history and the Referer header"
}

func (r apiKeyInQueryString) Check(doc *spec.Document) []Finding {
	return checkSecuritySchemes(doc, func(name string, scheme map[string]any) *Finding {
		if scheme["type"] != "apiKey" || scheme["in"] != "query" {
			return nil
		}
		return &Finding{
			RuleID:      r.ID(),
			Severity:    r.Severity(),
			Location:    fmt.Sprintf("components.securitySchemes.%s", name),
			Message:     "an apiKey scheme with in: query puts the key in the URL, which is logged and cached far more readily than a header",
			Remediation: "move the API key to a header (in: header) instead of the query string",
		}
	})
}

func checkSecuritySchemes(doc *spec.Document, check func(name string, scheme map[string]any) *Finding) []Finding {
	var out []Finding
	for _, name := range doc.SecuritySchemeNames() {
		scheme, ok := doc.SecurityScheme(name)
		if !ok {
			continue
		}
		if f := check(name, scheme); f != nil {
			out = append(out, *f)
		}
	}
	return out
}
