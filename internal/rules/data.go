package rules

import (
	"fmt"
	"strings"

	"github.com/sriharifortitude/apilint/internal/spec"
)

func init() {
	register(sensitiveFieldInResponse{})
	register(massAssignmentRisk{})
	register(missingFormatConstraint{})
	register(missingResponseSchema{})
}

// normalizeFieldName lowercases and strips separators so "api_key",
// "apiKey" and "API-KEY" all compare equal to the curated list below.
func normalizeFieldName(name string) string {
	name = strings.ToLower(name)
	name = strings.NewReplacer("_", "", "-", "", " ", "").Replace(name)
	return name
}

// --- sensitive-field-in-response ----------------------------------------------

var sensitiveFieldNames = map[string]bool{
	"password": true, "passwd": true, "secret": true, "token": true,
	"apikey": true, "accesstoken": true, "refreshtoken": true, "privatekey": true,
	"ssn": true, "socialsecuritynumber": true, "creditcard": true,
	"cardnumber": true, "cvv": true, "cvc": true, "pin": true,
}

type sensitiveFieldInResponse struct{}

func (sensitiveFieldInResponse) ID() string         { return "sensitive-field-in-response" }
func (sensitiveFieldInResponse) Severity() Severity { return Critical }
func (sensitiveFieldInResponse) Description() string {
	return "a response schema includes a field named like a credential or a piece of sensitive PII"
}

func (r sensitiveFieldInResponse) Check(doc *spec.Document) []Finding {
	var out []Finding
	for _, op := range doc.Operations() {
		for status, resp := range op.Responses {
			if resp.Schema == nil || !strings.HasPrefix(status, "2") {
				continue
			}
			for _, prop := range doc.WalkProperties(resp.Schema) {
				if !sensitiveFieldNames[normalizeFieldName(prop.Name)] {
					continue
				}
				if writeOnly, _ := prop.Schema["writeOnly"].(bool); writeOnly {
					continue // declared as request-only; the spec says it never appears in a response
				}
				out = append(out, Finding{
					RuleID:   r.ID(),
					Severity: r.Severity(),
					Location: fmt.Sprintf("%s (%s response)", opLocation(op), status),
					Message:  fmt.Sprintf("response includes a field named %q, which looks like a credential or sensitive PII", prop.Name),
					Remediation: fmt.Sprintf(
						"remove %q from the response schema, or mark it writeOnly: true if it genuinely never appears in a real response", prop.Name,
					),
				})
			}
		}
	}
	return out
}

// --- mass-assignment-risk -------------------------------------------------------

var privilegedFieldNames = map[string]bool{
	"role": true, "isadmin": true, "admin": true, "permissions": true,
	"verified": true, "isverified": true, "balance": true, "credit": true,
}

type massAssignmentRisk struct{}

func (massAssignmentRisk) ID() string         { return "mass-assignment-risk" }
func (massAssignmentRisk) Severity() Severity { return High }
func (massAssignmentRisk) Description() string {
	return "a write request body accepts a field a client should not be able to set directly (a role, an admin flag, an id on creation)"
}

func (r massAssignmentRisk) Check(doc *spec.Document) []Finding {
	var out []Finding
	for _, op := range doc.Operations() {
		if op.RequestBody == nil {
			continue
		}
		if op.Method != "post" && op.Method != "put" && op.Method != "patch" {
			continue
		}
		for _, prop := range doc.WalkProperties(op.RequestBody) {
			normalized := normalizeFieldName(prop.Name)
			flagged := privilegedFieldNames[normalized]
			// "id" in a creation request specifically: the classic
			// case of a client choosing its own identifier.
			if op.Method == "post" && normalized == "id" {
				flagged = true
			}
			if !flagged {
				continue
			}
			out = append(out, Finding{
				RuleID:   r.ID(),
				Severity: r.Severity(),
				Location: opLocation(op),
				Message:  fmt.Sprintf("request body accepts %q, which a client should not be able to set directly", prop.Name),
				Remediation: fmt.Sprintf(
					"remove %q from the request schema and set it server-side, or document why this endpoint legitimately needs to accept it (e.g. an admin-only operation with its own authorization check)", prop.Name,
				),
			})
		}
	}
	return out
}

// --- missing-format-constraint ---------------------------------------------------

var formatHintedFieldNames = map[string]string{
	"email": "format: email", "url": "format: uri", "website": "format: uri",
	"phone": "a pattern", "phonenumber": "a pattern",
}

type missingFormatConstraint struct{}

func (missingFormatConstraint) ID() string         { return "missing-format-constraint" }
func (missingFormatConstraint) Severity() Severity { return Low }
func (missingFormatConstraint) Description() string {
	return "a request field named like a validated type (email, url, phone) has no format or pattern constraint"
}

func (r missingFormatConstraint) Check(doc *spec.Document) []Finding {
	var out []Finding
	for _, op := range doc.Operations() {
		if op.RequestBody == nil {
			continue
		}
		for _, prop := range doc.WalkProperties(op.RequestBody) {
			hint, wants := formatHintedFieldNames[normalizeFieldName(prop.Name)]
			if !wants || prop.Schema["type"] != "string" {
				continue
			}
			_, hasFormat := prop.Schema["format"]
			_, hasPattern := prop.Schema["pattern"]
			_, hasEnum := prop.Schema["enum"]
			if hasFormat || hasPattern || hasEnum {
				continue
			}
			out = append(out, Finding{
				RuleID:      r.ID(),
				Severity:    r.Severity(),
				Location:    opLocation(op),
				Message:     fmt.Sprintf("request field %q has no format/pattern constraint, only type: string", prop.Name),
				Remediation: fmt.Sprintf("add %s to the schema for %q so invalid input is rejected by validation, not by whatever code reads it later", hint, prop.Name),
			})
		}
	}
	return out
}

// --- missing-response-schema -----------------------------------------------------

type missingResponseSchema struct{}

func (missingResponseSchema) ID() string         { return "missing-response-schema" }
func (missingResponseSchema) Severity() Severity { return Medium }
func (missingResponseSchema) Description() string {
	return "a successful response has no documented schema, so its actual shape -- and whether it over-exposes data -- cannot be checked at all"
}

func (r missingResponseSchema) Check(doc *spec.Document) []Finding {
	var out []Finding
	for _, op := range doc.Operations() {
		for status, resp := range op.Responses {
			if !strings.HasPrefix(status, "2") || status == "204" || resp.Schema != nil {
				continue
			}
			out = append(out, Finding{
				RuleID:      r.ID(),
				Severity:    r.Severity(),
				Location:    fmt.Sprintf("%s (%s response)", opLocation(op), status),
				Message:     fmt.Sprintf("the %s response has no content/schema documented", status),
				Remediation: "document the response schema -- this tool (and anyone generating a client from this spec) cannot reason about what the endpoint actually returns without it",
			})
		}
	}
	return out
}
