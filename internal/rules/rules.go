// Package rules holds apilint's checks: OWASP API Security Top 10
// signals detectable from an OpenAPI document alone, with no live
// server to call. Every check is a plain pass/fail -- an OpenAPI
// document is a static artifact, the same reasoning kubeshield applies
// to a Kubernetes manifest (see that repo's ADR 1): there is nothing in
// it that is "unknown until a request actually happens," only things
// the spec's author did or didn't write down.
package rules

import (
	"fmt"
	"strings"

	"github.com/sriharifortitude/apilint/internal/spec"
)

type Severity string

const (
	Critical Severity = "CRITICAL"
	High     Severity = "HIGH"
	Medium   Severity = "MEDIUM"
	Low      Severity = "LOW"
)

var severityOrder = map[Severity]int{Low: 0, Medium: 1, High: 2, Critical: 3}

// AtLeast reports whether s is at or above threshold.
func (s Severity) AtLeast(threshold Severity) bool {
	return severityOrder[s] >= severityOrder[threshold]
}

// Finding is one rule's verdict against one location in the document --
// an operation ("GET /users/{id}"), a component ("components.
// securitySchemes.apiKey"), or the document as a whole ("servers[0]").
type Finding struct {
	RuleID      string
	Severity    Severity
	Location    string
	Message     string
	Remediation string
}

// Rule inspects the whole document and reports every location it has an
// opinion about.
type Rule interface {
	ID() string
	Severity() Severity
	Description() string
	Check(doc *spec.Document) []Finding
}

var registry []Rule

func register(r Rule) {
	for _, existing := range registry {
		if existing.ID() == r.ID() {
			panic(fmt.Sprintf("rule ID %q registered twice", r.ID()))
		}
	}
	registry = append(registry, r)
}

// All returns every built-in rule, in registration order.
func All() []Rule {
	out := make([]Rule, len(registry))
	copy(out, registry)
	return out
}

// RunAll executes every rule and returns every finding, in rule order.
func RunAll(doc *spec.Document) []Finding {
	var out []Finding
	for _, r := range All() {
		out = append(out, r.Check(doc)...)
	}
	return out
}

func opLocation(op spec.Operation) string {
	return fmt.Sprintf("%s %s", strings.ToUpper(op.Method), op.Path)
}
