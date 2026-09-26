package rules

import (
	"testing"

	"github.com/sriharifortitude/apilint/internal/spec"
)

func parseOne(t *testing.T, yaml string) *spec.Document {
	t.Helper()
	doc, err := spec.Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func ruleByID(id string) Rule {
	for _, r := range All() {
		if r.ID() == id {
			return r
		}
	}
	return nil
}

func check(t *testing.T, ruleID, yaml string) []Finding {
	t.Helper()
	rule := ruleByID(ruleID)
	if rule == nil {
		t.Fatalf("no registered rule %q", ruleID)
	}
	return rule.Check(parseOne(t, yaml))
}

func TestRegistryHasNoDuplicateIDs(t *testing.T) {
	seen := map[string]bool{}
	all := All()
	if len(all) != 10 {
		t.Fatalf("got %d rules, want 10", len(all))
	}
	for _, r := range all {
		if seen[r.ID()] {
			t.Fatalf("duplicate rule ID %q", r.ID())
		}
		seen[r.ID()] = true
	}
}

const docHeader = "openapi: 3.0.3\ninfo: {title: x, version: \"1\"}\n"
