package waiver

import (
	"strings"
	"testing"
	"time"

	"github.com/sriharifortitude/apilint/internal/rules"
)

func TestParseRequiresEveryField(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want string
	}{
		{"missing rule", `waivers:
  - location: "GET /users"
    reason: test
    expires: "2030-01-01"`, "rule"},
		{"missing location", `waivers:
  - rule: missing-security-requirement
    reason: test
    expires: "2030-01-01"`, "location"},
		{"missing reason", `waivers:
  - rule: missing-security-requirement
    location: "GET /users"
    expires: "2030-01-01"`, "reason"},
		{"missing expires", `waivers:
  - rule: missing-security-requirement
    location: "GET /users"
    reason: test`, "expires"},
		{"malformed expires", `waivers:
  - rule: missing-security-requirement
    location: "GET /users"
    reason: test
    expires: "next tuesday"`, "expires"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Parse([]byte(c.yaml))
			if err == nil {
				t.Fatalf("Parse(%q) succeeded, want an error", c.yaml)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error %q does not mention %q", err, c.want)
			}
		})
	}
}

func TestApplyMatchesOnRuleAndLocationExactly(t *testing.T) {
	f := &File{Waivers: []Entry{{
		Rule: "missing-rate-limit-evidence", Location: "(whole document)",
		Reason: "test", Expires: "2030-01-01",
	}}}
	today := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	match := rules.Finding{RuleID: "missing-rate-limit-evidence", Location: "(whole document)"}
	if outcome, entry := f.Apply(match, today); outcome != Waived || entry == nil {
		t.Fatalf("got %v, %v, want Waived", outcome, entry)
	}

	wrongLocation := rules.Finding{RuleID: "missing-rate-limit-evidence", Location: "GET /users"}
	if outcome, _ := f.Apply(wrongLocation, today); outcome != NotWaived {
		t.Fatalf("got %v, want NotWaived", outcome)
	}
}

func TestApplyReportsExpiredSeparatelyFromWaived(t *testing.T) {
	f := &File{Waivers: []Entry{{
		Rule: "unencrypted-server-url", Location: "servers[0]", Reason: "test", Expires: "2026-06-15",
	}}}
	finding := rules.Finding{RuleID: "unencrypted-server-url", Location: "servers[0]"}

	dayBefore := time.Date(2026, 6, 14, 0, 0, 0, 0, time.UTC)
	if outcome, _ := f.Apply(finding, dayBefore); outcome != Waived {
		t.Errorf("day before expiry: got %v, want Waived", outcome)
	}
	expiryDay := time.Date(2026, 6, 15, 0, 0, 0, 0, time.UTC)
	if outcome, _ := f.Apply(finding, expiryDay); outcome != Waived {
		t.Errorf("expiry day itself: got %v, want Waived", outcome)
	}
	dayAfter := time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC)
	if outcome, _ := f.Apply(finding, dayAfter); outcome != Expired {
		t.Errorf("day after expiry: got %v, want Expired", outcome)
	}
}
