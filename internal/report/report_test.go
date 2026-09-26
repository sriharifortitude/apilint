package report

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/sriharifortitude/apilint/internal/rules"
	"github.com/sriharifortitude/apilint/internal/waiver"
)

func sample() Result {
	rows := []Row{
		{Finding: rules.Finding{
			RuleID: "missing-security-requirement", Severity: rules.Critical, Location: "GET /users/{id}",
			Message: "no security requirement", Remediation: "add one",
		}},
		{Finding: rules.Finding{
			RuleID: "missing-rate-limit-evidence", Severity: rules.Low, Location: "(whole document)",
			Message: "no 429 documented", Remediation: "document one",
		}, WaiverOutcome: waiver.Waived, Waiver: &waiver.Entry{Reason: "internal API, gateway rate-limits", Expires: "2030-01-01"}},
		{Finding: rules.Finding{
			RuleID: "unencrypted-server-url", Severity: rules.Medium, Location: "servers[0]",
			Message: "plain http", Remediation: "use https",
		}, WaiverOutcome: waiver.Expired, Waiver: &waiver.Entry{Reason: "temporary", Expires: "2025-01-01"}},
	}
	return NewResult(rows)
}

func TestCountsBucketsEachRowExactlyOnce(t *testing.T) {
	c := sample().Counts()
	if c.Fail != 1 || c.Waived != 1 || c.ExpiredWaiver != 1 {
		t.Fatalf("got %+v, want Fail=1 Waived=1 ExpiredWaiver=1", c)
	}
}

func TestFailingExcludesWaivedButIncludesExpired(t *testing.T) {
	failing := sample().Failing(rules.Low)
	if len(failing) != 2 {
		t.Fatalf("got %d, want 2", len(failing))
	}
}

func TestTerminalShowsExpiredLabelAndSummary(t *testing.T) {
	out := Terminal(sample())
	if !strings.Contains(out, "WAIVER EXPIRED") {
		t.Errorf("missing EXPIRED label:\n%s", out)
	}
	if !strings.Contains(out, "3 findings: 1 failing, 1 waived, 1 expired waivers") {
		t.Errorf("missing or wrong summary line:\n%s", out)
	}
}

func TestJSONRoundTrips(t *testing.T) {
	data, err := JSON(sample())
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Summary  Counts    `json:"summary"`
		Findings []jsonRow `json:"findings"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.Summary.Fail != 1 {
		t.Errorf("summary = %+v", parsed.Summary)
	}
	if len(parsed.Findings) != 3 {
		t.Fatalf("got %d findings, want 3", len(parsed.Findings))
	}
}

func TestSARIFOmitsWaivedButKeepsExpired(t *testing.T) {
	data, err := SARIF(sample())
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID string `json:"ruleId"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatal(err)
	}
	if len(parsed.Runs[0].Tool.Driver.Rules) != len(rules.All()) {
		t.Fatalf("declared %d rules, want all %d", len(parsed.Runs[0].Tool.Driver.Rules), len(rules.All()))
	}
	if len(parsed.Runs[0].Results) != 2 {
		t.Fatalf("got %d results, want 2 (waived omitted, expired kept)", len(parsed.Runs[0].Results))
	}
}
