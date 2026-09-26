package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// out runs the CLI in-process and returns the exit code plus whatever
// was written to --output. --output is inserted right after the
// subcommand: flag parsing stops at the first non-flag token, so it
// must come before the positional spec-file argument.
func out(t *testing.T, args ...string) (code int, report string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "report.out")
	withOutput := append([]string{args[0], "--output", path}, args[1:]...)
	code = run(withOutput)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return code, ""
		}
		t.Fatalf("reading report: %s", err)
	}
	return code, string(data)
}

func TestScanTheSmallFixtureWithoutWaivers(t *testing.T) {
	code, report := out(t, "scan", "--format", "json", "../../testdata/small.yaml")
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(report, `"fail": 9`) {
		t.Errorf("report:\n%s", report)
	}
	for _, want := range []string{
		`"rule": "dangling-security-scheme-reference"`,
		`"rule": "sensitive-field-in-response"`,
		`"rule": "mass-assignment-risk"`,
		`"rule": "api-key-in-query-string"`,
		`"rule": "weak-http-basic-auth"`,
	} {
		if !strings.Contains(report, want) {
			t.Errorf("report missing %s\n%s", want, report)
		}
	}
}

func TestScanTheSmallFixtureWithWaivers(t *testing.T) {
	code, report := out(t, "scan", "--format", "json", "--waivers", "../../testdata/waivers.yaml", "../../testdata/small.yaml")
	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (the expired waiver still fails the gate)", code)
	}
	if !strings.Contains(report, `"fail": 7`) || !strings.Contains(report, `"waived": 1`) || !strings.Contains(report, `"expired_waiver": 1`) {
		t.Errorf("report:\n%s", report)
	}
	if !strings.Contains(report, "rate limiting is enforced at the API gateway") {
		t.Error("the active waiver's reason should be in the report")
	}
	if !strings.Contains(report, "was meant to be removed once the OAuth migration finished") {
		t.Error("the expired waiver's reason should still be visible")
	}
}

func TestScanWithAHighFailOnThresholdDropsLowAndMediumFindings(t *testing.T) {
	code, _ := out(t, "scan", "--fail-on", "critical", "--waivers", "../../testdata/waivers.yaml", "../../testdata/small.yaml")
	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (two CRITICAL findings remain)", code)
	}
}

func TestScanTheCleanFixtureExitsZero(t *testing.T) {
	code, report := out(t, "scan", "--format", "json", "../../testdata/clean.yaml")
	if code != 0 {
		t.Fatalf("exit code = %d, want 0: %s", code, report)
	}
	if !strings.Contains(report, `"findings": null`) && !strings.Contains(report, `"findings": []`) {
		t.Errorf("expected no findings at all:\n%s", report)
	}
}

func TestSarifOutputIsWellFormedAndOmitsWaivedFindings(t *testing.T) {
	code, report := out(t, "scan", "--format", "sarif", "--waivers", "../../testdata/waivers.yaml", "../../testdata/small.yaml")
	if code != 1 {
		t.Fatalf("exit code = %d", code)
	}
	if !strings.Contains(report, `"version": "2.1.0"`) {
		t.Error("not a SARIF 2.1.0 document")
	}
	if strings.Contains(report, "API gateway") {
		t.Error("a waived finding's reason should not leak into SARIF")
	}
	if !strings.Contains(report, `"ruleId": "weak-http-basic-auth"`) {
		t.Error("the expired-waiver finding should still be a real SARIF result")
	}
}

func TestUnreadableSpecFileExitsTwo(t *testing.T) {
	code, _ := out(t, "scan", "does-not-exist.yaml")
	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
}

func TestNotAnOpenAPIDocumentExitsTwoWithAReason(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(bad, []byte("hello: world\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _ := out(t, "scan", bad)
	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
}

func TestUnknownFailOnValueIsRejected(t *testing.T) {
	code, _ := out(t, "scan", "--fail-on", "severe", "../../testdata/clean.yaml")
	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
}

func TestBadWaiverFileIsRejected(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "waivers.yaml")
	if err := os.WriteFile(bad, []byte("waivers:\n  - rule: x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _ := out(t, "scan", "--waivers", bad, "../../testdata/clean.yaml")
	if code != 2 {
		t.Fatalf("exit code = %d, want 2 (missing location/reason/expires)", code)
	}
}

func TestNoSubcommandPrintsUsage(t *testing.T) {
	if code := run(nil); code != 2 {
		t.Fatalf("run(nil) = %d, want 2", code)
	}
	if code := run([]string{"bogus"}); code != 2 {
		t.Fatalf("run([bogus]) = %d, want 2", code)
	}
}
