// Command apilint checks an OpenAPI 3.x document for OWASP API
// Security Top 10 signals detectable from the spec alone.
//
//	apilint scan openapi.yaml
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/sriharifortitude/apilint/internal/report"
	"github.com/sriharifortitude/apilint/internal/rules"
	"github.com/sriharifortitude/apilint/internal/spec"
	"github.com/sriharifortitude/apilint/internal/waiver"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 || args[0] != "scan" {
		fmt.Fprintln(os.Stderr, usage)
		return 2
	}
	fs := newFlagSet()
	if err := fs.Parse(args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "scan: expected exactly one OpenAPI document")
		return 2
	}

	specPath := fs.Arg(0)
	specData, err := os.ReadFile(specPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "reading %s: %s\n", specPath, err)
		return 2
	}
	doc, err := spec.Parse(specData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %s\n", specPath, err)
		return 2
	}

	var w waiver.File
	if fs.waivers != "" {
		data, err := os.ReadFile(fs.waivers)
		if err != nil {
			fmt.Fprintf(os.Stderr, "reading %s: %s\n", fs.waivers, err)
			return 2
		}
		parsed, err := waiver.Parse(data)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %s\n", fs.waivers, err)
			return 2
		}
		w = *parsed
	}

	threshold, err := parseSeverity(fs.failOn)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	findings := rules.RunAll(doc)
	rows := make([]report.Row, 0, len(findings))
	today := time.Now()
	for _, f := range findings {
		outcome, entry := w.Apply(f, today)
		rows = append(rows, report.Row{Finding: f, WaiverOutcome: outcome, Waiver: entry})
	}
	result := report.NewResult(rows)

	out, err := render(result, fs.format)
	if err != nil {
		fmt.Fprintf(os.Stderr, "rendering %s report: %s\n", fs.format, err)
		return 2
	}
	if err := write(out, fs.output); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if fs.output != "" && fs.format != "terminal" {
		fmt.Print(report.Terminal(result))
	}

	if len(result.Failing(threshold)) > 0 {
		return 1
	}
	return 0
}

func render(r report.Result, format string) (string, error) {
	switch format {
	case "terminal", "":
		return report.Terminal(r), nil
	case "json":
		b, err := report.JSON(r)
		return string(b) + "\n", err
	case "sarif":
		b, err := report.SARIF(r)
		return string(b) + "\n", err
	default:
		return "", fmt.Errorf("unknown format %q: expected terminal, json or sarif", format)
	}
}

func write(text, path string) error {
	if path == "" {
		fmt.Print(text)
		return nil
	}
	return os.WriteFile(path, []byte(text), 0o644)
}

func parseSeverity(s string) (rules.Severity, error) {
	switch s {
	case "low", "":
		return rules.Low, nil
	case "medium":
		return rules.Medium, nil
	case "high":
		return rules.High, nil
	case "critical":
		return rules.Critical, nil
	default:
		return "", fmt.Errorf("--fail-on: expected low, medium, high or critical, got %q", s)
	}
}

const usage = `usage: apilint scan [--format terminal|json|sarif] [--output FILE] [--fail-on low|medium|high|critical] [--waivers FILE] <openapi.yaml>`
