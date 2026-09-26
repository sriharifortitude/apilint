package report

import (
	"encoding/json"

	"github.com/sriharifortitude/apilint/internal/rules"
	"github.com/sriharifortitude/apilint/internal/waiver"
)

// SARIF 2.1.0, the subset GitHub's code scanning UI reads: one run, one
// tool driver with every rule declared up front, and one result per
// non-waived finding.
type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string                 `json:"id"`
	ShortDescription sarifText              `json:"shortDescription"`
	Properties       map[string]interface{} `json:"properties"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifLocation struct {
	LogicalLocations []sarifLogicalLocation `json:"logicalLocations"`
}

type sarifLogicalLocation struct {
	FullyQualifiedName string `json:"fullyQualifiedName"`
	Kind               string `json:"kind"`
}

func SARIF(r Result) ([]byte, error) {
	seen := map[string]bool{}
	var ruleDefs []sarifRule
	for _, def := range rules.All() {
		if seen[def.ID()] {
			continue
		}
		seen[def.ID()] = true
		ruleDefs = append(ruleDefs, sarifRule{
			ID:               def.ID(),
			ShortDescription: sarifText{Text: def.Description()},
			Properties:       map[string]interface{}{"severity": string(def.Severity())},
		})
	}

	var results []sarifResult
	for _, row := range r.Rows {
		if row.WaiverOutcome == waiver.Waived {
			continue
		}
		results = append(results, sarifResult{
			RuleID:  row.RuleID,
			Level:   sarifLevel(row.Severity),
			Message: sarifText{Text: row.Message},
			Locations: []sarifLocation{{
				LogicalLocations: []sarifLogicalLocation{{FullyQualifiedName: row.Location, Kind: "operation"}},
			}},
		})
	}

	log := sarifLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool:    sarifTool{Driver: sarifDriver{Name: "apilint", InformationURI: "https://github.com/sriharifortitude/apilint", Rules: ruleDefs}},
			Results: results,
		}},
	}
	return json.MarshalIndent(log, "", "  ")
}

func sarifLevel(s rules.Severity) string {
	switch s {
	case rules.Critical, rules.High:
		return "error"
	case rules.Medium:
		return "warning"
	default:
		return "note"
	}
}
