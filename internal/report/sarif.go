package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"

	"github.com/OTA-EITA/kube-rbac-paths/internal/check"
	"github.com/OTA-EITA/kube-rbac-paths/internal/rbac"
)

// SARIF 2.1.0, the subset GitHub code scanning reads.
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
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifRule struct {
	ID                   string         `json:"id"`
	Name                 string         `json:"name"`
	ShortDescription     sarifText      `json:"shortDescription"`
	FullDescription      sarifText      `json:"fullDescription"`
	Help                 sarifText      `json:"help"`
	HelpURI              string         `json:"helpUri"`
	DefaultConfiguration map[string]any `json:"defaultConfiguration"`
	Properties           map[string]any `json:"properties"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	RelatedLocations    []sarifLocation   `json:"relatedLocations,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	Properties          map[string]any    `json:"properties"`
}

type sarifLocation struct {
	ID               *int                  `json:"id,omitempty"`
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
	Message          *sarifText            `json:"message,omitempty"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           *sarifRegion  `json:"region,omitempty"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

func level(s check.Severity) string {
	switch s {
	case check.High:
		return "error"
	case check.Medium:
		return "warning"
	}
	return "note"
}

// securitySeverity maps to GitHub's critical/high/medium/low buckets.
func securitySeverity(s check.Severity) string {
	switch s {
	case check.High:
		return "8.0"
	case check.Medium:
		return "5.0"
	}
	return "2.0"
}

func location(s rbac.Source) sarifLocation {
	l := sarifLocation{PhysicalLocation: sarifPhysicalLocation{ArtifactLocation: sarifArtifact{URI: s.File}}}
	if s.Line > 0 {
		l.PhysicalLocation.Region = &sarifRegion{StartLine: s.Line}
	}
	return l
}

// SARIF writes a SARIF 2.1.0 log.
func SARIF(w io.Writer, res check.Result, meta Meta) error {
	driver := sarifDriver{Name: "kube-rbac-paths", Version: meta.Version, InformationURI: "https://github.com/OTA-EITA/kube-rbac-paths"}
	index := map[string]int{}
	for i, c := range check.Checks {
		index[c.ID] = i
		driver.Rules = append(driver.Rules, sarifRule{
			ID: c.ID, Name: c.Title,
			ShortDescription:     sarifText{c.Title},
			FullDescription:      sarifText{c.Why},
			Help:                 sarifText{"How to reduce: " + c.Fix + " See " + c.URL()},
			HelpURI:              c.URL(),
			DefaultConfiguration: map[string]any{"level": "warning"},
			Properties:           map[string]any{"tags": []string{"security", "kubernetes", "rbac"}},
		})
	}
	results := []sarifResult{}
	for _, f := range res.Findings {
		c := f.Check()
		r := sarifResult{
			RuleID: f.CheckID, RuleIndex: index[f.CheckID], Level: level(f.Severity),
			Message:   sarifText{f.Message + ". Why it matters: " + c.Why + " How to reduce: " + c.Fix},
			Locations: []sarifLocation{location(f.Location)},
			PartialFingerprints: map[string]string{
				"kubeRbacPaths/v1": hash(f.Fingerprint),
			},
			Properties: map[string]any{"security-severity": securitySeverity(f.Severity)},
		}
		id := 1
		for _, e := range f.Evidence {
			if e.Source.File == "" || e.Source.Builtin() {
				continue
			}
			l := location(e.Source)
			n := id
			l.ID = &n
			l.Message = &sarifText{e.Text}
			r.RelatedLocations = append(r.RelatedLocations, l)
			id++
		}
		results = append(results, r)
	}
	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs:    []sarifRun{{Tool: sarifTool{Driver: driver}, Results: results}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

func hash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:16])
}
