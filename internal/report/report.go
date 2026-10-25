// Package report writes audit results as text, JSON, Markdown or SARIF.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/OTA-EITA/kube-rbac-paths/internal/check"
	"github.com/OTA-EITA/kube-rbac-paths/internal/rbac"
)

// Formats lists the supported output formats.
var Formats = []string{"text", "json", "markdown", "sarif"}

// Meta describes the run, for headers and SARIF.
type Meta struct {
	Version string
	// Diff is true in diff mode, where only new findings are shown.
	Diff bool
}

// Write renders res in the given format.
func Write(w io.Writer, format string, res check.Result, meta Meta) error {
	switch format {
	case "text":
		return Text(w, res, meta)
	case "json":
		return JSON(w, res, meta)
	case "markdown":
		return Markdown(w, res, meta)
	case "sarif":
		return SARIF(w, res, meta)
	}
	return fmt.Errorf("unknown format %q (want %s)", format, strings.Join(Formats, ", "))
}

func summary(res check.Result, meta Meta) string {
	var high, medium, low int
	for _, f := range res.Findings {
		switch f.Severity {
		case check.High:
			high++
		case check.Medium:
			medium++
		case check.Low:
			low++
		}
	}
	noun := "finding(s)"
	if meta.Diff {
		noun = "new finding(s)"
	}
	s := fmt.Sprintf("%d subject(s) audited, %d cluster-admin-equivalent, %d %s: %d high, %d medium, %d low",
		res.Subjects, len(res.Admins), len(res.Findings), noun, high, medium, low)
	if res.Excluded > 0 {
		s += fmt.Sprintf(" (%d built-in system subject(s) excluded; --include-system shows them)", res.Excluded)
	}
	return s
}

func loc(s rbac.Source) string {
	if s.Builtin() {
		return "(built-in)"
	}
	return s.String()
}

// Text writes a report for a terminal.
func Text(w io.Writer, res check.Result, meta Meta) error {
	if len(res.Admins) > 0 {
		title := "Effective cluster-admin"
		if meta.Diff {
			title = "New effective cluster-admin"
		}
		fmt.Fprintf(w, "%s (%d)\n\n", title, len(res.Admins))
		for _, a := range res.Admins {
			fmt.Fprintf(w, "  %s\n    %s\n", a.Subject, a.Reason)
			for _, e := range append(a.Evidence, a.UsedBy...) {
				fmt.Fprintf(w, "      %s  %s\n", e.Text, loc(e.Source))
			}
			fmt.Fprintln(w)
		}
	}
	if len(res.Findings) > 0 {
		fmt.Fprintf(w, "Findings\n\n")
	}
	for _, f := range res.Findings {
		c := f.Check()
		fmt.Fprintf(w, "%s  %-6s %s  %s\n", loc(f.Location), strings.ToUpper(f.Severity.String()), f.CheckID, f.Message)
		if f.CheckID != check.EffectiveAdmin {
			for _, e := range f.Evidence {
				fmt.Fprintf(w, "      %s  %s\n", e.Text, loc(e.Source))
			}
		}
		fmt.Fprintf(w, "    why: %s\n    fix: %s\n    see: %s\n\n", c.Why, c.Fix, c.URL())
	}
	for _, u := range res.Unresolved {
		fmt.Fprintf(w, "note: %s, which is not in the inputs; it was not analysed\n", u)
	}
	if res.Duplicates > 0 {
		fmt.Fprintf(w, "note: %d object(s) defined more than once; the first definition was used\n", res.Duplicates)
	}
	fmt.Fprintln(w, summary(res, meta))
	return nil
}

type jsonFinding struct {
	check.Finding
	Title string `json:"title"`
	Why   string `json:"why"`
	Fix   string `json:"fix"`
	Docs  string `json:"docs"`
}

type jsonReport struct {
	Tool    string `json:"tool"`
	Version string `json:"version"`
	Diff    bool   `json:"diff,omitempty"`
	check.Result
	Findings []jsonFinding `json:"findings"`
}

// JSON writes the full result.
func JSON(w io.Writer, res check.Result, meta Meta) error {
	out := jsonReport{Tool: "kube-rbac-paths", Version: meta.Version, Diff: meta.Diff, Result: res, Findings: []jsonFinding{}}
	if out.Admins == nil {
		out.Admins = []check.Admin{}
	}
	for _, f := range res.Findings {
		c := f.Check()
		out.Findings = append(out.Findings, jsonFinding{Finding: f, Title: c.Title, Why: c.Why, Fix: c.Fix, Docs: c.URL()})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func mdEscape(s string) string {
	return strings.NewReplacer("|", `\|`, "\n", " ", "*", `\*`, "_", `\_`, "<", "&lt;", ">", "&gt;").Replace(s)
}

// Markdown writes a report for a pull request comment or job summary.
func Markdown(w io.Writer, res check.Result, meta Meta) error {
	title := "kube-rbac-paths"
	if meta.Diff {
		title += " (new in this change)"
	}
	fmt.Fprintf(w, "### %s\n\n%s\n\n", title, summary(res, meta))
	if len(res.Admins) > 0 {
		fmt.Fprintf(w, "#### Effective cluster-admin\n\n")
		for _, a := range res.Admins {
			fmt.Fprintf(w, "- **%s** %s\n", mdEscape(a.Subject.String()), mdEscape(a.Reason))
			for _, e := range append(a.Evidence, a.UsedBy...) {
				fmt.Fprintf(w, "  - %s `%s`\n", mdEscape(e.Text), loc(e.Source))
			}
		}
		fmt.Fprintln(w)
	}
	if len(res.Findings) > 0 {
		fmt.Fprintf(w, "| Severity | Check | Finding | Location |\n| --- | --- | --- | --- |\n")
		for _, f := range res.Findings {
			c := f.Check()
			fmt.Fprintf(w, "| %s | [%s](%s) %s | %s | `%s` |\n", f.Severity, f.CheckID, c.URL(), mdEscape(c.Title), mdEscape(f.Message), loc(f.Location))
		}
		fmt.Fprintln(w)
		fmt.Fprintf(w, "<details><summary>Why these matter and how to reduce them</summary>\n\n")
		seen := map[string]bool{}
		for _, f := range res.Findings {
			if seen[f.CheckID] {
				continue
			}
			seen[f.CheckID] = true
			c := f.Check()
			fmt.Fprintf(w, "- **%s %s**: %s Fix: %s\n", c.ID, mdEscape(c.Title), mdEscape(c.Why), mdEscape(c.Fix))
		}
		fmt.Fprintf(w, "\n</details>\n")
	}
	return nil
}
