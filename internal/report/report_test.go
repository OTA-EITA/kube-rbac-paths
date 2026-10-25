package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/OTA-EITA/kube-rbac-paths/internal/check"
	"github.com/OTA-EITA/kube-rbac-paths/internal/rbac"
)

func sample() check.Result {
	alice := rbac.Subject{Kind: rbac.KindUser, Name: "alice"}
	bot := rbac.Subject{Kind: rbac.KindServiceAccount, Namespace: "team", Name: "bot"}
	binding := rbac.Source{File: "rbac.yaml", Line: 10}
	builtin := rbac.Source{File: rbac.BuiltinPrefix + "kubernetes/cluster-roles.yaml", Line: 20}
	return check.Result{
		Subjects: 2, Excluded: 1, Duplicates: 1,
		Unresolved: []string{"RoleBinding team/x (rbac.yaml:40) references Role gone"},
		Admins: []check.Admin{{
			Subject: alice, Via: &bot, Chain: []rbac.Subject{bot}, Reason: "can create pods in namespace team, where ServiceAccount team/bot lives",
			Evidence: []check.Evidence{{Text: "RoleBinding team/edit binds ClusterRole edit to User alice", Source: binding}, {Text: "ClusterRole edit", Source: builtin}},
			UsedBy:   []check.Evidence{{Text: "runs as it: Deployment team/bot", Source: rbac.Source{File: "deploy.yaml", Line: 1}}},
		}},
		Findings: []check.Finding{
			{CheckID: check.EffectiveAdmin, Severity: check.High, Subject: &alice, Message: "User alice effectively holds cluster-admin-equivalent permissions because it can create pods", Location: binding, Fingerprint: "KRP014|alice"},
			{CheckID: check.SecretsRead, Severity: check.Medium, Subject: &alice, Message: "User alice can get secrets in namespace team | pipe", Location: binding,
				Evidence:    []check.Evidence{{Text: "rule verbs=[get]", Source: rbac.Source{File: "rbac.yaml", Line: 5}}, {Text: "ClusterRole edit", Source: builtin}, {Text: "no source"}},
				Fingerprint: "KRP003|alice"},
			{CheckID: check.WorkloadCreate, Severity: check.Low, Subject: &alice, Message: "User alice can create pods in namespace team", Location: rbac.Source{File: "stdin"}, Fingerprint: "KRP004|alice"},
		},
	}
}

func render(t *testing.T, format string, res check.Result, meta Meta) string {
	t.Helper()
	var b bytes.Buffer
	if err := Write(&b, format, res, meta); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func TestText(t *testing.T) {
	out := render(t, "text", sample(), Meta{})
	for _, want := range []string{
		"Effective cluster-admin (1)",
		"  User alice\n    can create pods in namespace team",
		"      RoleBinding team/edit binds ClusterRole edit to User alice  rbac.yaml:10",
		"      ClusterRole edit  (built-in)",
		"      runs as it: Deployment team/bot  deploy.yaml:1",
		"rbac.yaml:10  HIGH   KRP014  User alice effectively holds",
		"rbac.yaml:10  MEDIUM KRP003  User alice can get secrets",
		"      rule verbs=[get]  rbac.yaml:5",
		"    why: get reveals a Secret",
		"    fix: drop list and watch",
		"    see: https://kubernetes.io/docs/concepts/security/rbac-good-practices/#listing-secrets",
		"stdin  LOW    KRP004",
		"note: RoleBinding team/x (rbac.yaml:40) references Role gone, which is not in the inputs",
		"note: 1 object(s) defined more than once",
		"2 subject(s) audited, 1 cluster-admin-equivalent, 3 finding(s): 1 high, 1 medium, 1 low (1 built-in system subject(s) excluded",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("text output lacks %q:\n%s", want, out)
		}
	}
	diff := render(t, "text", sample(), Meta{Diff: true})
	if !strings.Contains(diff, "New effective cluster-admin (1)") || !strings.Contains(diff, "3 new finding(s)") {
		t.Errorf("diff text:\n%s", diff)
	}
	empty := render(t, "text", check.Result{}, Meta{})
	if empty != "0 subject(s) audited, 0 cluster-admin-equivalent, 0 finding(s): 0 high, 0 medium, 0 low\n" {
		t.Errorf("empty text = %q", empty)
	}
}

func TestJSON(t *testing.T) {
	out := render(t, "json", sample(), Meta{Version: "v1", Diff: true})
	var got struct {
		Tool     string `json:"tool"`
		Version  string `json:"version"`
		Diff     bool   `json:"diff"`
		Subjects int    `json:"subjects"`
		Findings []struct {
			Check    string `json:"check"`
			Severity string `json:"severity"`
			Title    string `json:"title"`
			Docs     string `json:"docs"`
			Why      string `json:"why"`
			Location struct {
				File string `json:"file"`
				Line int    `json:"line"`
			} `json:"location"`
		} `json:"findings"`
		Admins []struct {
			Via   *rbac.Subject  `json:"via"`
			Chain []rbac.Subject `json:"chain"`
		} `json:"effectiveAdmins"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatal(err)
	}
	if got.Tool != "kube-rbac-paths" || got.Version != "v1" || !got.Diff || got.Subjects != 2 || len(got.Findings) != 3 {
		t.Fatalf("json = %+v", got)
	}
	f := got.Findings[1]
	if f.Check != "KRP003" || f.Severity != "medium" || f.Title != "Read access to Secrets" || !strings.HasSuffix(f.Docs, "#listing-secrets") || f.Why == "" || f.Location.Line != 10 {
		t.Errorf("finding = %+v", f)
	}
	if len(got.Admins) != 1 || got.Admins[0].Via == nil || len(got.Admins[0].Chain) != 1 || got.Admins[0].Chain[0].Name != "bot" {
		t.Errorf("admins = %+v", got.Admins)
	}
	empty := render(t, "json", check.Result{}, Meta{})
	if !strings.Contains(empty, `"findings": []`) || !strings.Contains(empty, `"effectiveAdmins": []`) {
		t.Errorf("empty json should have empty arrays:\n%s", empty)
	}
}

func TestMarkdown(t *testing.T) {
	out := render(t, "markdown", sample(), Meta{Diff: true})
	for _, want := range []string{
		"### kube-rbac-paths (new in this change)",
		"#### Effective cluster-admin",
		"- **User alice** can create pods in namespace team",
		"  - ClusterRole edit `(built-in)`",
		"| high | [KRP014](https://kubernetes.io/docs/concepts/security/rbac-good-practices/#privilege-escalation-risks) Effective cluster-admin |",
		`in namespace team \| pipe`,
		"<details><summary>Why these matter",
		"- **KRP003 Read access to Secrets**:",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown lacks %q:\n%s", want, out)
		}
	}
	if strings.Count(out, "- **KRP003") != 1 {
		t.Error("each check is explained once")
	}
	empty := render(t, "markdown", check.Result{}, Meta{})
	if strings.Contains(empty, "| Severity") {
		t.Errorf("no table without findings:\n%s", empty)
	}
}

func TestSARIF(t *testing.T) {
	out := render(t, "sarif", sample(), Meta{Version: "v0.1.0"})
	var log struct {
		Version string `json:"version"`
		Schema  string `json:"$schema"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name    string `json:"name"`
					Version string `json:"version"`
					Rules   []struct {
						ID      string `json:"id"`
						HelpURI string `json:"helpUri"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				RuleIndex int    `json:"ruleIndex"`
				Level     string `json:"level"`
				Message   struct {
					Text string `json:"text"`
				} `json:"message"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						Region *struct {
							StartLine int `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
				RelatedLocations []struct {
					ID int `json:"id"`
				} `json:"relatedLocations"`
				PartialFingerprints map[string]string `json:"partialFingerprints"`
				Properties          map[string]string `json:"properties"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(out), &log); err != nil {
		t.Fatal(err)
	}
	if log.Version != "2.1.0" || !strings.Contains(log.Schema, "sarif-2.1.0") || len(log.Runs) != 1 {
		t.Fatalf("log = %+v", log)
	}
	run := log.Runs[0]
	if run.Tool.Driver.Name != "kube-rbac-paths" || run.Tool.Driver.Version != "v0.1.0" || len(run.Tool.Driver.Rules) != len(check.Checks) {
		t.Errorf("driver = %+v", run.Tool.Driver)
	}
	if len(run.Results) != 3 {
		t.Fatalf("results = %d", len(run.Results))
	}
	levels := []string{"error", "warning", "note"}
	sev := []string{"8.0", "5.0", "2.0"}
	for i, r := range run.Results {
		if r.Level != levels[i] || r.Properties["security-severity"] != sev[i] || len(r.PartialFingerprints["kubeRbacPaths/v1"]) != 32 {
			t.Errorf("result %d = %+v", i, r)
		}
		if run.Tool.Driver.Rules[r.RuleIndex].ID != r.RuleID {
			t.Errorf("result %d ruleIndex %d does not point at %s", i, r.RuleIndex, r.RuleID)
		}
	}
	first := run.Results[0].Locations[0].PhysicalLocation
	if first.ArtifactLocation.URI != "rbac.yaml" || first.Region == nil || first.Region.StartLine != 10 {
		t.Errorf("location = %+v", first)
	}
	if run.Results[2].Locations[0].PhysicalLocation.Region != nil {
		t.Error("a location without a line has no region")
	}
	// Built-in roles and evidence without a file are not locations.
	if rl := run.Results[1].RelatedLocations; len(rl) != 1 || rl[0].ID != 1 {
		t.Errorf("related locations = %+v", rl)
	}
	if !strings.Contains(run.Results[1].Message.Text, "Why it matters:") || !strings.Contains(run.Results[1].Message.Text, "How to reduce:") {
		t.Errorf("message = %s", run.Results[1].Message.Text)
	}
	empty := render(t, "sarif", check.Result{}, Meta{})
	if !strings.Contains(empty, `"results": []`) {
		t.Error("empty SARIF must have an empty results array")
	}
}

func TestUnknownFormat(t *testing.T) {
	if err := Write(&bytes.Buffer{}, "xml", check.Result{}, Meta{}); err == nil {
		t.Fatal("expected an error")
	}
}
