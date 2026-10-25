package main

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

const (
	risky = "../../test/fixtures/risky"
	safe  = "../../test/fixtures/safe"
)

func runCLI(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := run(args, strings.NewReader(stdin), &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestRiskyFixtures(t *testing.T) {
	code, out, _ := runCLI(t, "", risky)
	if code != exitFindings {
		t.Fatalf("exit = %d, want 1\n%s", code, out)
	}
	for _, id := range []string{"KRP001", "KRP002", "KRP003", "KRP004", "KRP005", "KRP006", "KRP007", "KRP008", "KRP009", "KRP010", "KRP011", "KRP012", "KRP013", "KRP014", "KRP015", "KRP016"} {
		if !strings.Contains(out, " "+id+" ") {
			t.Errorf("risky fixtures should trigger %s", id)
		}
	}
	for _, want := range []string{
		"Effective cluster-admin (8)",
		"User bob@example.com\n    can patch deployments in namespace delivery, where ServiceAccount delivery/pipeline lives, so it can set serviceAccountName in their Pod template to that ServiceAccount; ServiceAccount delivery/pipeline can create tokens for ServiceAccount infra/cluster-operator, and ServiceAccount infra/cluster-operator holds every verb",
		"User alice@example.com\n    can create pods, replicationcontrollers, deployments and 5 more in namespace team-a, where ServiceAccount team-a/release-bot lives",
		"runs as it: CronJob team-a/release",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q", want)
		}
	}
}

func TestSafeFixtures(t *testing.T) {
	code, out, _ := runCLI(t, "", "--fail-on", "low", safe)
	if code != exitOK || !strings.Contains(out, "0 finding(s)") {
		t.Fatalf("exit = %d\n%s", code, out)
	}
}

func TestFailOn(t *testing.T) {
	tests := []struct {
		failOn string
		want   int
	}{{"high", exitFindings}, {"medium", exitFindings}, {"low", exitFindings}, {"none", exitOK}}
	for _, tt := range tests {
		if code, _, _ := runCLI(t, "", "--fail-on", tt.failOn, risky); code != tt.want {
			t.Errorf("--fail-on %s: exit %d, want %d", tt.failOn, code, tt.want)
		}
	}
	// Only a low finding: medium passes, low fails.
	low := "apiVersion: rbac.authorization.k8s.io/v1\nkind: RoleBinding\nmetadata: {name: b, namespace: team}\nroleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: r}\nsubjects: [{kind: User, name: u}]\n---\napiVersion: rbac.authorization.k8s.io/v1\nkind: Role\nmetadata: {name: r, namespace: team}\nrules: [{apiGroups: [\"\"], resources: [pods], verbs: [create]}]\n"
	if code, _, _ := runCLI(t, low, "-"); code != exitOK {
		t.Errorf("low finding with default --fail-on medium: exit %d", code)
	}
	if code, _, _ := runCLI(t, low, "--fail-on", "low", "-"); code != exitFindings {
		t.Errorf("low finding with --fail-on low: exit %d", code)
	}
}

func TestStdinAndFlagsAfterPaths(t *testing.T) {
	data, err := os.ReadFile(risky + "/ci.yaml")
	if err != nil {
		t.Fatal(err)
	}
	code, out, _ := runCLI(t, string(data), "-", "--format", "json")
	if code != exitFindings {
		t.Fatalf("exit = %d", code)
	}
	var got struct {
		Findings []struct {
			Location struct{ File string } `json:"location"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("flags after the path were not parsed: %v\n%s", err, out)
	}
	if len(got.Findings) == 0 || got.Findings[0].Location.File != "stdin" {
		t.Errorf("findings = %+v", got.Findings)
	}
}

func TestFormats(t *testing.T) {
	for _, f := range []string{"text", "json", "markdown", "sarif"} {
		code, out, _ := runCLI(t, "", "--format", f, "--fail-on", "none", risky)
		if code != exitOK || out == "" {
			t.Errorf("%s: exit %d, %d bytes", f, code, len(out))
		}
	}
}

func TestNamespaceAndBuiltinFlags(t *testing.T) {
	doc := "apiVersion: rbac.authorization.k8s.io/v1\nkind: RoleBinding\nmetadata: {name: b}\nroleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: edit}\nsubjects: [{kind: ServiceAccount, name: ci}]\n"
	_, out, _ := runCLI(t, doc, "--namespace", "apps", "-")
	if !strings.Contains(out, "ServiceAccount apps/ci can get, list, watch secrets in namespace apps") {
		t.Errorf("--namespace not applied:\n%s", out)
	}
	_, out, _ = runCLI(t, doc, "--no-builtin-roles", "-")
	if !strings.Contains(out, "references ClusterRole edit, which is not in the inputs") || !strings.Contains(out, "0 finding(s)") {
		t.Errorf("--no-builtin-roles:\n%s", out)
	}
}

func TestIncludeSystem(t *testing.T) {
	doc := "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\nmetadata: {name: masters}\nroleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: cluster-admin}\nsubjects: [{kind: Group, name: system:masters}]\n"
	if code, out, _ := runCLI(t, doc, "-"); code != exitOK || !strings.Contains(out, "1 built-in system subject(s) excluded") {
		t.Errorf("default: exit %d\n%s", code, out)
	}
	if code, out, _ := runCLI(t, doc, "--include-system", "-"); code != exitFindings || !strings.Contains(out, "Group system:masters") {
		t.Errorf("--include-system: exit %d\n%s", code, out)
	}
}

func TestDiff(t *testing.T) {
	code, out, _ := runCLI(t, "", "diff", "--base", safe, "--head", risky)
	if code != exitFindings || !strings.Contains(out, "new finding(s)") || !strings.Contains(out, "New effective cluster-admin") {
		t.Fatalf("exit = %d\n%s", code, out)
	}
	code, out, _ = runCLI(t, "", "diff", "--base", risky, "--head", risky, "--format", "markdown")
	if code != exitOK || !strings.Contains(out, "0 new finding(s)") {
		t.Fatalf("identical base and head: exit %d\n%s", code, out)
	}
	code, out, _ = runCLI(t, "", "diff", "--base", risky, "--head", safe, "--fail-on", "low")
	if code != exitOK || !strings.Contains(out, "0 new finding(s)") {
		t.Fatalf("removing findings is not a failure: exit %d\n%s", code, out)
	}
}

func TestListChecksAndVersion(t *testing.T) {
	code, out, _ := runCLI(t, "", "--list-checks")
	if code != exitOK || !strings.Contains(out, "KRP001  Binding to cluster-admin") || !strings.Contains(out, "#namespace-modification") {
		t.Errorf("--list-checks:\n%s", out)
	}
	code, out, _ = runCLI(t, "", "--version")
	if code != exitOK || strings.TrimSpace(out) != "dev" {
		t.Errorf("--version = %q", out)
	}
	if code, _, errOut := runCLI(t, "", "-h"); code != exitOK || !strings.Contains(errOut, "Usage:") {
		t.Errorf("-h: exit %d\n%s", code, errOut)
	}
}

func TestUsageErrors(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"no paths", nil, "Usage:"},
		{"unknown flag", []string{"--nope", risky}, "flag provided but not defined"},
		{"bad severity", []string{"--fail-on", "critical", risky}, "unknown severity"},
		{"bad format", []string{"--format", "xml", risky}, "unknown format"},
		{"missing path", []string{"does-not-exist"}, "error:"},
		{"diff without head", []string{"diff", "--base", safe}, "needs --base and --head"},
		{"diff with extra paths", []string{"diff", "--base", safe, "--head", risky, "x"}, "needs --base and --head"},
		{"diff bad base", []string{"diff", "--base", "nope", "--head", risky}, "error:"},
		{"diff bad head", []string{"diff", "--base", safe, "--head", "nope"}, "error:"},
		{"diff unknown flag", []string{"diff", "--path", "x"}, "flag provided but not defined"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, _, errOut := runCLI(t, "", tt.args...)
			if code != exitError || !strings.Contains(errOut, tt.want) {
				t.Errorf("exit %d, stderr %q, want 2 and %q", code, errOut, tt.want)
			}
		})
	}
}

func TestDirectoryWarnings(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/bad.yaml", []byte("a: [\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, errOut := runCLI(t, "", dir)
	if code != exitOK || !strings.Contains(errOut, "warning:") || !strings.Contains(errOut, "bad.yaml: skipped") {
		t.Errorf("exit %d, stderr %q", code, errOut)
	}
}
