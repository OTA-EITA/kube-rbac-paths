package loader

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/OTA-EITA/kube-rbac-paths/internal/rbac"
)

const multi = `# leading comment
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: reader
  labels:
    team: a
aggregationRule:
  clusterRoleSelectors:
    - matchLabels:
        x: "true"
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get"]
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: local
aggregationRule:
  clusterRoleSelectors: [{matchLabels: {x: "true"}}]
rules: []
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: rb
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: local}
subjects:
  - kind: ServiceAccount
    name: app
  - kind: User
    name: system:serviceaccount:other:bot
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: crb
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: reader}
subjects:
  - kind: ServiceAccount
    name: no-namespace
---
---
just a string
---
apiVersion: v1
kind: ConfigMap
metadata: {name: ignored}
`

func TestParseMultiDocument(t *testing.T) {
	inv, err := Parse("m.yaml", []byte(multi), Options{DefaultNamespace: "team"})
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Roles) != 2 || len(inv.Bindings) != 2 {
		t.Fatalf("roles=%d bindings=%d", len(inv.Roles), len(inv.Bindings))
	}
	cr := inv.Roles[0]
	if cr.Kind != "ClusterRole" || cr.Namespace != "" || cr.Labels["team"] != "a" || cr.Aggregation == nil {
		t.Errorf("cluster role: %+v", cr)
	}
	if cr.Source != (rbac.Source{File: "m.yaml", Line: 2}) {
		t.Errorf("cluster role source = %v", cr.Source)
	}
	if len(cr.Rules) != 2 || cr.Rules[0].Source.Line != 13 || cr.Rules[1].Source.Line != 16 || cr.Rules[1].Origin != cr {
		t.Errorf("rule lines: %v %v", cr.Rules[0].Source, cr.Rules[1].Source)
	}
	role := inv.Roles[1]
	if role.Namespace != "team" || role.Aggregation != nil {
		t.Errorf("Role: namespace %q, aggregation %v (Roles cannot aggregate)", role.Namespace, role.Aggregation)
	}
	rb := inv.Bindings[0]
	if rb.Namespace != "team" || rb.Source.Line != 28 {
		t.Errorf("RoleBinding: %+v", rb)
	}
	want := []rbac.Subject{
		{Kind: rbac.KindServiceAccount, Namespace: "team", Name: "app"},
		{Kind: rbac.KindServiceAccount, Namespace: "other", Name: "bot"},
	}
	for i, w := range want {
		if rb.Subjects[i] != w {
			t.Errorf("subject %d = %v, want %v", i, rb.Subjects[i], w)
		}
	}
	crb := inv.Bindings[1]
	if crb.Namespace != "" || crb.Subjects[0].Namespace != "team" {
		t.Errorf("ClusterRoleBinding: %+v", crb)
	}
}

func TestParseList(t *testing.T) {
	data := `apiVersion: v1
kind: List
items:
  - apiVersion: rbac.authorization.k8s.io/v1
    kind: ClusterRole
    metadata: {name: a}
  - apiVersion: v1
    kind: ServiceAccount
    metadata: {name: sa, namespace: x}
  - apiVersion: rbac.authorization.k8s.io/v1
    kind: ClusterRoleList
    items:
      - apiVersion: rbac.authorization.k8s.io/v1
        kind: ClusterRole
        metadata: {name: b}
`
	inv, err := Parse("l.yaml", []byte(data), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Roles) != 2 || inv.Roles[0].Source.Line != 4 || inv.Roles[1].Source.Line != 13 {
		t.Fatalf("roles: %+v", inv.Roles)
	}
	if len(inv.ServiceAccounts) != 1 || inv.ServiceAccounts[0].Namespace != "x" || inv.ServiceAccounts[0].Source.Line != 7 {
		t.Errorf("service accounts: %+v", inv.ServiceAccounts)
	}
}

func TestWorkloads(t *testing.T) {
	tests := []struct {
		name, doc, kind, sa string
	}{
		{"pod", "apiVersion: v1\nkind: Pod\nmetadata: {name: p}\nspec: {serviceAccountName: a}\n", "Pod", "a"},
		{"pod deprecated field", "apiVersion: v1\nkind: Pod\nmetadata: {name: p}\nspec: {serviceAccount: old}\n", "Pod", "old"},
		{"pod default", "apiVersion: v1\nkind: Pod\nmetadata: {name: p}\nspec: {}\n", "Pod", "default"},
		{"no spec", "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: d}\n", "Deployment", "default"},
		{"rc", "apiVersion: v1\nkind: ReplicationController\nmetadata: {name: r}\nspec: {template: {spec: {serviceAccountName: b}}}\n", "ReplicationController", "b"},
		{"deployment", "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: d}\nspec: {template: {spec: {serviceAccountName: c}}}\n", "Deployment", "c"},
		{"daemonset", "apiVersion: apps/v1\nkind: DaemonSet\nmetadata: {name: d}\nspec: {template: {spec: {serviceAccountName: c}}}\n", "DaemonSet", "c"},
		{"statefulset", "apiVersion: apps/v1\nkind: StatefulSet\nmetadata: {name: d}\nspec: {template: {spec: {serviceAccountName: c}}}\n", "StatefulSet", "c"},
		{"replicaset", "apiVersion: apps/v1\nkind: ReplicaSet\nmetadata: {name: d}\nspec: {template: {spec: {serviceAccountName: c}}}\n", "ReplicaSet", "c"},
		{"job", "apiVersion: batch/v1\nkind: Job\nmetadata: {name: j}\nspec: {template: {spec: {serviceAccountName: d}}}\n", "Job", "d"},
		{"cronjob", "apiVersion: batch/v1\nkind: CronJob\nmetadata: {name: c}\nspec: {jobTemplate: {spec: {template: {spec: {serviceAccountName: e}}}}}\n", "CronJob", "e"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inv, err := Parse("w.yaml", []byte(tt.doc), Options{DefaultNamespace: "ns"})
			if err != nil {
				t.Fatal(err)
			}
			if len(inv.Workloads) != 1 {
				t.Fatalf("workloads = %d", len(inv.Workloads))
			}
			w := inv.Workloads[0]
			if w.Kind != tt.kind || w.ServiceAccount != tt.sa || w.Namespace != "ns" || w.Source.Line != 1 {
				t.Errorf("workload = %+v", w)
			}
		})
	}
	// A Deployment in the wrong API group is not a workload.
	inv, err := Parse("w.yaml", []byte("apiVersion: example.com/v1\nkind: Deployment\nmetadata: {name: d}\n"), Options{})
	if err != nil || len(inv.Workloads) != 0 {
		t.Errorf("custom Deployment kind: %v %v", inv, err)
	}
}

func TestParseErrors(t *testing.T) {
	tests := []struct{ name, doc, want string }{
		{"syntax", "a: [\n", "bad.yaml"},
		{"bad role", "apiVersion: rbac.authorization.k8s.io/v1\nkind: Role\nmetadata: {name: [x]}\n", "bad.yaml:1"},
		{"bad binding", "apiVersion: rbac.authorization.k8s.io/v1\nkind: RoleBinding\nsubjects: {a: b}\n", "bad.yaml:1"},
		{"bad sa", "apiVersion: v1\nkind: ServiceAccount\nmetadata: [x]\n", "bad.yaml:1"},
		{"bad workload", "apiVersion: v1\nkind: Pod\nmetadata: [x]\n", "bad.yaml:1"},
		{"bad list item", "apiVersion: v1\nkind: List\nitems:\n  - apiVersion: v1\n    kind: Pod\n    metadata: [x]\n", "bad.yaml:4"},
		{"non-string keys", "apiVersion: v1\nkind: Pod\nmetadata:\n  ? [a, b]\n  : c\n", "bad.yaml:1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse("bad.yaml", []byte(tt.doc), Options{})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want it to mention %s", err, tt.want)
			}
		})
	}
}

func write(t *testing.T, dir, name, data string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const sa = "apiVersion: v1\nkind: ServiceAccount\nmetadata: {name: %s}\n"

func TestLoadPaths(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "a.yaml", strings.Replace(sa, "%s", "a", 1))
	write(t, dir, "sub/b.yml", strings.Replace(sa, "%s", "b", 1))
	write(t, dir, "sub/c.json", `{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"c"}}`)
	write(t, dir, ".hidden/d.yaml", strings.Replace(sa, "%s", "d", 1))
	write(t, dir, "notes.txt", "not yaml")
	bad := write(t, dir, "templates/bad.yaml", "metadata:\n  name: {{ .Values.name }\n")
	single := write(t, t.TempDir(), "single.yaml", strings.Replace(sa, "%s", "e", 1))

	inv, warnings, err := LoadPaths([]string{dir, single, "-"}, Options{Stdin: strings.NewReader(strings.Replace(sa, "%s", "f", 1))})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, s := range inv.ServiceAccounts {
		names = append(names, s.Name+"@"+filepath.Base(s.Source.File))
	}
	if got := strings.Join(names, ","); got != "a@a.yaml,b@b.yml,c@c.json,e@single.yaml,f@stdin" {
		t.Errorf("loaded %s", got)
	}
	if len(warnings) != 1 || warnings[0].File != bad || !strings.Contains(warnings[0].String(), "skipped") {
		t.Errorf("warnings = %v", warnings)
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("boom") }

func TestLoadPathsErrors(t *testing.T) {
	dir := t.TempDir()
	bad := write(t, dir, "bad.yaml", "a: [\n")
	tests := []struct {
		name  string
		paths []string
		opts  Options
	}{
		{"missing", []string{filepath.Join(dir, "nope.yaml")}, Options{}},
		{"explicit bad file", []string{bad}, Options{}},
		{"no stdin", []string{"-"}, Options{}},
		{"stdin read error", []string{"-"}, Options{Stdin: failingReader{}}},
		{"stdin parse error", []string{"-"}, Options{Stdin: strings.NewReader("a: [\n")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, err := LoadPaths(tt.paths, tt.opts); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestWalkError(t *testing.T) {
	dir := t.TempDir()
	locked := filepath.Join(dir, "locked")
	if err := os.Mkdir(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o700) }) // #nosec G302 -- test cleanup
	if os.Geteuid() == 0 {
		t.Skip("root can read any directory")
	}
	if _, _, err := LoadPaths([]string{dir}, Options{}); err == nil {
		t.Fatal("expected an error for an unreadable directory")
	}
}
