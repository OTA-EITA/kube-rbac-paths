package check

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/OTA-EITA/kube-rbac-paths/internal/bootstrap"
	"github.com/OTA-EITA/kube-rbac-paths/internal/loader"
	"github.com/OTA-EITA/kube-rbac-paths/internal/rbac"
)

// --- manifest helpers --------------------------------------------------------

func clusterRole(name string, rules ...string) string {
	return fmt.Sprintf("apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\nmetadata:\n  name: %s\nrules:\n%s", name, strings.Join(rules, ""))
}

func role(ns, name string, rules ...string) string {
	return fmt.Sprintf("apiVersion: rbac.authorization.k8s.io/v1\nkind: Role\nmetadata:\n  name: %s\n  namespace: %s\nrules:\n%s", name, ns, strings.Join(rules, ""))
}

// rule renders one rule. groups is written as is (e.g. `""`); resources and
// verbs are comma separated and quoted, so "*" stays a string.
func rule(groups, resources, verbs string, names ...string) string {
	r := fmt.Sprintf("  - apiGroups: [%s]\n    resources: [%s]\n    verbs: [%s]\n", groups, quote(resources), quote(verbs))
	if len(names) > 0 {
		r += fmt.Sprintf("    resourceNames: [%s]\n", strings.Join(names, ","))
	}
	return r
}

func quote(list string) string {
	parts := strings.Split(list, ",")
	for i, p := range parts {
		parts[i] = fmt.Sprintf("%q", p)
	}
	return strings.Join(parts, ",")
}

func crb(name, roleName string, subjects ...string) string {
	return fmt.Sprintf("apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\nmetadata:\n  name: %s\nroleRef:\n  apiGroup: rbac.authorization.k8s.io\n  kind: ClusterRole\n  name: %s\nsubjects:\n%s", name, roleName, strings.Join(subjects, ""))
}

func rb(ns, name, kind, roleName string, subjects ...string) string {
	return fmt.Sprintf("apiVersion: rbac.authorization.k8s.io/v1\nkind: RoleBinding\nmetadata:\n  name: %s\n  namespace: %s\nroleRef:\n  apiGroup: rbac.authorization.k8s.io\n  kind: %s\n  name: %s\nsubjects:\n%s", name, ns, kind, roleName, strings.Join(subjects, ""))
}

func user(name string) string  { return fmt.Sprintf("  - kind: User\n    name: %q\n", name) }
func group(name string) string { return fmt.Sprintf("  - kind: Group\n    name: %q\n", name) }
func sa(ns, name string) string {
	return fmt.Sprintf("  - kind: ServiceAccount\n    name: %s\n    namespace: %s\n", name, ns)
}

func saObject(ns, name string) string {
	return fmt.Sprintf("apiVersion: v1\nkind: ServiceAccount\nmetadata:\n  name: %s\n  namespace: %s\n", name, ns)
}

func deployment(ns, name, saName string) string {
	return fmt.Sprintf("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: %s\n  namespace: %s\nspec:\n  template:\n    spec:\n      serviceAccountName: %s\n", name, ns, saName)
}

func pod(ns, name, saName string) string {
	return fmt.Sprintf("apiVersion: v1\nkind: Pod\nmetadata:\n  name: %s\n  namespace: %s\nspec:\n  serviceAccountName: %s\n", name, ns, saName)
}

func audit(t *testing.T, opts Options, docs ...string) Result {
	t.Helper()
	inv, err := loader.Parse("t.yaml", []byte(strings.Join(docs, "---\n")), loader.Options{})
	if err != nil {
		t.Fatal(err)
	}
	inv.Merge(&rbac.Inventory{Roles: bootstrap.Roles()})
	return Run(rbac.Build(inv), opts)
}

func findings(res Result, id string) []Finding {
	var out []Finding
	for _, f := range res.Findings {
		if f.CheckID == id {
			out = append(out, f)
		}
	}
	return out
}

func dump(res Result) string {
	var b strings.Builder
	for _, f := range res.Findings {
		fmt.Fprintf(&b, "  %s %s %s\n", f.CheckID, f.Severity, f.Message)
	}
	return b.String()
}

// --- risky permission checks ---------------------------------------------------

func TestPermissionChecks(t *testing.T) {
	alice := user("alice")
	tests := []struct {
		name    string
		docs    []string
		id      string
		sev     Severity // None: the check must not fire
		message string
	}{
		{"secrets cluster-wide", []string{clusterRole("r", rule(`""`, "secrets", "list,watch")), crb("b", "r", alice)},
			SecretsRead, High, "User alice can list, watch secrets in every namespace"},
		{"secrets in one namespace", []string{role("team", "r", rule(`""`, "secrets", "get")), rb("team", "b", "Role", "r", alice)},
			SecretsRead, Medium, "can get secrets in namespace team"},
		{"ClusterRole through a RoleBinding stays in the namespace", []string{clusterRole("r", rule(`""`, "secrets", "get")), rb("team", "b", "ClusterRole", "r", alice)},
			SecretsRead, Medium, "in namespace team"},
		{"named secrets", []string{clusterRole("r", rule(`""`, "secrets", "get", "tls", "ca")), crb("b", "r", alice)},
			SecretsRead, Low, "(only tls, ca)"},
		{"configmaps are not secrets", []string{clusterRole("r", rule(`""`, "configmaps", "get,list")), crb("b", "r", alice)},
			SecretsRead, None, ""},
		{"workloads cluster-wide", []string{clusterRole("r", rule(`"apps"`, "deployments", "create")), crb("b", "r", alice)},
			WorkloadCreate, Medium, "can create deployments in every namespace"},
		{"workloads in one namespace", []string{role("team", "r", rule(`""`, "pods", "create")), rb("team", "b", "Role", "r", alice)},
			WorkloadCreate, Low, "in namespace team"},
		{"many workload kinds are shortened", []string{clusterRole("r", rule(`"*"`, "*", "create")), crb("b", "r", alice)},
			WorkloadCreate, Medium, "and 5 more"},
		{"create with resourceNames grants nothing", []string{clusterRole("r", rule(`""`, "pods", "create", "p")), crb("b", "r", alice)},
			WorkloadCreate, None, ""},
		{"workload patch cluster-wide", []string{clusterRole("r", rule(`"apps"`, "deployments", "patch")), crb("b", "r", alice)},
			WorkloadModify, Medium, "User alice can patch deployments in every namespace"},
		{"workload update in one namespace", []string{role("team", "r", rule(`"apps"`, "statefulsets", "get,update")), rb("team", "b", "Role", "r", alice)},
			WorkloadModify, Low, "can update statefulsets in namespace team"},
		{"cronjob update", []string{role("team", "r", rule(`"batch"`, "cronjobs", "update")), rb("team", "b", "Role", "r", alice)},
			WorkloadModify, Low, "can update cronjobs in namespace team"},
		{"named deployments", []string{role("team", "r", rule(`"apps"`, "deployments", "patch", "web")), rb("team", "b", "Role", "r", alice)},
			WorkloadModify, Low, "(only web)"},
		{"pod image patch", []string{role("team", "r", rule(`""`, "pods", "patch")), rb("team", "b", "Role", "r", alice)},
			WorkloadModify, Low, "can patch pods in namespace team"},
		{"ephemeral containers", []string{clusterRole("r", rule(`""`, "pods/ephemeralcontainers", "update")), crb("b", "r", alice)},
			WorkloadModify, Medium, "can update pods/ephemeralcontainers in every namespace"},
		{"job template is immutable", []string{role("team", "r", rule(`"batch"`, "jobs", "update,patch")), rb("team", "b", "Role", "r", alice)},
			WorkloadModify, None, ""},
		{"pod status is not the pod", []string{role("team", "r", rule(`""`, "pods/status", "update,patch")), rb("team", "b", "Role", "r", alice)},
			WorkloadModify, None, ""},
		{"modification adds nothing to creation in the same namespace", []string{role("team", "r", rule(`"apps"`, "deployments", "create,patch")), rb("team", "b", "Role", "r", alice)},
			WorkloadModify, None, ""},
		{"modification adds nothing to creation cluster-wide", []string{clusterRole("c", rule(`""`, "pods", "create")), crb("c", "c", alice), role("team", "r", rule(`"apps"`, "deployments", "patch")), rb("team", "b", "Role", "r", alice)},
			WorkloadModify, None, ""},
		{"creation in another namespace does not cover modification", []string{role("other", "c", rule(`""`, "pods", "create")), rb("other", "c", "Role", "c", alice), role("team", "r", rule(`"apps"`, "deployments", "patch")), rb("team", "b", "Role", "r", alice)},
			WorkloadModify, Low, "in namespace team"},
		{"persistent volumes", []string{clusterRole("r", rule(`""`, "persistentvolumes", "create")), crb("b", "r", alice)},
			PersistentVolume, Medium, "can create persistentvolumes cluster-wide"},
		{"persistent volumes through a RoleBinding", []string{clusterRole("r", rule(`""`, "persistentvolumes", "create")), rb("team", "b", "ClusterRole", "r", alice)},
			PersistentVolume, None, ""},
		{"nodes/proxy", []string{clusterRole("r", rule(`""`, "nodes/proxy", "get")), crb("b", "r", alice)},
			NodesProxy, High, "can get nodes/proxy cluster-wide"},
		{"nodes/metrics is not proxy", []string{clusterRole("r", rule(`""`, "nodes,nodes/metrics", "get")), crb("b", "r", alice)},
			NodesProxy, None, ""},
		{"nodes/proxy through a RoleBinding", []string{clusterRole("r", rule(`""`, "nodes/proxy", "get")), rb("team", "b", "ClusterRole", "r", alice)},
			NodesProxy, None, ""},
		{"escalate cluster-wide", []string{clusterRole("r", rule(`"rbac.authorization.k8s.io"`, "clusterroles", "escalate")), crb("b", "r", alice)},
			EscalateBind, High, "can escalate clusterroles cluster-wide"},
		{"escalate roles in a namespace", []string{role("team", "r", rule(`"rbac.authorization.k8s.io"`, "roles", "escalate")), rb("team", "b", "Role", "r", alice)},
			EscalateBind, Medium, "in namespace team"},
		{"bind on named roles", []string{clusterRole("r", rule(`"rbac.authorization.k8s.io"`, "clusterroles", "bind", "view")), crb("b", "r", alice)},
			EscalateBind, Low, "(only view)"},
		{"bind on clusterroles in a namespace", []string{role("team", "r", rule(`"rbac.authorization.k8s.io"`, "clusterroles", "bind")), rb("team", "b", "Role", "r", alice)},
			EscalateBind, Medium, "can bind clusterroles in namespace team"},
		{"impersonate users", []string{clusterRole("r", rule(`""`, "users", "impersonate")), crb("b", "r", alice)},
			Impersonate, High, "can impersonate users cluster-wide"},
		{"impersonate service accounts in a namespace", []string{role("team", "r", rule(`""`, "serviceaccounts", "impersonate")), rb("team", "b", "Role", "r", alice)},
			Impersonate, Medium, "can impersonate serviceaccounts in namespace team"},
		{"impersonate uids", []string{clusterRole("r", rule(`"authentication.k8s.io"`, "uids", "impersonate")), crb("b", "r", alice)},
			Impersonate, High, "uids"},
		{"csr approval", []string{clusterRole("r", rule(`"certificates.k8s.io"`, "certificatesigningrequests/approval", "update")), crb("b", "r", alice)},
			CSRApproval, Medium, "can update certificatesigningrequests/approval cluster-wide"},
		{"token request cluster-wide", []string{clusterRole("r", rule(`""`, "serviceaccounts/token", "create")), crb("b", "r", alice)},
			TokenRequest, High, "in every namespace"},
		{"token request in a namespace", []string{role("team", "r", rule(`""`, "serviceaccounts/token", "create")), rb("team", "b", "Role", "r", alice)},
			TokenRequest, Medium, "in namespace team"},
		{"token request for named accounts", []string{role("team", "r", rule(`""`, "serviceaccounts/token", "create", "builder")), rb("team", "b", "Role", "r", alice)},
			TokenRequest, Low, "(only builder)"},
		{"webhook create", []string{clusterRole("r", rule(`"admissionregistration.k8s.io"`, "validatingwebhookconfigurations", "create")), crb("b", "r", alice)},
			AdmissionWebhooks, High, "can create validatingwebhookconfigurations cluster-wide"},
		{"webhook update on its own configuration", []string{clusterRole("r", rule(`"admissionregistration.k8s.io"`, "mutatingwebhookconfigurations", "get,update", "mine")), crb("b", "r", alice)},
			AdmissionWebhooks, Low, "(only mine)"},
		{"webhook read only", []string{clusterRole("r", rule(`"admissionregistration.k8s.io"`, "mutatingwebhookconfigurations", "get,list,watch")), crb("b", "r", alice)},
			AdmissionWebhooks, None, ""},
		{"namespace patch cluster-wide", []string{clusterRole("r", rule(`""`, "namespaces", "patch")), crb("b", "r", alice)},
			NamespaceModify, Medium, "can patch namespaces cluster-wide"},
		{"namespace patch through a RoleBinding", []string{role("team", "r", rule(`""`, "namespaces", "patch")), rb("team", "b", "Role", "r", alice)},
			NamespaceModify, Medium, "can patch its own Namespace team"},
		{"named namespaces", []string{clusterRole("r", rule(`""`, "namespaces", "update", "sandbox")), crb("b", "r", alice)},
			NamespaceModify, Low, "(only sandbox)"},
		{"wildcard resources in a namespace", []string{role("team", "r", rule(`"apps"`, "*", "get")), rb("team", "b", "Role", "r", alice)},
			Wildcard, Medium, "holds a wildcard rule verbs=[get] apiGroups=[apps] resources=[*] from Role team/r, in namespace team"},
		{"wildcard verbs cluster-wide", []string{clusterRole("r", rule(`""`, "configmaps", "*")), crb("b", "r", alice)},
			Wildcard, Medium, "cluster-wide"},
		{"built-in roles are not reported as wildcards", []string{rb("team", "b", "ClusterRole", "admin", alice)},
			Wildcard, None, ""},
		{"cluster-admin ClusterRoleBinding", []string{crb("b", "cluster-admin", alice)},
			ClusterAdminBinding, High, "ClusterRoleBinding b grants cluster-admin on the whole cluster to User alice"},
		{"cluster-admin RoleBinding", []string{rb("team", "b", "ClusterRole", "cluster-admin", alice)},
			ClusterAdminBinding, Medium, "on namespace team"},
		{"unauthenticated", []string{clusterRole("r", rule(`""`, "configmaps", "get")), crb("b", "r", group("system:unauthenticated"))},
			BroadGroupBinding, High, "to Group system:unauthenticated"},
		{"anonymous", []string{clusterRole("r", rule(`""`, "configmaps", "get")), crb("b", "r", user("system:anonymous"))},
			BroadGroupBinding, High, "to User system:anonymous"},
		{"authenticated", []string{clusterRole("r", rule(`""`, "configmaps", "get")), crb("b", "r", group("system:authenticated"))},
			BroadGroupBinding, Medium, "system:authenticated"},
		{"all service accounts", []string{clusterRole("r", rule(`""`, "configmaps", "get")), rb("team", "b", "ClusterRole", "r", group("system:serviceaccounts"))},
			BroadGroupBinding, Medium, "system:serviceaccounts"},
		{"ordinary group", []string{clusterRole("r", rule(`""`, "configmaps", "get")), crb("b", "r", group("devs"))},
			BroadGroupBinding, None, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := audit(t, Options{}, tt.docs...)
			got := findings(res, tt.id)
			if tt.sev == None {
				if len(got) != 0 {
					t.Fatalf("%s should not fire:\n%s", tt.id, dump(res))
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("want one %s finding, got:\n%s", tt.id, dump(res))
			}
			f := got[0]
			if f.Severity != tt.sev {
				t.Errorf("severity = %s, want %s", f.Severity, tt.sev)
			}
			if !strings.Contains(f.Message, tt.message) {
				t.Errorf("message %q does not contain %q", f.Message, tt.message)
			}
			if f.Location.File != "t.yaml" || f.Location.Line == 0 || f.Fingerprint == "" {
				t.Errorf("location %v, fingerprint %q", f.Location, f.Fingerprint)
			}
		})
	}
}

func TestEvidenceChain(t *testing.T) {
	res := audit(t, Options{},
		"apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\nmetadata:\n  name: extra\n  labels:\n    rbac.authorization.k8s.io/aggregate-to-view: \"true\"\nrules:\n"+rule(`""`, "secrets", "get"),
		rb("team", "b", "ClusterRole", "view", group("devs")),
	)
	got := findings(res, SecretsRead)
	if len(got) != 1 {
		t.Fatalf("aggregating Secret access into view should be reported:\n%s", dump(res))
	}
	var texts []string
	for _, e := range got[0].Evidence {
		texts = append(texts, e.Text+" @ "+e.Source.String())
	}
	joined := strings.Join(texts, "\n")
	for _, want := range []string{
		"RoleBinding team/b binds ClusterRole view to Group devs @ t.yaml:",
		"ClusterRole view (Kubernetes default role) @ builtin:",
		"aggregated from ClusterRole extra @ t.yaml:1",
		"rule verbs=[get] apiGroups=[\"\"] resources=[secrets] @ t.yaml:8",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("evidence lacks %q:\n%s", want, joined)
		}
	}
}

func TestNamespacedFindingCoveredByClusterWide(t *testing.T) {
	alice := user("alice")
	res := audit(t, Options{},
		clusterRole("wide", rule(`""`, "secrets", "get,list,watch")), crb("w", "wide", alice),
		role("team", "narrow", rule(`""`, "secrets", "get")), rb("team", "n", "Role", "narrow", alice),
		role("other", "more", rule(`""`, "secrets", "get,delete,deletecollection")), rb("other", "m", "Role", "more", alice),
	)
	got := findings(res, SecretsRead)
	if len(got) != 1 || got[0].Severity != High {
		t.Fatalf("namespaced Secret read adds nothing to the cluster-wide one:\n%s", dump(res))
	}
	res = audit(t, Options{},
		clusterRole("wide", rule(`""`, "secrets", "get")), crb("w", "wide", alice),
		role("team", "narrow", rule(`""`, "secrets", "list")), rb("team", "n", "Role", "narrow", alice),
	)
	if got := findings(res, SecretsRead); len(got) != 2 {
		t.Fatalf("list in a namespace is more than get cluster-wide:\n%s", dump(res))
	}
}

// --- effective admin -----------------------------------------------------------

func TestEffectiveAdmin(t *testing.T) {
	rg := `"rbac.authorization.k8s.io"`
	cg := `"certificates.k8s.io"`
	bob := user("bob")
	tests := []struct {
		name   string
		docs   []string
		admin  bool
		reason string
	}{
		{"cluster-admin", []string{crb("b", "cluster-admin", bob)}, true, "every verb on every resource"},
		{"own wildcard role", []string{clusterRole("r", rule(`"*"`, "*", "*")), crb("b", "r", bob)}, true, "every verb"},
		{"wildcard in a namespace only", []string{clusterRole("r", rule(`"*"`, "*", "*")), rb("team", "b", "ClusterRole", "r", bob)}, false, ""},
		{"wildcard with resourceNames", []string{clusterRole("r", rule(`"*"`, "*", "*", "x")), crb("b", "r", bob)}, false, ""},
		{"bind and create clusterrolebindings", []string{clusterRole("r", rule(rg, "clusterroles", "bind"), rule(rg, "clusterrolebindings", "create")), crb("b", "r", bob)}, true, "bind itself to cluster-admin"},
		{"bind limited to cluster-admin", []string{clusterRole("r", rule(rg, "clusterroles", "bind", "cluster-admin"), rule(rg, "clusterrolebindings", "create")), crb("b", "r", bob)}, true, "bind itself"},
		{"bind limited to view", []string{clusterRole("r", rule(rg, "clusterroles", "bind", "view"), rule(rg, "clusterrolebindings", "create")), crb("b", "r", bob)}, false, ""},
		{"bind without clusterrolebindings", []string{clusterRole("r", rule(rg, "clusterroles", "bind")), crb("b", "r", bob)}, false, ""},
		{"rbac wildcard", []string{clusterRole("r", rule(rg, "*", "*")), crb("b", "r", bob)}, true, "bind itself"},
		{"escalate and update its own role", []string{clusterRole("r", rule(rg, "clusterroles", "escalate,update")), crb("b", "r", bob)}, true, "can update ClusterRole r, which is bound to it"},
		{"escalate without update", []string{clusterRole("r", rule(rg, "clusterroles", "escalate")), crb("b", "r", bob)}, false, ""},
		{"escalate on another role only", []string{clusterRole("r", rule(rg, "clusterroles", "escalate,update", "other")), crb("b", "r", bob)}, false, ""},
		{"impersonate groups", []string{clusterRole("r", rule(`""`, "groups", "impersonate")), crb("b", "r", bob)}, true, "impersonate the system:masters group"},
		{"impersonate system:masters by name", []string{clusterRole("r", rule(`""`, "groups", "impersonate", "system:masters")), crb("b", "r", bob)}, true, "system:masters"},
		{"impersonate other groups", []string{clusterRole("r", rule(`""`, "groups", "impersonate", "readers")), crb("b", "r", bob)}, false, ""},
		{"csr issue", []string{clusterRole("r",
			rule(cg, "certificatesigningrequests", "create"),
			rule(cg, "certificatesigningrequests/approval", "update", "mine"),
			rule(cg, "signers", "approve", "kubernetes.io/kube-apiserver-client")), crb("b", "r", bob)}, true, "client certificate for the system:masters group"},
		{"csr issue with signer wildcard", []string{clusterRole("r",
			rule(cg, "certificatesigningrequests", "create"),
			rule(cg, "certificatesigningrequests/approval", "update"),
			rule(cg, "signers", "approve", `"kubernetes.io/*"`)), crb("b", "r", bob)}, true, "client certificate"},
		{"csr approval for another signer", []string{clusterRole("r",
			rule(cg, "certificatesigningrequests", "create"),
			rule(cg, "certificatesigningrequests/approval", "update"),
			rule(cg, "signers", "approve", "example.com/signer")), crb("b", "r", bob)}, false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := audit(t, Options{}, tt.docs...)
			got := findings(res, EffectiveAdmin)
			if !tt.admin {
				if len(got) != 0 || len(res.Admins) != 0 {
					t.Fatalf("not admin-equivalent, got:\n%s", dump(res))
				}
				return
			}
			if len(got) != 1 || len(res.Admins) != 1 {
				t.Fatalf("want one admin, got:\n%s", dump(res))
			}
			if !strings.Contains(got[0].Message, tt.reason) || !strings.Contains(got[0].Message, "effectively holds cluster-admin-equivalent permissions because it") {
				t.Errorf("message %q lacks %q", got[0].Message, tt.reason)
			}
			if res.Admins[0].Via != nil || len(res.Admins[0].Evidence) == 0 {
				t.Errorf("admin = %+v", res.Admins[0])
			}
			// The individual risky permissions are not repeated.
			for _, f := range res.Findings {
				if f.CheckID != EffectiveAdmin && f.CheckID != ClusterAdminBinding {
					t.Errorf("unexpected %s for an admin subject: %s", f.CheckID, f.Message)
				}
			}
		})
	}
}

func TestGroupGrantsReachServiceAccounts(t *testing.T) {
	res := audit(t, Options{}, crb("b", "cluster-admin", group("system:serviceaccounts:ci")), saObject("ci", "runner"), deployment("ci", "runner", "runner"))
	var found *Admin
	for i, a := range res.Admins {
		if a.Subject.Name == "runner" {
			found = &res.Admins[i]
		}
	}
	if found == nil {
		t.Fatalf("ServiceAccount ci/runner inherits cluster-admin from its group: %+v", res.Admins)
	}
	if !strings.Contains(found.Evidence[0].Text, "through its membership of Group system:serviceaccounts:ci") {
		t.Errorf("evidence = %v", found.Evidence[0].Text)
	}
	if len(found.UsedBy) != 1 || !strings.Contains(found.UsedBy[0].Text, "Deployment ci/runner") {
		t.Errorf("used by = %v", found.UsedBy)
	}
}

// --- acting as another ServiceAccount --------------------------------------------

func TestServiceAccountPivot(t *testing.T) {
	alice := user("alice")
	privileged := []string{saObject("team", "deployer"), crb("deployer", "cluster-admin", sa("team", "deployer"))}
	secretReader := []string{clusterRole("secrets", rule(`""`, "secrets", "list")), crb("reader", "secrets", sa("team", "reader"))}
	podCreator := role("team", "pods", rule(`""`, "pods", "create"))
	tests := []struct {
		name    string
		docs    []string
		id      string // KRP005, KRP014 (target is admin), or "" for nothing
		message string
	}{
		{"pods in the namespace of an admin ServiceAccount",
			append([]string{podCreator, rb("team", "a", "Role", "pods", alice)}, privileged...),
			EffectiveAdmin, "User alice effectively holds cluster-admin-equivalent permissions because it can create pods in namespace team, where ServiceAccount team/deployer lives, and ServiceAccount team/deployer holds every verb"},
		{"pods in every namespace",
			append([]string{clusterRole("pods", rule(`""`, "pods", "create")), crb("a", "pods", alice)}, privileged...),
			EffectiveAdmin, "in every namespace, including team"},
		{"pods in another namespace",
			append([]string{role("other", "pods", rule(`""`, "pods", "create")), rb("other", "a", "Role", "pods", alice)}, privileged...),
			"", ""},
		{"token for the admin ServiceAccount",
			append([]string{role("team", "t", rule(`""`, "serviceaccounts/token", "create", "deployer")), rb("team", "a", "Role", "t", alice)}, privileged...),
			EffectiveAdmin, "can create tokens for ServiceAccount team/deployer"},
		{"token for another ServiceAccount only",
			append([]string{role("team", "t", rule(`""`, "serviceaccounts/token", "create", "builder")), rb("team", "a", "Role", "t", alice)}, privileged...),
			"", ""},
		{"impersonating the admin ServiceAccount",
			append([]string{role("team", "i", rule(`""`, "serviceaccounts", "impersonate")), rb("team", "a", "Role", "i", alice)}, privileged...),
			EffectiveAdmin, "can impersonate ServiceAccount team/deployer"},
		{"target with notable permissions",
			append([]string{podCreator, rb("team", "a", "Role", "pods", alice)}, secretReader...),
			ServiceAccountPivot, "User alice can create pods in namespace team, where ServiceAccount team/reader lives; ServiceAccount team/reader holds: read access to Secrets (high)"},
		{"several routes are one finding",
			append([]string{role("team", "x", rule(`""`, "pods,serviceaccounts/token", "create"), rule(`""`, "serviceaccounts", "impersonate")), rb("team", "a", "Role", "x", alice)}, secretReader...),
			ServiceAccountPivot, ". It can also create tokens for ServiceAccount team/reader and impersonate ServiceAccount team/reader"},
		{"target found through a workload",
			[]string{podCreator, rb("team", "a", "Role", "pods", alice), clusterRole("secrets", rule(`""`, "secrets", "list")), crb("reader", "secrets", sa("team", "reader")), deployment("team", "web", "reader")},
			ServiceAccountPivot, "ServiceAccount team/reader holds"},
		{"nothing to gain",
			append([]string{podCreator, rb("team", "a", "Role", "pods", alice), clusterRole("mine", rule(`""`, "secrets", "get,list")), crb("mine", "mine", alice)}, secretReader...),
			"", ""},
		{"target without notable permissions",
			[]string{podCreator, rb("team", "a", "Role", "pods", alice), saObject("team", "plain"), role("team", "cm", rule(`""`, "configmaps", "get")), rb("team", "p", "Role", "cm", sa("team", "plain"))},
			"", ""},
		{"patching deployments in the namespace of an admin ServiceAccount",
			append([]string{role("team", "d", rule(`"apps"`, "deployments", "get,patch")), rb("team", "a", "Role", "d", alice)}, privileged...),
			EffectiveAdmin, "because it can patch deployments in namespace team, where ServiceAccount team/deployer lives, so it can set serviceAccountName in their Pod template to that ServiceAccount, and ServiceAccount team/deployer holds every verb"},
		{"patching one named deployment still reaches every ServiceAccount",
			append([]string{role("team", "d", rule(`"apps"`, "deployments", "update", "web")), rb("team", "a", "Role", "d", alice)}, privileged...),
			EffectiveAdmin, "can update deployments (only web) in namespace team, where ServiceAccount team/deployer lives"},
		{"updating cronjobs everywhere",
			append([]string{clusterRole("cj", rule(`"batch"`, "cronjobs", "update")), crb("a", "cj", alice)}, privileged...),
			EffectiveAdmin, "can update cronjobs in every namespace, including team, where ServiceAccount team/deployer lives"},
		{"updating jobs does not change their Pods",
			append([]string{role("team", "j", rule(`"batch"`, "jobs", "update,patch")), rb("team", "a", "Role", "j", alice)}, privileged...),
			"", ""},
		{"patching pods reaches the ServiceAccount of a running workload",
			append([]string{role("team", "p", rule(`""`, "pods", "patch")), rb("team", "a", "Role", "p", alice), deployment("team", "web", "deployer")}, privileged...),
			EffectiveAdmin, "can patch pods in namespace team, where Deployment team/web runs as ServiceAccount team/deployer, so it can replace a container image in those Pods, and ServiceAccount team/deployer holds"},
		{"ephemeral containers reach the ServiceAccount of a running workload",
			append([]string{role("team", "p", rule(`""`, "pods/ephemeralcontainers", "update")), rb("team", "a", "Role", "p", alice), pod("team", "web", "deployer")}, privileged...),
			EffectiveAdmin, "so it can add an ephemeral container to those Pods"},
		{"patching pods and ephemeral containers",
			append([]string{role("team", "p", rule(`""`, "pods,pods/ephemeralcontainers", "patch")), rb("team", "a", "Role", "p", alice), pod("team", "web", "deployer")}, privileged...),
			EffectiveAdmin, "so it can replace a container image or add an ephemeral container in those Pods"},
		{"patching pods when nothing runs as the ServiceAccount",
			append([]string{role("team", "p", rule(`""`, "pods", "patch")), rb("team", "a", "Role", "p", alice)}, privileged...),
			"", ""},
		{"patching a named Pod reaches its ServiceAccount",
			append([]string{role("team", "p", rule(`""`, "pods", "patch", "web")), rb("team", "a", "Role", "p", alice), pod("team", "web", "deployer")}, privileged...),
			EffectiveAdmin, "can patch pods (only web) in namespace team, where Pod team/web runs as ServiceAccount team/deployer"},
		{"patching another named Pod",
			append([]string{role("team", "p", rule(`""`, "pods", "patch", "other")), rb("team", "a", "Role", "p", alice), pod("team", "web", "deployer"), deployment("team", "other", "deployer")}, privileged...),
			"", ""},
		{"the admin path lists the other routes",
			append([]string{role("team", "x", rule(`""`, "pods", "create"), rule(`"apps"`, "daemonsets", "patch")), rb("team", "a", "Role", "x", alice)}, privileged...),
			EffectiveAdmin, ". It can also patch daemonsets in namespace team, to set serviceAccountName in their Pod template to that ServiceAccount"},
		{"other routes are separated when one changes a workload",
			append([]string{role("team", "x", rule(`""`, "pods,serviceaccounts/token", "create"), rule(`""`, "pods", "patch")), rb("team", "a", "Role", "x", alice), deployment("team", "web", "deployer")}, privileged...),
			EffectiveAdmin, ". It can also patch pods of Deployment team/web to replace a container image; create tokens for ServiceAccount team/deployer"},
		{"workload modification to a ServiceAccount with notable permissions",
			append([]string{role("team", "d", rule(`"apps"`, "replicasets", "update")), rb("team", "a", "Role", "d", alice), saObject("team", "reader")}, secretReader...),
			ServiceAccountPivot, "User alice can update replicasets in namespace team, where ServiceAccount team/reader lives, so it can set serviceAccountName in their Pod template to that ServiceAccount; ServiceAccount team/reader holds: read access to Secrets (high)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := audit(t, Options{}, tt.docs...)
			var mine []Finding
			for _, f := range res.Findings {
				if f.Subject != nil && f.Subject.Name == "alice" && (f.CheckID == ServiceAccountPivot || f.CheckID == EffectiveAdmin) {
					mine = append(mine, f)
				}
			}
			if tt.id == "" {
				if len(mine) != 0 {
					t.Fatalf("nothing expected for alice:\n%s", dump(res))
				}
				return
			}
			if len(mine) != 1 || mine[0].CheckID != tt.id || !strings.Contains(mine[0].Message, tt.message) || mine[0].Severity != High {
				t.Fatalf("want one %s containing %q, got:\n%s", tt.id, tt.message, dump(res))
			}
			var viaAdmin *Admin
			for i, a := range res.Admins {
				if a.Subject.Name == "alice" {
					viaAdmin = &res.Admins[i]
				}
			}
			if (tt.id == EffectiveAdmin) != (viaAdmin != nil) {
				t.Fatalf("alice in the admin summary = %v", viaAdmin != nil)
			}
			if viaAdmin != nil {
				if viaAdmin.Via == nil || viaAdmin.Via.Name != "deployer" {
					t.Errorf("via = %v", viaAdmin.Via)
				}
				// alice's own permissions are still listed, but not a KRP005
				// that repeats the KRP014.
				if len(findings(res, ServiceAccountPivot)) != 0 {
					t.Errorf("KRP005 repeats KRP014:\n%s", dump(res))
				}
			}
		})
	}
}

// podsIn lets a ServiceAccount (or alice) create Pods in a namespace.
func podsIn(ns, who, subject string) []string {
	return []string{role(ns, "pods", rule(`""`, "pods", "create")), rb(ns, "pods-"+who, "Role", "pods", subject)}
}

func chain(docs ...[]string) []string {
	var out []string
	for _, d := range docs {
		out = append(out, d...)
	}
	return out
}

func TestMultiHop(t *testing.T) {
	alice := user("alice")
	admin := func(ns, name string) []string {
		return []string{saObject(ns, name), crb("admin-"+ns, "cluster-admin", sa(ns, name))}
	}
	secrets := func(ns, name string) []string {
		return []string{saObject(ns, name), clusterRole("secrets-"+ns, rule(`""`, "secrets", "list")), crb("secrets-"+ns, "secrets-"+ns, sa(ns, name))}
	}
	tests := []struct {
		name    string
		docs    []string
		id      string   // EffectiveAdmin, ServiceAccountPivot or "" for nothing
		message []string // all must appear in alice's finding
		via     []string // the ServiceAccounts of the admin chain
		count   int      // number of alice's KRP005/KRP014 findings (default 1)
	}{
		{"two hops to cluster-admin",
			chain(podsIn("a", "alice", alice), []string{saObject("a", "builder"), role("b", "t", rule(`""`, "serviceaccounts/token", "create")), rb("b", "t", "Role", "t", sa("a", "builder"))}, admin("b", "root")),
			EffectiveAdmin, []string{"User alice effectively holds cluster-admin-equivalent permissions because it can create pods in namespace a, where ServiceAccount a/builder lives; ServiceAccount a/builder can create tokens for ServiceAccount b/root, and ServiceAccount b/root holds every verb on every resource"},
			[]string{"a/builder", "b/root"}, 0},
		{"four hops is the limit",
			chain(podsIn("n1", "alice", alice), []string{saObject("n1", "s1")}, podsIn("n2", "n1-s1", sa("n1", "s1")), []string{saObject("n2", "s2")}, podsIn("n3", "n2-s2", sa("n2", "s2")), []string{saObject("n3", "s3")}, podsIn("n4", "n3-s3", sa("n3", "s3")), admin("n4", "root")),
			EffectiveAdmin, []string{"ServiceAccount n1/s1 can create pods in namespace n2, where ServiceAccount n2/s2 lives; ServiceAccount n2/s2 can create pods in namespace n3", "ServiceAccount n3/s3 can create pods in namespace n4, where ServiceAccount n4/root lives, and ServiceAccount n4/root holds"},
			[]string{"n1/s1", "n2/s2", "n3/s3", "n4/root"}, 0},
		{"five hops are not followed",
			chain(podsIn("n1", "alice", alice), []string{saObject("n1", "s1")}, podsIn("n2", "n1-s1", sa("n1", "s1")), []string{saObject("n2", "s2")}, podsIn("n3", "n2-s2", sa("n2", "s2")), []string{saObject("n3", "s3")}, podsIn("n4", "n3-s3", sa("n3", "s3")), []string{saObject("n4", "s4")}, podsIn("n5", "n4-s4", sa("n4", "s4")), admin("n5", "root")),
			"", nil, nil, 0},
		{"a cycle ends",
			chain(podsIn("a", "alice", alice), []string{saObject("a", "x"), saObject("b", "y")}, podsIn("b", "a-x", sa("a", "x")), podsIn("a", "b-y", sa("b", "y"))),
			"", nil, nil, 0},
		{"the shortest chain is reported",
			chain(podsIn("long", "alice", alice), []string{saObject("long", "l")}, podsIn("mid", "long-l", sa("long", "l")), []string{saObject("mid", "m")}, podsIn("top", "mid-m", sa("mid", "m")),
				podsIn("short", "alice", alice), []string{saObject("short", "s")}, podsIn("top", "short-s", sa("short", "s")), admin("top", "root")),
			EffectiveAdmin, []string{"ServiceAccount short/s can create pods in namespace top"}, []string{"short/s", "top/root"}, 0},
		{"two hops to a Secret reader",
			chain(podsIn("a", "alice", alice), []string{saObject("a", "x")}, podsIn("b", "a-x", sa("a", "x")), secrets("b", "reader")),
			ServiceAccountPivot, []string{"User alice can create pods in namespace a, where ServiceAccount a/x lives; ServiceAccount a/x can create pods in namespace b, where ServiceAccount b/reader lives; ServiceAccount b/reader holds: read access to Secrets (high)"}, nil, 0},
		{"a longer chain to nothing new is not reported",
			chain(podsIn("a", "alice", alice), secrets("a", "r1"), podsIn("b", "a-r1", sa("a", "r1")), secrets("b", "r2")),
			ServiceAccountPivot, []string{"ServiceAccount a/r1 holds: read access to Secrets (high)"}, nil, 0},
		{"a longer chain to something new is reported",
			chain(podsIn("a", "alice", alice), secrets("a", "r1"), podsIn("b", "a-r1", sa("a", "r1")), []string{saObject("b", "proxy"), clusterRole("proxy", rule(`""`, "nodes/proxy", "get")), crb("proxy", "proxy", sa("b", "proxy"))}),
			ServiceAccountPivot, []string{"ServiceAccount a/r1 can create pods in namespace b, where ServiceAccount b/proxy lives; ServiceAccount b/proxy holds: nodes/proxy access (high)"}, nil, 2},
		{"workload modification as a middle step",
			chain(podsIn("a", "alice", alice), []string{saObject("a", "ci"), role("b", "d", rule(`"apps"`, "deployments", "patch")), rb("b", "d", "Role", "d", sa("a", "ci"))}, admin("b", "root")),
			EffectiveAdmin, []string{"ServiceAccount a/ci can patch deployments in namespace b, where ServiceAccount b/root lives, so it can set serviceAccountName in their Pod template to that ServiceAccount, and ServiceAccount b/root holds"},
			[]string{"a/ci", "b/root"}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := audit(t, Options{}, tt.docs...)
			var mine []Finding
			for _, f := range res.Findings {
				if f.Subject != nil && f.Subject.Name == "alice" && (f.CheckID == ServiceAccountPivot || f.CheckID == EffectiveAdmin) {
					mine = append(mine, f)
				}
			}
			want := tt.count
			if want == 0 && tt.id != "" {
				want = 1
			}
			if len(mine) != want {
				t.Fatalf("want %d finding(s) for alice, got:\n%s", want, dump(res))
			}
			if tt.id == "" {
				return
			}
			if mine[0].CheckID != tt.id {
				t.Fatalf("want %s, got:\n%s", tt.id, dump(res))
			}
			for _, m := range tt.message {
				if !strings.Contains(mine[0].Message, m) {
					t.Errorf("message lacks %q:\n%s", m, mine[0].Message)
				}
			}
			var adm *Admin
			for i, a := range res.Admins {
				if a.Subject.Name == "alice" {
					adm = &res.Admins[i]
				}
			}
			if (tt.id == EffectiveAdmin) != (adm != nil) {
				t.Fatalf("alice in the admin summary = %v", adm != nil)
			}
			if adm == nil {
				return
			}
			var got []string
			for _, s := range adm.Chain {
				got = append(got, s.Namespace+"/"+s.Name)
			}
			if strings.Join(got, " ") != strings.Join(tt.via, " ") || adm.Via == nil || adm.Via.Key() != adm.Chain[len(adm.Chain)-1].Key() {
				t.Errorf("chain = %v, via = %v, want %v", got, adm.Via, tt.via)
			}
			// Every hop's binding is part of the evidence.
			for _, s := range adm.Chain[:len(adm.Chain)-1] {
				found := false
				for _, e := range adm.Evidence {
					if strings.Contains(e.Text, "to ServiceAccount "+s.Namespace+"/"+s.Name) {
						found = true
					}
				}
				if !found {
					t.Errorf("evidence lacks the binding of %s:\n%v", s, adm.Evidence)
				}
			}
		})
	}
}

// --- system subjects -------------------------------------------------------------

func TestSystemExclusion(t *testing.T) {
	bootstrapBinding := "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\nmetadata:\n  name: system:basic-user\n  labels:\n    kubernetes.io/bootstrapping: rbac-defaults\nroleRef:\n  apiGroup: rbac.authorization.k8s.io\n  kind: ClusterRole\n  name: system:basic-user\nsubjects:\n" + group("system:authenticated")
	docs := []string{
		crb("masters", "cluster-admin", group("system:masters")),
		clusterRole("cm", rule(`""`, "secrets", "list")), crb("cm", "cm", user("system:kube-controller-manager"), sa("kube-system", "namespace-controller")),
		bootstrapBinding,
	}
	res := audit(t, Options{}, docs...)
	if len(res.Findings) != 0 || len(res.Admins) != 0 {
		t.Fatalf("system subjects should be excluded by default:\n%s", dump(res))
	}
	if res.Excluded != 3 {
		t.Errorf("excluded = %d, want 3", res.Excluded)
	}
	res = audit(t, Options{IncludeSystem: true}, docs...)
	for _, id := range []string{ClusterAdminBinding, EffectiveAdmin, SecretsRead, BroadGroupBinding} {
		if len(findings(res, id)) == 0 {
			t.Errorf("--include-system should report %s:\n%s", id, dump(res))
		}
	}
	if res.Excluded != 0 {
		t.Errorf("excluded = %d with --include-system", res.Excluded)
	}
}

func TestSystemServiceAccountIsStillAPivotTarget(t *testing.T) {
	res := audit(t, Options{},
		role("kube-system", "pods", rule(`""`, "pods", "create")), rb("kube-system", "a", "Role", "pods", user("alice")),
		crb("agg", "cluster-admin", sa("kube-system", "clusterrole-aggregation-controller")),
	)
	if len(res.Admins) != 1 || res.Admins[0].Via == nil || res.Admins[0].Via.Name != "clusterrole-aggregation-controller" {
		t.Fatalf("a Pod in kube-system can run as a controller ServiceAccount:\n%s", dump(res))
	}
}

// --- result helpers ---------------------------------------------------------------

func TestUnresolvedAndDuplicates(t *testing.T) {
	res := audit(t, Options{}, rb("team", "b", "Role", "missing", user("alice")), clusterRole("x"), clusterRole("x"))
	if len(res.Unresolved) != 1 || !strings.Contains(res.Unresolved[0], "references Role missing") {
		t.Errorf("unresolved = %v", res.Unresolved)
	}
	if res.Duplicates != 1 {
		t.Errorf("duplicates = %d", res.Duplicates)
	}
}

func TestDiff(t *testing.T) {
	base := audit(t, Options{}, clusterRole("r", rule(`""`, "secrets", "list")), crb("b", "r", user("alice")))
	head := audit(t, Options{}, clusterRole("r", rule(`""`, "secrets", "list")), crb("b", "r", user("alice")),
		"# moved down a line\n"+crb("admin", "cluster-admin", user("bob")))
	d := Diff(base, head)
	for _, f := range d.Findings {
		if f.CheckID == SecretsRead {
			t.Errorf("unchanged finding reported as new: %s", f.Message)
		}
	}
	if len(findings(d, ClusterAdminBinding)) != 1 || len(findings(d, EffectiveAdmin)) != 1 || len(d.Admins) != 1 {
		t.Errorf("new findings missing:\n%s", dump(d))
	}
	if same := Diff(head, head); len(same.Findings) != 0 || len(same.Admins) != 0 {
		t.Errorf("diff of identical inputs:\n%s", dump(same))
	}
}

func TestSeverity(t *testing.T) {
	for _, v := range []string{"high", "MEDIUM", "low", "none"} {
		s, err := ParseSeverity(v)
		if err != nil || s.String() != strings.ToLower(v) {
			t.Errorf("ParseSeverity(%q) = %v, %v", v, s, err)
		}
	}
	if _, err := ParseSeverity("critical"); err == nil {
		t.Error("unknown severity accepted")
	}
	b, _ := json.Marshal(struct{ S Severity }{High})
	if string(b) != `{"S":"high"}` {
		t.Errorf("json = %s", b)
	}
	res := Result{Findings: []Finding{{Severity: High}, {Severity: Low}}}
	if res.Count(Medium) != 1 || res.Count(Low) != 2 || res.Count(None) != 0 {
		t.Error("Count")
	}
}

func TestCheckCatalogue(t *testing.T) {
	seen := map[string]bool{}
	for i, c := range Checks {
		if want := fmt.Sprintf("KRP%03d", i+1); c.ID != want {
			t.Errorf("check %d has ID %s, want %s", i, c.ID, want)
		}
		if seen[c.ID] || c.Title == "" || c.Why == "" || c.Fix == "" || c.Section == "" || c.Severities == "" {
			t.Errorf("incomplete check %+v", c)
		}
		seen[c.ID] = true
		if !strings.HasPrefix(c.URL(), DocsURL+"#") || c.Anchor == "" {
			t.Errorf("%s url %s", c.ID, c.URL())
		}
		if got, ok := Lookup(c.ID); !ok || got.ID != c.ID {
			t.Errorf("Lookup(%s)", c.ID)
		}
	}
	if _, ok := Lookup("KRP999"); ok {
		t.Error("Lookup of an unknown ID")
	}
	if (Finding{CheckID: SecretsRead}).Check().Title != "Read access to Secrets" {
		t.Error("Finding.Check")
	}
}

func TestRuleText(t *testing.T) {
	r := &rbac.Rule{}
	r.NonResourceURLs = []string{"/metrics"}
	r.Verbs = []string{"get"}
	if got := ruleText(r); got != "verbs=[get] nonResourceURLs=[/metrics]" {
		t.Error(got)
	}
	if firstBindingSource(nil) != (rbac.Source{}) {
		t.Error("firstBindingSource(nil)")
	}
}

func TestPivotSeverityFollowsTarget(t *testing.T) {
	res := audit(t, Options{},
		role("team", "pods", rule(`""`, "pods", "create")), rb("team", "a", "Role", "pods", user("alice")),
		role("team", "secrets", rule(`""`, "secrets", "get")), rb("team", "r", "Role", "secrets", sa("team", "reader")),
	)
	got := findings(res, ServiceAccountPivot)
	if len(got) != 1 || got[0].Severity != Medium || !strings.Contains(got[0].Message, "read access to Secrets (medium)") {
		t.Fatalf("pivot to a namespaced Secret reader:\n%s", dump(res))
	}
}
