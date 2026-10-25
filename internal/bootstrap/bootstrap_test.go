package bootstrap

import (
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"

	"github.com/OTA-EITA/kube-rbac-paths/internal/rbac"
)

func TestRoles(t *testing.T) {
	roles := Roles()
	byName := map[string]*rbac.Role{}
	for _, r := range roles {
		if !r.Source.Builtin() {
			t.Errorf("%s: source %q is not marked built-in", r.Ref(), r.Source)
		}
		byName[r.Kind+"/"+r.Namespace+"/"+r.Name] = r
	}
	for _, want := range []string{"ClusterRole//cluster-admin", "ClusterRole//admin", "ClusterRole//edit", "ClusterRole//view", "Role/kube-system/extension-apiserver-authentication-reader"} {
		if byName[want] == nil {
			t.Errorf("missing built-in %s", want)
		}
	}
	// Copies are independent: changing one does not change the next call.
	byName["ClusterRole//cluster-admin"].Rules = nil
	for _, r := range Roles() {
		if r.Name == "cluster-admin" && len(r.Rules) == 0 {
			t.Fatal("Roles returned a shared object")
		}
		for _, rule := range r.Rules {
			if rule.Origin != r {
				t.Fatalf("%s: rule origin points at another copy", r.Ref())
			}
		}
	}
}

func TestEditAggregatesSecretsAndWorkloads(t *testing.T) {
	inv := &rbac.Inventory{
		Roles: Roles(),
		Bindings: []*rbac.Binding{{
			Kind: "RoleBinding", Name: "b", Namespace: "team",
			RoleRef:  rbacv1.RoleRef{Kind: "ClusterRole", Name: "edit"},
			Subjects: []rbac.Subject{{Kind: rbac.KindUser, Name: "alice"}},
		}},
	}
	g := rbac.Build(inv)
	grants := g.DirectGrants(rbac.Subject{Kind: rbac.KindUser, Name: "alice"})
	if len(rbac.Can(grants, []string{"list"}, "", "secrets")) == 0 {
		t.Error("edit should allow listing Secrets")
	}
	if len(rbac.Can(grants, []string{"create"}, "", "pods")) == 0 {
		t.Error("edit should allow creating Pods")
	}
	if len(rbac.Can(grants, []string{"create"}, "rbac.authorization.k8s.io", "rolebindings")) != 0 {
		t.Error("edit does not include RoleBindings")
	}
}

func TestIsSystem(t *testing.T) {
	tests := []struct {
		s    rbac.Subject
		want bool
	}{
		{rbac.Subject{Kind: rbac.KindGroup, Name: "system:masters"}, true},
		{rbac.Subject{Kind: rbac.KindGroup, Name: "system:nodes"}, true},
		{rbac.Subject{Kind: rbac.KindGroup, Name: "system:bootstrappers:kubeadm:default-node-token"}, true},
		{rbac.Subject{Kind: rbac.KindGroup, Name: "system:authenticated"}, false},
		{rbac.Subject{Kind: rbac.KindGroup, Name: "system:unauthenticated"}, false},
		{rbac.Subject{Kind: rbac.KindGroup, Name: "system:serviceaccounts"}, false},
		{rbac.Subject{Kind: rbac.KindGroup, Name: "admins"}, false},
		{rbac.Subject{Kind: rbac.KindUser, Name: "system:kube-controller-manager"}, true},
		{rbac.Subject{Kind: rbac.KindUser, Name: "system:kube-scheduler"}, true},
		{rbac.Subject{Kind: rbac.KindUser, Name: "system:node:worker-1"}, true},
		{rbac.Subject{Kind: rbac.KindUser, Name: "system:anonymous"}, false},
		{rbac.Subject{Kind: rbac.KindUser, Name: "alice"}, false},
		{rbac.Subject{Kind: rbac.KindServiceAccount, Namespace: "kube-system", Name: "clusterrole-aggregation-controller"}, true},
		{rbac.Subject{Kind: rbac.KindServiceAccount, Namespace: "kube-system", Name: "bootstrap-signer"}, true},
		{rbac.Subject{Kind: rbac.KindServiceAccount, Namespace: "kube-system", Name: "my-addon"}, false},
		{rbac.Subject{Kind: rbac.KindServiceAccount, Namespace: "default", Name: "deployment-controller"}, false},
		{rbac.Subject{Kind: "Other", Name: "x"}, false},
	}
	for _, tt := range tests {
		if got := IsSystem(tt.s); got != tt.want {
			t.Errorf("IsSystem(%v) = %v, want %v", tt.s, got, tt.want)
		}
	}
}
