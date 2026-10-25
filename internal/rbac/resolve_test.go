package rbac

import (
	"reflect"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func rule(groups, resources, verbs, names []string) *Rule {
	return &Rule{PolicyRule: rbacv1.PolicyRule{APIGroups: groups, Resources: resources, Verbs: verbs, ResourceNames: names}}
}

func s(v ...string) []string { return v }

func grant(r *Rule, ns string) *Grant {
	role := &Role{Kind: "ClusterRole", Name: "r"}
	r.Origin = role
	return &Grant{Binding: &Binding{Kind: "ClusterRoleBinding", Name: "b"}, Role: role, Rule: r, Namespace: ns}
}

func TestCan(t *testing.T) {
	tests := []struct {
		name      string
		rule      *Rule
		ns        string
		verb      string
		group     string
		resource  string
		want      bool
		wantNames []string
		named     bool
	}{
		{"exact", rule(s(""), s("secrets"), s("get"), nil), "", "get", "", "secrets", true, nil, false},
		{"other verb", rule(s(""), s("secrets"), s("get"), nil), "", "list", "", "secrets", false, nil, false},
		{"other group", rule(s("apps"), s("secrets"), s("get"), nil), "", "get", "", "secrets", false, nil, false},
		{"verb wildcard", rule(s(""), s("secrets"), s("*"), nil), "", "watch", "", "secrets", true, nil, false},
		{"group wildcard", rule(s("*"), s("deployments"), s("create"), nil), "", "create", "apps", "deployments", true, nil, false},
		{"resource wildcard covers subresource", rule(s(""), s("*"), s("get"), nil), "", "get", "", "nodes/proxy", true, nil, false},
		{"star slash subresource", rule(s(""), s("*/proxy"), s("get"), nil), "", "get", "", "nodes/proxy", true, nil, false},
		{"star slash other subresource", rule(s(""), s("*/status"), s("get"), nil), "", "get", "", "nodes/proxy", false, nil, false},
		{"parent does not cover subresource", rule(s(""), s("nodes"), s("get"), nil), "", "get", "", "nodes/proxy", false, nil, false},
		{"namespaced grant reaches namespaced resource", rule(s(""), s("secrets"), s("get"), nil), "team", "get", "", "secrets", true, nil, false},
		{"namespaced grant misses cluster-scoped", rule(s(""), s("nodes/proxy"), s("get"), nil), "team", "get", "", "nodes/proxy", false, nil, false},
		{"namespaced wildcard misses cluster-scoped", rule(s("*"), s("*"), s("*"), nil), "team", "create", "", "persistentvolumes", false, nil, false},
		{"namespaced grant reaches its own namespace", rule(s(""), s("namespaces"), s("patch"), nil), "team", "patch", "", "namespaces", true, s("team"), false},
		{"namespaced own namespace with other names", rule(s(""), s("namespaces"), s("patch"), s("other")), "team", "patch", "", "namespaces", false, nil, true},
		{"namespaced bind on clusterroles", rule(s("rbac.authorization.k8s.io"), s("clusterroles"), s("bind"), nil), "team", "bind", "rbac.authorization.k8s.io", "clusterroles", true, nil, false},
		{"namespaced escalate on clusterroles", rule(s("rbac.authorization.k8s.io"), s("clusterroles"), s("escalate"), nil), "team", "escalate", "rbac.authorization.k8s.io", "clusterroles", false, nil, false},
		{"resourceNames narrow", rule(s(""), s("secrets"), s("get"), s("a", "b")), "", "get", "", "secrets", true, s("a", "b"), true},
		{"resourceNames never allow top-level create", rule(s(""), s("pods"), s("create"), s("p")), "", "create", "", "pods", false, nil, true},
		{"resourceNames do allow subresource create", rule(s(""), s("serviceaccounts/token"), s("create"), s("sa")), "", "create", "", "serviceaccounts/token", true, s("sa"), true},
		{"custom resource is namespaced", rule(s("example.com"), s("widgets"), s("get"), nil), "team", "get", "example.com", "widgets", true, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ms := Can([]*Grant{grant(tt.rule, tt.ns)}, []string{tt.verb}, tt.group, tt.resource)
			if got := len(ms) > 0; got != tt.want {
				t.Fatalf("Can = %v, want %v", got, tt.want)
			}
			if !tt.want {
				return
			}
			if !reflect.DeepEqual(ms[0].Names, tt.wantNames) {
				t.Errorf("names = %v, want %v", ms[0].Names, tt.wantNames)
			}
			if ms[0].NamedByRule != tt.named {
				t.Errorf("NamedByRule = %v, want %v", ms[0].NamedByRule, tt.named)
			}
			if ms[0].Unrestricted() != (tt.wantNames == nil) {
				t.Errorf("Unrestricted = %v", ms[0].Unrestricted())
			}
			if ms[0].Resource != tt.resource || ms[0].Group != tt.group || ms[0].Verb != tt.verb {
				t.Errorf("match = %+v", ms[0])
			}
		})
	}
}

func TestCanSkipsNonResourceRules(t *testing.T) {
	r := &Rule{PolicyRule: rbacv1.PolicyRule{NonResourceURLs: []string{"*"}, Verbs: []string{"*"}}}
	if ms := Can([]*Grant{grant(r, "")}, []string{"get"}, "", "secrets"); len(ms) != 0 {
		t.Fatalf("non-resource rule matched a resource: %v", ms)
	}
}

func TestClusterScoped(t *testing.T) {
	if !ClusterScoped("", "nodes") || !ClusterScoped("rbac.authorization.k8s.io", "clusterroles") {
		t.Error("nodes and clusterroles are cluster-scoped")
	}
	if ClusterScoped("", "pods") || ClusterScoped("example.com", "widgets") {
		t.Error("pods and custom resources are namespaced")
	}
}

func clusterRole(name string, labels map[string]string, agg *rbacv1.AggregationRule, rules ...*Rule) *Role {
	r := &Role{Kind: "ClusterRole", Name: name, Labels: labels, Aggregation: agg, Source: Source{File: "f.yaml", Line: 1}}
	for _, ru := range rules {
		ru.Origin = r
		r.Rules = append(r.Rules, ru)
	}
	return r
}

func selector(k, v string) *rbacv1.AggregationRule {
	return &rbacv1.AggregationRule{ClusterRoleSelectors: []metav1.LabelSelector{{MatchLabels: map[string]string{k: v}}}}
}

func TestAggregation(t *testing.T) {
	secrets := rule(s(""), s("secrets"), s("get"), nil)
	pods := rule(s(""), s("pods"), s("create"), nil)
	ignored := rule(s(""), s("nodes"), s("get"), nil)
	inv := &Inventory{
		Roles: []*Role{
			// top aggregates mid, which aggregates leaf: rules flow up two levels.
			clusterRole("top", nil, selector("to-top", "true"), ignored),
			clusterRole("mid", map[string]string{"to-top": "true"}, selector("to-mid", "true")),
			clusterRole("leaf", map[string]string{"to-mid": "true"}, nil, secrets),
			clusterRole("other", map[string]string{"to-top": "true"}, nil, pods),
			// a cycle must terminate.
			clusterRole("loop-a", map[string]string{"loop": "b"}, selector("loop", "a")),
			clusterRole("loop-b", map[string]string{"loop": "a"}, selector("loop", "b")),
		},
		Bindings: []*Binding{{
			Kind: "ClusterRoleBinding", Name: "b", RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "top"},
			Subjects: []Subject{{Kind: KindUser, Name: "u"}},
		}},
	}
	g := Build(inv)
	u := Subject{Kind: KindUser, Name: "u"}
	grants := g.DirectGrants(u)
	if len(grants) != 2 {
		t.Fatalf("got %d grants, want 2 (secrets via mid, pods via other)", len(grants))
	}
	if len(Can(grants, s("get"), "", "nodes")) != 0 {
		t.Error("an aggregated role's own rules are replaced by the controller")
	}
	ms := Can(grants, s("get"), "", "secrets")
	if len(ms) != 1 || ms[0].Grant.Rule.Origin.Name != "leaf" || ms[0].Grant.Role.Name != "top" {
		t.Fatalf("secrets should come from leaf through top: %+v", ms)
	}
}

func TestEmptySelectorMatchesEverything(t *testing.T) {
	agg := &rbacv1.AggregationRule{ClusterRoleSelectors: []metav1.LabelSelector{{}}}
	inv := &Inventory{Roles: []*Role{
		clusterRole("all", nil, agg),
		clusterRole("x", nil, nil, rule(s(""), s("pods"), s("get"), nil)),
	}}
	Build(inv)
	if n := len(inv.Roles[0].EffectiveRules()); n != 1 {
		t.Fatalf("got %d rules, want 1", n)
	}
	bad := &rbacv1.AggregationRule{ClusterRoleSelectors: []metav1.LabelSelector{{MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "k", Operator: "Bogus"}}}}}
	inv = &Inventory{Roles: []*Role{clusterRole("bad", nil, bad), clusterRole("x", nil, nil, rule(s(""), s("pods"), s("get"), nil))}}
	Build(inv)
	if n := len(inv.Roles[0].EffectiveRules()); n != 0 {
		t.Fatalf("invalid selector matched %d rules", n)
	}
}

func TestBuildBindingsAndScope(t *testing.T) {
	role := &Role{Kind: "Role", Name: "reader", Namespace: "team"}
	role.Rules = []*Rule{{PolicyRule: rbacv1.PolicyRule{APIGroups: s(""), Resources: s("secrets"), Verbs: s("get")}, Origin: role}}
	builtin := clusterRole("edit", nil, nil, rule(s(""), s("pods"), s("create"), nil))
	builtin.Source = Source{File: BuiltinPrefix + "x.yaml", Line: 3}
	mine := clusterRole("edit", nil, nil, rule(s(""), s("configmaps"), s("get"), nil))
	inv := &Inventory{
		Roles: []*Role{builtin, mine, role, clusterRole("edit", nil, nil)},
		Bindings: []*Binding{
			{Kind: "RoleBinding", Name: "rb", Namespace: "team", RoleRef: rbacv1.RoleRef{Kind: "Role", Name: "reader"},
				Subjects: []Subject{{Kind: KindServiceAccount, Name: "app"}}},
			{Kind: "RoleBinding", Name: "rb", Namespace: "team", RoleRef: rbacv1.RoleRef{Kind: "Role", Name: "reader"}},
			{Kind: "RoleBinding", Name: "edit", Namespace: "team", RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "edit"},
				Subjects: []Subject{{Kind: KindUser, Name: "system:serviceaccount:team:app"}}},
			{Kind: "RoleBinding", Name: "missing", Namespace: "team", RoleRef: rbacv1.RoleRef{Kind: "Role", Name: "nope"},
				Subjects: []Subject{{Kind: KindUser, Name: "u"}}},
			{Kind: "ClusterRoleBinding", Name: "bad-kind", RoleRef: rbacv1.RoleRef{Kind: "Role", Name: "reader"}},
			{Kind: "ClusterRoleBinding", Name: "weird", RoleRef: rbacv1.RoleRef{Kind: "Something", Name: "reader"}},
			{Kind: "ClusterRoleBinding", Name: "sas", RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "edit"},
				Subjects: []Subject{{Kind: KindGroup, Name: "system:serviceaccounts:team"}}},
		},
		ServiceAccounts: []*ServiceAccount{{Name: "app", Namespace: "team"}, {Name: "app", Namespace: "team"}},
		Workloads:       []*Workload{{Kind: "Deployment", Name: "web", Namespace: "team", ServiceAccount: "web"}},
	}
	g := Build(inv)
	app := Subject{Kind: KindServiceAccount, Namespace: "team", Name: "app"}
	direct := g.DirectGrants(app)
	if len(direct) != 2 {
		t.Fatalf("direct grants = %d, want 2", len(direct))
	}
	for _, gr := range direct {
		if gr.Namespace != "team" || gr.ClusterWide() {
			t.Errorf("RoleBinding grant must be scoped to team: %+v", gr)
		}
		if gr.Role.Name == "edit" && gr.Role != mine {
			t.Error("a role from the inputs must win over the built-in one")
		}
	}
	if eff := g.EffectiveGrants(app); len(eff) != 3 {
		t.Errorf("effective grants = %d, want 3 (with system:serviceaccounts:team)", len(eff))
	}
	if g.Duplicates() != 2 {
		t.Errorf("duplicates = %d, want 2", g.Duplicates())
	}
	if n := len(g.Unresolved()); n != 3 {
		t.Errorf("unresolved = %d, want 3", n)
	}
	if n := len(g.Bindings()); n != 6 {
		t.Errorf("bindings = %d, want 6", n)
	}
	if got := g.ServiceAccountsIn("team"); len(got) != 2 {
		t.Errorf("service accounts in team = %v", got)
	}
	if got := g.ServiceAccountsIn("other"); len(got) != 0 {
		t.Errorf("service accounts in other = %v", got)
	}
	web := Subject{Kind: KindServiceAccount, Namespace: "team", Name: "web"}
	if len(g.WorkloadsUsing(web)) != 1 || g.ServiceAccountObject(web) != nil || g.ServiceAccountObject(app) == nil {
		t.Error("workload and ServiceAccount lookups")
	}
	if subs := g.Subjects(); len(subs) != 3 {
		t.Errorf("subjects = %v", subs)
	}
}

func TestImplicitGroups(t *testing.T) {
	tests := []struct {
		s    Subject
		want []string
	}{
		{Subject{Kind: KindServiceAccount, Namespace: "ns", Name: "a"}, s("system:serviceaccounts", "system:serviceaccounts:ns", "system:authenticated")},
		{Subject{Kind: KindUser, Name: "alice"}, s("system:authenticated")},
		{Subject{Kind: KindUser, Name: "system:anonymous"}, s("system:unauthenticated")},
		{Subject{Kind: KindGroup, Name: "g"}, nil},
	}
	for _, tt := range tests {
		if got := ImplicitGroups(tt.s); !reflect.DeepEqual(got, tt.want) {
			t.Errorf("%v: got %v, want %v", tt.s, got, tt.want)
		}
	}
}

func TestNormalizeSubject(t *testing.T) {
	tests := []struct {
		in   Subject
		ns   string
		want Subject
	}{
		{Subject{Kind: KindUser, Name: "system:serviceaccount:a:b"}, "", Subject{Kind: KindServiceAccount, Namespace: "a", Name: "b"}},
		{Subject{Kind: KindUser, Name: "system:serviceaccount:a"}, "", Subject{Kind: KindUser, Name: "system:serviceaccount:a"}},
		{Subject{Kind: KindServiceAccount, Name: "b"}, "x", Subject{Kind: KindServiceAccount, Namespace: "x", Name: "b"}},
		{Subject{Kind: KindGroup, Name: "g", Namespace: "x"}, "x", Subject{Kind: KindGroup, Name: "g"}},
	}
	for _, tt := range tests {
		if got := NormalizeSubject(tt.in, tt.ns); got != tt.want {
			t.Errorf("NormalizeSubject(%v) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestStrings(t *testing.T) {
	if got := (Source{}).String(); got != "" {
		t.Errorf("empty source = %q", got)
	}
	if got := (Source{File: "a.yaml"}).String(); got != "a.yaml" {
		t.Errorf("source without line = %q", got)
	}
	if got := (Source{File: "a.yaml", Line: 3}).String(); got != "a.yaml:3" {
		t.Errorf("source = %q", got)
	}
	if !(Source{File: BuiltinPrefix + "x"}).Builtin() {
		t.Error("builtin source")
	}
	if got := (&Role{Kind: "Role", Namespace: "n", Name: "r"}).Ref(); got != "Role n/r" {
		t.Error(got)
	}
	if got := (&Role{Kind: "ClusterRole", Name: "r"}).Ref(); got != "ClusterRole r" {
		t.Error(got)
	}
	if got := (&Binding{Kind: "RoleBinding", Namespace: "n", Name: "b"}).Ref(); got != "RoleBinding n/b" {
		t.Error(got)
	}
	if got := (&Binding{Kind: "ClusterRoleBinding", Name: "b"}).Ref(); got != "ClusterRoleBinding b" {
		t.Error(got)
	}
	if got := (&Workload{Kind: "Pod", Namespace: "n", Name: "p"}).Ref(); got != "Pod n/p" {
		t.Error(got)
	}
	if !(&Binding{Labels: map[string]string{"kubernetes.io/bootstrapping": "rbac-defaults"}}).Bootstrap() {
		t.Error("bootstrap label")
	}
	if got := (Subject{Kind: KindGroup, Name: "g"}).String(); got != "Group g" {
		t.Error(got)
	}
	if got := (Subject{Kind: KindServiceAccount, Namespace: "n", Name: "a"}).String(); got != "ServiceAccount n/a" {
		t.Error(got)
	}
}

func TestMerge(t *testing.T) {
	a := &Inventory{Roles: []*Role{{}}}
	a.Merge(&Inventory{Roles: []*Role{{}}, Bindings: []*Binding{{}}, ServiceAccounts: []*ServiceAccount{{}}, Workloads: []*Workload{{}}})
	if len(a.Roles) != 2 || len(a.Bindings) != 1 || len(a.ServiceAccounts) != 1 || len(a.Workloads) != 1 {
		t.Errorf("merge: %+v", a)
	}
}
