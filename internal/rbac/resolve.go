package rbac

import (
	"slices"
	"sort"
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Grant is one rule that reaches a subject through one binding.
type Grant struct {
	// Subject is the binding subject that matched. For a ServiceAccount
	// this can be one of the groups it belongs to.
	Subject Subject
	Binding *Binding
	Role    *Role
	Rule    *Rule
	// Namespace limits the grant to one namespace. Empty means cluster-wide:
	// the rule applies to every namespace and to cluster-scoped resources.
	Namespace string
}

// ClusterWide reports whether the grant comes from a ClusterRoleBinding.
func (g *Grant) ClusterWide() bool { return g.Namespace == "" }

// Graph is the resolved view of an Inventory.
type Graph struct {
	clusterRoles map[string]*Role
	roles        map[string]*Role // namespace/name
	bindings     []*Binding
	grants       map[string][]*Grant // subject key -> grants
	subjects     map[string]Subject
	serviceAccts map[string]Subject // known ServiceAccounts, key -> subject
	workloads    map[string][]*Workload
	saObjects    map[string]*ServiceAccount
	unresolved   []*Binding
	duplicates   int
}

// Build resolves aggregation and bindings. Objects that appear more than
// once (same kind, namespace and name) are kept once: the first occurrence
// wins, and a definition from the inputs wins over a built-in one.
func Build(inv *Inventory) *Graph {
	g := &Graph{
		clusterRoles: map[string]*Role{},
		roles:        map[string]*Role{},
		grants:       map[string][]*Grant{},
		subjects:     map[string]Subject{},
		serviceAccts: map[string]Subject{},
		workloads:    map[string][]*Workload{},
		saObjects:    map[string]*ServiceAccount{},
	}
	for _, r := range inv.Roles {
		m, key := g.roles, r.Namespace+"/"+r.Name
		if r.Kind == "ClusterRole" {
			m, key = g.clusterRoles, r.Name
		}
		if prev, ok := m[key]; ok {
			if prev.Source.Builtin() && !r.Source.Builtin() {
				m[key] = r
				continue
			}
			if !r.Source.Builtin() {
				g.duplicates++
			}
			continue
		}
		m[key] = r
	}
	g.aggregate()

	seen := map[string]bool{}
	for _, b := range inv.Bindings {
		key := b.Kind + "/" + b.Namespace + "/" + b.Name
		if seen[key] {
			g.duplicates++
			continue
		}
		seen[key] = true
		g.bindings = append(g.bindings, b)
		role := g.lookup(b)
		if role == nil {
			g.unresolved = append(g.unresolved, b)
		}
		for _, s := range b.Subjects {
			s = NormalizeSubject(s, b.Namespace)
			g.subjects[s.Key()] = s
			if s.Kind == KindServiceAccount {
				g.serviceAccts[s.Key()] = s
			}
			if role == nil {
				continue
			}
			for _, rule := range role.EffectiveRules() {
				g.grants[s.Key()] = append(g.grants[s.Key()], &Grant{
					Subject: s, Binding: b, Role: role, Rule: rule, Namespace: b.Namespace,
				})
			}
		}
	}
	for _, sa := range inv.ServiceAccounts {
		s := Subject{Kind: KindServiceAccount, Namespace: sa.Namespace, Name: sa.Name}
		g.serviceAccts[s.Key()] = s
		if _, ok := g.saObjects[s.Key()]; !ok {
			g.saObjects[s.Key()] = sa
		}
	}
	for _, w := range inv.Workloads {
		s := Subject{Kind: KindServiceAccount, Namespace: w.Namespace, Name: w.ServiceAccount}
		g.serviceAccts[s.Key()] = s
		g.workloads[s.Key()] = append(g.workloads[s.Key()], w)
	}
	return g
}

func (g *Graph) lookup(b *Binding) *Role {
	switch b.RoleRef.Kind {
	case "ClusterRole":
		return g.clusterRoles[b.RoleRef.Name]
	case "Role":
		if b.Namespace == "" {
			return nil
		}
		return g.roles[b.Namespace+"/"+b.RoleRef.Name]
	}
	return nil
}

// aggregate fills the rules of ClusterRoles that have an aggregationRule
// with the rules of every ClusterRole their selectors match, the way the
// clusterrole-aggregation controller does. The role's own rules are
// replaced, because the controller overwrites them.
func (g *Graph) aggregate() {
	names := make([]string, 0, len(g.clusterRoles))
	for n := range g.clusterRoles {
		names = append(names, n)
	}
	sort.Strings(names)
	var resolve func(r *Role, visiting map[string]bool) []*Rule
	resolve = func(r *Role, visiting map[string]bool) []*Rule {
		if r.Aggregation == nil {
			return r.Rules
		}
		if r.resolved != nil {
			return r.resolved
		}
		if visiting[r.Name] {
			return nil
		}
		visiting[r.Name] = true
		defer delete(visiting, r.Name)
		out := []*Rule{}
		for _, n := range names {
			other := g.clusterRoles[n]
			if other == r || !matchesAny(r.Aggregation.ClusterRoleSelectors, other.Labels) {
				continue
			}
			out = append(out, resolve(other, visiting)...)
		}
		r.resolved = out
		return out
	}
	for _, n := range names {
		resolve(g.clusterRoles[n], map[string]bool{})
	}
}

func matchesAny(selectors []metav1.LabelSelector, lbls map[string]string) bool {
	for _, s := range selectors {
		if selectorMatches(s, lbls) {
			return true
		}
	}
	return false
}

// Subjects returns every subject named in a binding, sorted.
func (g *Graph) Subjects() []Subject {
	out := make([]Subject, 0, len(g.subjects))
	for _, s := range g.subjects {
		out = append(out, s)
	}
	sortSubjects(out)
	return out
}

func sortSubjects(s []Subject) {
	sort.Slice(s, func(i, j int) bool { return s[i].Key() < s[j].Key() })
}

// ServiceAccountsIn returns the ServiceAccounts known to exist in a
// namespace: ServiceAccount objects, ServiceAccounts named in bindings, and
// ServiceAccounts used by workloads. An empty namespace returns all of them.
func (g *Graph) ServiceAccountsIn(namespace string) []Subject {
	var out []Subject
	for _, s := range g.serviceAccts {
		if namespace == "" || s.Namespace == namespace {
			out = append(out, s)
		}
	}
	sortSubjects(out)
	return out
}

// WorkloadsUsing returns the workloads that run as a ServiceAccount.
func (g *Graph) WorkloadsUsing(s Subject) []*Workload { return g.workloads[s.Key()] }

// ServiceAccountObject returns the ServiceAccount object, if it was in the inputs.
func (g *Graph) ServiceAccountObject(s Subject) *ServiceAccount { return g.saObjects[s.Key()] }

// DirectGrants returns the grants given to the subject itself.
func (g *Graph) DirectGrants(s Subject) []*Grant { return g.grants[s.Key()] }

// EffectiveGrants returns the direct grants plus the grants of the groups the
// subject is known to belong to: every ServiceAccount is in
// system:serviceaccounts, system:serviceaccounts:<namespace> and
// system:authenticated.
func (g *Graph) EffectiveGrants(s Subject) []*Grant {
	out := slices.Clone(g.grants[s.Key()])
	for _, grp := range ImplicitGroups(s) {
		out = append(out, g.grants[Subject{Kind: KindGroup, Name: grp}.Key()]...)
	}
	return out
}

// ImplicitGroups lists the groups Kubernetes puts a subject in.
func ImplicitGroups(s Subject) []string {
	switch s.Kind {
	case KindServiceAccount:
		return []string{"system:serviceaccounts", "system:serviceaccounts:" + s.Namespace, "system:authenticated"}
	case KindUser:
		if s.Name == "system:anonymous" {
			return []string{"system:unauthenticated"}
		}
		return []string{"system:authenticated"}
	}
	return nil
}

// Bindings returns the bindings after de-duplication.
func (g *Graph) Bindings() []*Binding { return g.bindings }

// Unresolved returns bindings whose role is not in the inputs or the
// built-in roles. They grant nothing in this analysis.
func (g *Graph) Unresolved() []*Binding { return g.unresolved }

// Duplicates is the number of objects that were defined more than once.
func (g *Graph) Duplicates() int { return g.duplicates }

// Match is a grant that allows a request.
type Match struct {
	Grant *Grant
	Verb  string
	// Group and Resource are what was asked for.
	Group, Resource string
	// Names limits the match to these object names; nil means any name.
	Names []string
	// NamedByRule is true when the rule's resourceNames set the limit (as
	// opposed to a RoleBinding reaching only its own Namespace object).
	NamedByRule bool
}

// Unrestricted reports whether the match applies to every object.
func (m Match) Unrestricted() bool { return m.Names == nil }

// Can returns the grants that allow verb on group/resource (resource may
// name a subresource, e.g. "nodes/proxy"). It follows the RBAC authorizer:
// "*" matches every verb, group and resource, "*/sub" matches a subresource,
// a RoleBinding never reaches cluster-scoped resources, and resourceNames
// narrow the match (a top-level create carries no name, so a rule with
// resourceNames never allows it).
func Can(grants []*Grant, verbs []string, group, resource string) []Match {
	var out []Match
	for _, gr := range grants {
		r := gr.Rule
		if len(r.NonResourceURLs) > 0 && len(r.Resources) == 0 {
			continue
		}
		if !containsOrStar(r.APIGroups, group) || !resourceMatches(r.Resources, resource) {
			continue
		}
		for _, verb := range verbs {
			if !containsOrStar(r.Verbs, verb) {
				continue
			}
			names, ok := scopeNames(gr, verb, group, resource)
			if !ok {
				continue
			}
			if len(r.ResourceNames) > 0 {
				if verb == "create" && !strings.Contains(resource, "/") {
					continue
				}
				names = intersectNames(names, r.ResourceNames)
				if len(names) == 0 {
					continue
				}
			}
			out = append(out, Match{Grant: gr, Verb: verb, Group: group, Resource: resource, Names: names, NamedByRule: len(r.ResourceNames) > 0})
		}
	}
	return out
}

// scopeNames decides whether a grant's namespace scope reaches a resource.
// It returns the names the scope limits the request to (nil for no limit).
func scopeNames(gr *Grant, verb, group, resource string) ([]string, bool) {
	if gr.ClusterWide() {
		return nil, true
	}
	base := strings.SplitN(resource, "/", 2)[0]
	switch {
	case group == "" && base == "namespaces":
		// Requests on a Namespace object carry the namespace's own name as
		// their namespace, so a RoleBinding reaches that one Namespace.
		return []string{gr.Namespace}, true
	case group == rbacv1.GroupName && base == "clusterroles" && verb == "bind":
		// The bind check for a RoleBinding is made in the RoleBinding's
		// namespace, so bind on clusterroles in a Role is effective there.
		return nil, true
	case ClusterScoped(group, base):
		return nil, false
	}
	return nil, true
}

func intersectNames(scope, names []string) []string {
	if scope == nil {
		return slices.Clone(names)
	}
	var out []string
	for _, n := range scope {
		if slices.Contains(names, n) {
			out = append(out, n)
		}
	}
	return out
}

func containsOrStar(list []string, v string) bool {
	return slices.Contains(list, rbacv1.ResourceAll) || slices.Contains(list, v)
}

func resourceMatches(list []string, resource string) bool {
	sub := ""
	if i := strings.Index(resource, "/"); i >= 0 {
		sub = resource[i+1:]
	}
	for _, r := range list {
		if r == rbacv1.ResourceAll || r == resource {
			return true
		}
		if sub != "" && r == "*/"+sub {
			return true
		}
	}
	return false
}

// clusterScoped lists built-in cluster-scoped resources by API group.
var clusterScoped = map[string][]string{
	"":                             {"namespaces", "nodes", "persistentvolumes", "componentstatuses", "users", "groups"},
	"rbac.authorization.k8s.io":    {"clusterroles", "clusterrolebindings"},
	"certificates.k8s.io":          {"certificatesigningrequests", "signers", "clustertrustbundles"},
	"admissionregistration.k8s.io": {"validatingwebhookconfigurations", "mutatingwebhookconfigurations", "validatingadmissionpolicies", "validatingadmissionpolicybindings", "mutatingadmissionpolicies", "mutatingadmissionpolicybindings"},
	"apiextensions.k8s.io":         {"customresourcedefinitions"},
	"apiregistration.k8s.io":       {"apiservices"},
	"authentication.k8s.io":        {"tokenreviews", "selfsubjectreviews", "uids", "userextras"},
	"authorization.k8s.io":         {"subjectaccessreviews", "selfsubjectaccessreviews", "selfsubjectrulesreviews"},
	"storage.k8s.io":               {"storageclasses", "csidrivers", "csinodes", "volumeattachments", "volumeattributesclasses"},
	"scheduling.k8s.io":            {"priorityclasses"},
	"node.k8s.io":                  {"runtimeclasses"},
	"networking.k8s.io":            {"ingressclasses", "ipaddresses", "servicecidrs"},
	"flowcontrol.apiserver.k8s.io": {"flowschemas", "prioritylevelconfigurations"},
	"resource.k8s.io":              {"deviceclasses", "resourceslices"},
}

// ClusterScoped reports whether a built-in resource is cluster-scoped.
// Unknown resources (custom resources) are treated as namespaced.
func ClusterScoped(group, resource string) bool {
	return slices.Contains(clusterScoped[group], resource)
}
