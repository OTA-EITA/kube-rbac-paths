package check

import (
	"fmt"
	"slices"
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"

	"github.com/OTA-EITA/kube-rbac-paths/internal/rbac"
)

type target struct {
	group, resource string
	verbs           []string
}

type permCheck struct {
	id      string
	targets []target
	// severity of a group of matches that come from one binding.
	severity func(ms []rbac.Match) Severity
}

// tiered picks a severity by scope: cluster-wide without resourceNames,
// one namespace without resourceNames, or narrowed by resourceNames.
func tiered(wide, namespaced, named Severity) func([]rbac.Match) Severity {
	return func(ms []rbac.Match) Severity {
		best := None
		for _, m := range ms {
			s := namespaced
			switch {
			case m.NamedByRule:
				s = named
			case m.Grant.ClusterWide():
				s = wide
			}
			best = max(best, s)
		}
		return best
	}
}

var workloadTargets = []target{
	{"", "pods", []string{"create"}},
	{"", "replicationcontrollers", []string{"create"}},
	{"apps", "deployments", []string{"create"}},
	{"apps", "daemonsets", []string{"create"}},
	{"apps", "statefulsets", []string{"create"}},
	{"apps", "replicasets", []string{"create"}},
	{"batch", "jobs", []string{"create"}},
	{"batch", "cronjobs", []string{"create"}},
}

// templateTargets are the workloads whose Pod template can be changed after
// creation; the controller then creates Pods from the new template. A Job's
// template is immutable (only its scheduling directives can change), so jobs
// are left out.
var templateTargets = []target{
	{"", "replicationcontrollers", []string{"update", "patch"}},
	{"apps", "deployments", []string{"update", "patch"}},
	{"apps", "daemonsets", []string{"update", "patch"}},
	{"apps", "statefulsets", []string{"update", "patch"}},
	{"apps", "replicasets", []string{"update", "patch"}},
	{"batch", "cronjobs", []string{"update", "patch"}},
}

// podTargets change a running Pod. Its serviceAccountName cannot change, but
// a container image can, and an ephemeral container can be added; both run
// with the Pod's ServiceAccount.
var podTargets = []target{
	{"", "pods", []string{"update", "patch"}},
	{"", "pods/ephemeralcontainers", []string{"update", "patch"}},
}

var permChecks = []permCheck{
	{SecretsRead, []target{{"", "secrets", []string{"get", "list", "watch"}}}, tiered(High, Medium, Low)},
	{WorkloadCreate, workloadTargets, tiered(Medium, Low, Low)},
	{WorkloadModify, append(slices.Clone(templateTargets), podTargets...), tiered(Medium, Low, Low)},
	{PersistentVolume, []target{{"", "persistentvolumes", []string{"create"}}}, tiered(Medium, Medium, Low)},
	{NodesProxy, []target{{"", "nodes/proxy", []string{"get", "create", "update", "patch", "delete"}}}, tiered(High, High, Medium)},
	{EscalateBind, []target{
		{rbacv1.GroupName, "roles", []string{"escalate", "bind"}},
		{rbacv1.GroupName, "clusterroles", []string{"escalate", "bind"}},
	}, tiered(High, Medium, Low)},
	{Impersonate, []target{
		{"", "users", []string{"impersonate"}},
		{"", "groups", []string{"impersonate"}},
		{"", "serviceaccounts", []string{"impersonate"}},
		{"authentication.k8s.io", "uids", []string{"impersonate"}},
	}, tiered(High, Medium, Medium)},
	{CSRApproval, []target{{"certificates.k8s.io", "certificatesigningrequests/approval", []string{"update", "patch"}}}, tiered(Medium, Medium, Medium)},
	{TokenRequest, []target{{"", "serviceaccounts/token", []string{"create"}}}, tiered(High, Medium, Low)},
	{AdmissionWebhooks, []target{
		{"admissionregistration.k8s.io", "validatingwebhookconfigurations", []string{"create", "update", "patch", "delete"}},
		{"admissionregistration.k8s.io", "mutatingwebhookconfigurations", []string{"create", "update", "patch", "delete"}},
	}, tiered(High, High, Low)},
	{NamespaceModify, []target{{"", "namespaces", []string{"patch", "update"}}}, tiered(Medium, Medium, Low)},
}

// permissionFindings runs the risky-permission checks on the grants given to
// the subject itself. A cluster-admin-equivalent subject gets none: its
// KRP014 finding already says it can do everything.
func (a *auditor) permissionFindings(s rbac.Subject) []Finding {
	if a.admin[s.Key()] != nil {
		return nil
	}
	grants := a.g.DirectGrants(s)
	out := wildcardFindings(s, grants)
	creates := map[string]bool{} // scopes with a workload creation finding
	for _, pc := range permChecks {
		var ms []rbac.Match
		for _, t := range pc.targets {
			ms = append(ms, rbac.Can(grants, t.verbs, t.group, t.resource)...)
		}
		groups := groupByScope(ms)
		for _, grp := range groups {
			if len(groups) > 1 && coveredByClusterWide(grp, groups) {
				continue
			}
			switch pc.id {
			case WorkloadCreate:
				creates[grp.key] = true
			case WorkloadModify:
				// Creating a workload already reaches every ServiceAccount
				// and volume that changing one does.
				if creates[""] || creates[grp.key] {
					continue
				}
			}
			out = append(out, permFinding(pc, s, grp))
		}
	}
	return out
}

// coveredByClusterWide reports whether a namespaced group adds nothing to a
// cluster-wide grant of the same check: same or more verbs, no resourceNames.
func coveredByClusterWide(grp matchGroup, groups []matchGroup) bool {
	if grp.key == "" {
		return false
	}
	wideVerbs := map[string]bool{}
	for _, g := range groups {
		if g.key != "" {
			continue
		}
		for _, m := range g.matches {
			if !m.NamedByRule {
				wideVerbs[m.Verb] = true
			}
		}
	}
	for _, m := range grp.matches {
		if !wideVerbs[m.Verb] {
			return false
		}
	}
	return true
}

type matchGroup struct {
	key     string
	matches []rbac.Match
}

// groupByScope groups matches by the namespace they apply in, so a subject
// gets one finding per check and scope however many bindings grant it; the
// bindings are all listed as evidence.
func groupByScope(ms []rbac.Match) []matchGroup {
	var out []matchGroup
	idx := map[string]int{}
	for _, m := range ms {
		k := m.Grant.Namespace
		i, ok := idx[k]
		if !ok {
			i = len(out)
			idx[k] = i
			out = append(out, matchGroup{key: k})
		}
		out[i].matches = append(out[i].matches, m)
	}
	return out
}

func permFinding(pc permCheck, s rbac.Subject, grp matchGroup) Finding {
	var verbs, resources, names []string
	unrestricted := false
	allClusterScoped := true
	for _, m := range grp.matches {
		verbs = appendUnique(verbs, m.Verb)
		resources = appendUnique(resources, m.Resource)
		if !rbac.ClusterScoped(m.Group, strings.SplitN(m.Resource, "/", 2)[0]) {
			allClusterScoped = false
		}
		if m.NamedByRule {
			for _, n := range m.Names {
				names = appendUnique(names, n)
			}
		} else {
			unrestricted = true
		}
	}
	gr := grp.matches[0].Grant
	var scope string
	switch {
	case !gr.ClusterWide():
		scope = "in namespace " + gr.Namespace
	case allClusterScoped:
		scope = "cluster-wide"
	default:
		scope = "in every namespace"
	}
	msg := fmt.Sprintf("%s can %s %s %s", s, strings.Join(verbs, ", "), resourceList(resources), scope)
	if pc.id == NamespaceModify && !gr.ClusterWide() {
		msg = fmt.Sprintf("%s can %s its own Namespace %s (a RoleBinding reaches the Namespace object it lives in)", s, strings.Join(verbs, ", "), gr.Namespace)
	}
	if !unrestricted && len(names) > 0 {
		msg += " (only " + strings.Join(names, ", ") + ")"
	}
	return Finding{
		CheckID: pc.id, Severity: pc.severity(grp.matches), Subject: ptr(s),
		Message:     msg,
		Location:    gr.Binding.Source,
		Evidence:    matchEvidence(s, grp.matches),
		Fingerprint: fp(pc.id, s.Key(), grp.key, gr.Namespace),
	}
}

// resourceList names resources, shortening long lists of workload kinds.
func resourceList(res []string) string {
	if len(res) <= 3 {
		return strings.Join(res, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(res[:3], ", "), len(res)-3)
}

func appendUnique(list []string, v string) []string {
	if slices.Contains(list, v) {
		return list
	}
	return append(list, v)
}

func isWild(v []string) bool { return slices.Contains(v, rbacv1.ResourceAll) }

func wildcardFindings(s rbac.Subject, grants []*rbac.Grant) []Finding {
	var out []Finding
	seen := map[string]bool{}
	for _, gr := range grants {
		r := gr.Rule
		if len(r.Resources) == 0 || r.Origin == nil || r.Origin.Source.Builtin() {
			continue
		}
		if !isWild(r.Verbs) && !isWild(r.Resources) {
			continue
		}
		key := fp(gr.Binding.Ref(), gr.Role.Ref(), ruleText(r))
		if seen[key] {
			continue
		}
		seen[key] = true
		sev := Medium
		if gr.ClusterWide() && isWild(r.Verbs) && isWild(r.Resources) && isWild(r.APIGroups) && len(r.ResourceNames) == 0 {
			sev = High
		}
		scope := "cluster-wide"
		if !gr.ClusterWide() {
			scope = "in namespace " + gr.Namespace
		}
		out = append(out, Finding{
			CheckID: Wildcard, Severity: sev, Subject: ptr(s),
			Message:     fmt.Sprintf("%s holds a wildcard rule %s from %s, %s", s, ruleText(r), r.Origin.Ref(), scope),
			Location:    gr.Binding.Source,
			Evidence:    grantEvidence(s, gr),
			Fingerprint: fp(Wildcard, s.Key(), key, gr.Namespace),
		})
	}
	return out
}
