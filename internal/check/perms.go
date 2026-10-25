package check

import (
	"fmt"
	"slices"
	"sort"
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

var permChecks = []permCheck{
	{SecretsRead, []target{{"", "secrets", []string{"get", "list", "watch"}}}, tiered(High, Medium, Low)},
	{WorkloadCreate, workloadTargets, tiered(Medium, Low, Low)},
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

// --- acting as another ServiceAccount ---------------------------------------

type route struct {
	how   string // "workload", "token", "impersonate"
	match rbac.Match
	res   []string
}

func (a *auditor) routes(s rbac.Subject) []route {
	grants := a.g.DirectGrants(s)
	var out []route
	byNS := map[string]int{}
	for _, t := range workloadTargets {
		for _, m := range rbac.Can(grants, t.verbs, t.group, t.resource) {
			ns := m.Grant.Namespace
			i, ok := byNS[ns]
			if !ok {
				i = len(out)
				byNS[ns] = i
				out = append(out, route{how: "workload", match: m})
			}
			out[i].res = appendUnique(out[i].res, t.resource)
		}
	}
	for _, m := range rbac.Can(grants, []string{"create"}, "", "serviceaccounts/token") {
		out = append(out, route{how: "token", match: m})
	}
	for _, m := range rbac.Can(grants, []string{"impersonate"}, "", "serviceaccounts") {
		out = append(out, route{how: "impersonate", match: m})
	}
	return out
}

func (a *auditor) notable(t rbac.Subject) []Finding {
	var out []Finding
	for _, f := range a.direct[t.Key()] {
		if f.Severity >= Medium && f.CheckID != WorkloadCreate {
			out = append(out, f)
		}
	}
	return out
}

// covered reports whether s already holds every notable permission of t at
// the same or a higher severity, in which case acting as t adds nothing.
func (a *auditor) covered(s rbac.Subject, notes []Finding) bool {
	own := map[string]Severity{}
	for _, f := range a.direct[s.Key()] {
		own[f.CheckID] = max(own[f.CheckID], f.Severity)
	}
	for _, n := range notes {
		if own[n.CheckID] < n.Severity {
			return false
		}
	}
	return true
}

func (a *auditor) pivotFindings(s rbac.Subject) ([]Finding, *Admin) {
	// Collect, per target ServiceAccount, every route that reaches it. Routes
	// come in a fixed order: workload creation, token request, impersonation.
	type reach struct {
		t      rbac.Subject
		routes []route
	}
	var targets []*reach
	idx := map[string]*reach{}
	for _, r := range a.routes(s) {
		for _, t := range a.g.ServiceAccountsIn(r.match.Grant.Namespace) {
			if t.Key() == s.Key() || (r.match.Names != nil && !slices.Contains(r.match.Names, t.Name)) {
				continue
			}
			rc := idx[t.Key()]
			if rc == nil {
				rc = &reach{t: t}
				idx[t.Key()] = rc
				targets = append(targets, rc)
			}
			if !slices.ContainsFunc(rc.routes, func(x route) bool { return x.how == r.how }) {
				rc.routes = append(rc.routes, r)
			}
		}
	}
	sort.SliceStable(targets, func(i, j int) bool { return targets[i].t.Key() < targets[j].t.Key() })

	var out []Finding
	var viaAdmin *Admin
	for _, rc := range targets {
		t := rc.t
		adm := a.admin[t.Key()]
		notes := a.notable(t)
		if adm == nil && (len(notes) == 0 || a.covered(s, notes)) {
			continue
		}
		first := rc.routes[0]
		act := a.routeText(s, first, t)
		var ev []Evidence
		for _, r := range rc.routes {
			ev = append(ev, grantEvidence(s, r.match.Grant)...)
		}
		ev = dedupe(append(ev, a.whereLives(t)...))
		if adm != nil {
			// Reported as KRP014 for the subject, with this chain as evidence.
			if viaAdmin == nil {
				viaAdmin = &Admin{
					Subject: s, Via: ptr(t),
					Reason:   fmt.Sprintf("%s, and %s %s", strings.TrimPrefix(act, s.String()+" "), t, adm.text),
					Evidence: dedupe(append(ev, matchEvidence(t, adm.matches)...)),
					UsedBy:   a.usedBy(s),
				}
			}
			continue
		}
		var also []string
		for _, r := range rc.routes[1:] {
			also = append(also, strings.TrimPrefix(a.routeText(s, r, t), s.String()+" can "))
		}
		sev := Medium
		var titles []string
		for _, n := range notes {
			sev = max(sev, n.Severity)
			titles = appendUnique(titles, fmt.Sprintf("%s (%s)", strings.ToLower(n.Check().Title[:1])+n.Check().Title[1:], n.Severity))
			ev = append(ev, Evidence{Text: n.Message, Source: n.Location})
		}
		sort.Strings(titles)
		msg := fmt.Sprintf("%s; %s holds: %s", act, t, strings.Join(titles, "; "))
		if len(also) > 0 {
			msg += ". It can also " + strings.Join(also, " and ")
		}
		out = append(out, Finding{
			CheckID: ServiceAccountPivot, Severity: sev, Subject: ptr(s),
			Message:     msg,
			Location:    first.match.Grant.Binding.Source,
			Evidence:    ev,
			Fingerprint: fp(ServiceAccountPivot, s.Key(), t.Key()),
		})
	}
	return out, viaAdmin
}

func dedupe(ev []Evidence) []Evidence {
	var out []Evidence
	seen := map[string]bool{}
	for _, e := range ev {
		k := e.Text + "@" + e.Source.String()
		if !seen[k] {
			seen[k] = true
			out = append(out, e)
		}
	}
	return out
}

func (a *auditor) routeText(s rbac.Subject, r route, t rbac.Subject) string {
	switch r.how {
	case "workload":
		scope := "in namespace " + t.Namespace
		if r.match.Grant.ClusterWide() {
			scope = "in every namespace, including " + t.Namespace
		}
		return fmt.Sprintf("%s can create %s %s, where %s lives", s, resourceList(r.res), scope, t)
	case "token":
		return fmt.Sprintf("%s can create tokens for %s", s, t)
	}
	return fmt.Sprintf("%s can impersonate %s", s, t)
}

// whereLives points at the ServiceAccount object, or at a workload that uses
// it when the object itself is not in the inputs.
func (a *auditor) whereLives(t rbac.Subject) []Evidence {
	if sa := a.g.ServiceAccountObject(t); sa != nil {
		return []Evidence{{Text: t.String(), Source: sa.Source}}
	}
	if ws := a.g.WorkloadsUsing(t); len(ws) > 0 {
		return []Evidence{{Text: ws[0].Ref() + " runs as " + t.String(), Source: ws[0].Source}}
	}
	return nil
}
