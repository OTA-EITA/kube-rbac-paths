package check

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/OTA-EITA/kube-rbac-paths/internal/rbac"
)

// --- acting as another ServiceAccount ---------------------------------------

// maxHops bounds how many ServiceAccounts a chain may pass through.
const maxHops = 4

// Ways to act as another ServiceAccount, in the order they are reported.
const (
	routeCreate      = "create"      // create a workload that runs as it
	routeTemplate    = "template"    // change a workload's Pod template to it
	routePod         = "pod"         // change a running Pod that runs as it
	routeToken       = "token"       // request a token for it
	routeImpersonate = "impersonate" // impersonate it
)

type route struct {
	how   string
	match rbac.Match // the first match; its grant decides the scope
	res   []string
	verbs []string
	// names limits a template or pod route to these objects (resourceNames).
	names []string
}

// reach is one ServiceAccount a subject can act as, and every way it can.
type reach struct {
	t      rbac.Subject
	routes []route
}

// hop is one step of a chain.
type hop struct {
	from, to rbac.Subject
	routes   []route
}

// groupRoutes turns matches into routes, one per namespace and set of
// resourceNames.
func groupRoutes(how string, grants []*rbac.Grant, targets []target, named bool) []route {
	var out []route
	idx := map[string]int{}
	for _, t := range targets {
		for _, m := range rbac.Can(grants, t.verbs, t.group, t.resource) {
			var names []string
			if named && m.NamedByRule {
				names = m.Names
			}
			k := m.Grant.Namespace + "|" + strings.Join(names, ",")
			i, ok := idx[k]
			if !ok {
				i = len(out)
				idx[k] = i
				out = append(out, route{how: how, match: m, names: names})
			}
			out[i].res = appendUnique(out[i].res, t.resource)
			out[i].verbs = appendUnique(out[i].verbs, m.Verb)
		}
	}
	return out
}

func (a *auditor) routes(s rbac.Subject) []route {
	grants := a.g.DirectGrants(s)
	out := groupRoutes(routeCreate, grants, workloadTargets, false)
	out = append(out, groupRoutes(routeTemplate, grants, templateTargets, true)...)
	out = append(out, groupRoutes(routePod, grants, podTargets, true)...)
	for _, m := range rbac.Can(grants, []string{"create"}, "", "serviceaccounts/token") {
		out = append(out, route{how: routeToken, match: m})
	}
	for _, m := range rbac.Can(grants, []string{"impersonate"}, "", "serviceaccounts") {
		out = append(out, route{how: routeImpersonate, match: m})
	}
	return out
}

// pods returns the workloads whose Pods a pod route can change and that run
// as t. With resourceNames only bare Pods of those names qualify: the names
// of Pods made by a controller are not known.
func (a *auditor) pods(r route, t rbac.Subject) []*rbac.Workload {
	var out []*rbac.Workload
	for _, w := range a.g.WorkloadsUsing(t) {
		if r.names == nil || (w.Kind == "Pod" && slices.Contains(r.names, w.Name)) {
			out = append(out, w)
		}
	}
	return out
}

func (a *auditor) reaches(r route, t rbac.Subject) bool {
	switch r.how {
	case routeToken, routeImpersonate:
		return r.match.Names == nil || slices.Contains(r.match.Names, t.Name)
	case routePod:
		return len(a.pods(r, t)) > 0
	}
	// A new or changed Pod template can name any ServiceAccount in the
	// namespace, even when only one named workload can be changed.
	return true
}

// edges lists the ServiceAccounts s can act as in one step, sorted.
func (a *auditor) edges(s rbac.Subject) []*reach {
	var out []*reach
	idx := map[string]*reach{}
	for _, r := range a.routes(s) {
		for _, t := range a.g.ServiceAccountsIn(r.match.Grant.Namespace) {
			if t.Key() == s.Key() || !a.reaches(r, t) {
				continue
			}
			rc := idx[t.Key()]
			if rc == nil {
				rc = &reach{t: t}
				idx[t.Key()] = rc
				out = append(out, rc)
			}
			if !slices.ContainsFunc(rc.routes, func(x route) bool { return x.how == r.how }) {
				rc.routes = append(rc.routes, r)
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].t.Key() < out[j].t.Key() })
	return out
}

func (a *auditor) notable(t rbac.Subject) []Finding {
	var out []Finding
	for _, f := range a.direct[t.Key()] {
		// Workload creation and modification and token requests are
		// followed as further hops instead.
		if f.Severity >= Medium && f.CheckID != WorkloadCreate && f.CheckID != WorkloadModify && f.CheckID != TokenRequest {
			out = append(out, f)
		}
	}
	return out
}

// covered reports whether every notable permission is already held at the
// same or a higher severity, in which case acting as its holder adds nothing.
func covered(held map[string]Severity, notes []Finding) bool {
	for _, n := range notes {
		if held[n.CheckID] < n.Severity {
			return false
		}
	}
	return true
}

// pivotFindings follows the ServiceAccounts s can act as, breadth first, up
// to maxHops steps, so every ServiceAccount is reached by its shortest chain.
// A ServiceAccount with notable permissions gets a KRP005 finding unless s
// already holds them, or (for chains of two or more steps) a shorter chain
// already gives them. The first cluster-admin-equivalent ServiceAccount
// found is returned as an Admin, and the search stops after that depth.
func (a *auditor) pivotFindings(s rbac.Subject) ([]Finding, *Admin) {
	held := map[string]Severity{}
	for _, f := range a.direct[s.Key()] {
		held[f.CheckID] = max(held[f.CheckID], f.Severity)
	}
	visited := map[string]bool{s.Key(): true}
	frontier := [][]hop{nil}
	var out []Finding
	var viaAdmin *Admin
	for depth := 1; depth <= maxHops && len(frontier) > 0 && viaAdmin == nil; depth++ {
		var next [][]hop
		var gained []Finding
		for _, ch := range frontier {
			from := s
			if len(ch) > 0 {
				from = ch[len(ch)-1].to
			}
			for _, rc := range a.edges(from) {
				t := rc.t
				if visited[t.Key()] {
					continue
				}
				visited[t.Key()] = true
				path := append(slices.Clone(ch), hop{from: from, to: t, routes: rc.routes})
				if adm := a.admin[t.Key()]; adm != nil {
					// Reported as KRP014 for the subject, with this chain as
					// evidence.
					if viaAdmin == nil {
						viaAdmin = a.adminVia(s, path, adm)
					}
					continue
				}
				next = append(next, path)
				notes := a.notable(t)
				if len(notes) == 0 || covered(held, notes) {
					continue
				}
				out = append(out, a.pivotFinding(s, path, notes))
				gained = append(gained, notes...)
			}
		}
		for _, n := range gained {
			held[n.CheckID] = max(held[n.CheckID], n.Severity)
		}
		frontier = next
	}
	return out, viaAdmin
}

func (a *auditor) chainText(path []hop) string {
	parts := make([]string, len(path))
	for i, h := range path {
		parts[i] = a.routeText(h.from, h.routes[0], h.to)
	}
	return strings.Join(parts, "; ")
}

// alsoText lists the other ways of a one-step chain.
func (a *auditor) alsoText(path []hop) string {
	if len(path) != 1 {
		return ""
	}
	h := path[0]
	var also []string
	sep := " and "
	for _, r := range h.routes[1:] {
		also = append(also, a.alsoRouteText(r, h.to))
		if r.how == routeTemplate || r.how == routePod {
			sep = "; "
		}
	}
	if len(also) == 0 {
		return ""
	}
	return ". It can also " + strings.Join(also, sep)
}

// alsoRouteText is a short form of routeText for a further way to reach the
// same ServiceAccount.
func (a *auditor) alsoRouteText(r route, t rbac.Subject) string {
	switch r.how {
	case routeTemplate:
		return fmt.Sprintf("%s %s %s, to set serviceAccountName in their Pod template to that ServiceAccount", strings.Join(r.verbs, ", "), routeObjects(r), routeScope(r, t))
	case routePod:
		return fmt.Sprintf("%s %s of %s to %s", strings.Join(r.verbs, ", "), routeObjects(r), a.pods(r, t)[0].Ref(), podAction(r))
	}
	// Workload creation always comes first, so only tokens and
	// impersonation are left.
	return strings.TrimPrefix(a.routeText(t, r, t), t.String()+" can ")
}

func (a *auditor) chainEvidence(path []hop) []Evidence {
	var ev []Evidence
	for _, h := range path {
		for _, r := range h.routes {
			ev = append(ev, grantEvidence(h.from, r.match.Grant)...)
			if r.how == routePod {
				for _, w := range a.pods(r, h.to) {
					ev = append(ev, Evidence{Text: w.Ref() + " runs as " + h.to.String(), Source: w.Source})
				}
			}
		}
		ev = append(ev, a.whereLives(h.to)...)
	}
	return ev
}

func chainSubjects(path []hop) []rbac.Subject {
	out := make([]rbac.Subject, len(path))
	for i, h := range path {
		out[i] = h.to
	}
	return out
}

func (a *auditor) adminVia(s rbac.Subject, path []hop, adm *adminReason) *Admin {
	t := path[len(path)-1].to
	act := strings.TrimPrefix(a.chainText(path), s.String()+" ")
	return &Admin{
		Subject: s, Via: ptr(t), Chain: chainSubjects(path),
		Reason:   fmt.Sprintf("%s, and %s %s%s", act, t, adm.text, a.alsoText(path)),
		Evidence: dedupe(append(a.chainEvidence(path), matchEvidence(t, adm.matches)...)),
		UsedBy:   a.usedBy(s),
	}
}

func (a *auditor) pivotFinding(s rbac.Subject, path []hop, notes []Finding) Finding {
	t := path[len(path)-1].to
	ev := dedupe(a.chainEvidence(path))
	sev := Medium
	var titles []string
	for _, n := range notes {
		sev = max(sev, n.Severity)
		titles = appendUnique(titles, fmt.Sprintf("%s (%s)", strings.ToLower(n.Check().Title[:1])+n.Check().Title[1:], n.Severity))
		ev = append(ev, Evidence{Text: n.Message, Source: n.Location})
	}
	sort.Strings(titles)
	return Finding{
		CheckID: ServiceAccountPivot, Severity: sev, Subject: ptr(s),
		Message:     fmt.Sprintf("%s; %s holds: %s%s", a.chainText(path), t, strings.Join(titles, "; "), a.alsoText(path)),
		Location:    path[0].routes[0].match.Grant.Binding.Source,
		Evidence:    ev,
		Fingerprint: fp(ServiceAccountPivot, s.Key(), t.Key()),
	}
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

func routeScope(r route, t rbac.Subject) string {
	if r.match.Grant.ClusterWide() {
		return "in every namespace, including " + t.Namespace
	}
	return "in namespace " + t.Namespace
}

func routeObjects(r route) string {
	what := resourceList(r.res)
	if r.names != nil {
		what += " (only " + strings.Join(r.names, ", ") + ")"
	}
	return what
}

func podAction(r route) string {
	switch {
	case !slices.Contains(r.res, "pods/ephemeralcontainers"):
		return "replace a container image"
	case !slices.Contains(r.res, "pods"):
		return "add an ephemeral container"
	}
	return "replace a container image or add an ephemeral container"
}

func (a *auditor) routeText(s rbac.Subject, r route, t rbac.Subject) string {
	scope, what, verbs := routeScope(r, t), routeObjects(r), strings.Join(r.verbs, ", ")
	switch r.how {
	case routeCreate:
		return fmt.Sprintf("%s can create %s %s, where %s lives", s, what, scope, t)
	case routeTemplate:
		return fmt.Sprintf("%s can %s %s %s, where %s lives, so it can set serviceAccountName in their Pod template to that ServiceAccount", s, verbs, what, scope, t)
	case routePod:
		action := podAction(r)
		if action == "add an ephemeral container" {
			action += " to those Pods"
		} else {
			action += " in those Pods"
		}
		return fmt.Sprintf("%s can %s %s %s, where %s runs as %s, so it can %s", s, verbs, what, scope, a.pods(r, t)[0].Ref(), t, action)
	case routeToken:
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
