package check

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"

	"github.com/OTA-EITA/kube-rbac-paths/internal/bootstrap"
	"github.com/OTA-EITA/kube-rbac-paths/internal/rbac"
)

// Options control an audit.
type Options struct {
	// IncludeSystem reports the cluster's own identities too (see
	// bootstrap.IsSystem) and bindings from the default policy.
	IncludeSystem bool
}

// Admin is a subject that holds cluster-admin-equivalent permissions.
type Admin struct {
	Subject rbac.Subject `json:"subject"`
	// Via is the ServiceAccount the subject reaches admin through, if not direct.
	Via      *rbac.Subject `json:"via,omitempty"`
	Reason   string        `json:"reason"`
	Evidence []Evidence    `json:"evidence"`
	// UsedBy lists the workloads that run as the subject (ServiceAccounts only).
	UsedBy []Evidence `json:"usedBy,omitempty"`
}

// Result is the outcome of an audit.
type Result struct {
	Findings []Finding `json:"findings"`
	Admins   []Admin   `json:"effectiveAdmins"`
	// Subjects is the number of subjects audited; Excluded the number of
	// built-in system subjects left out.
	Subjects int `json:"subjects"`
	Excluded int `json:"excludedSystemSubjects"`
	// Unresolved are bindings whose role was not found; they grant nothing
	// in this analysis.
	Unresolved []string `json:"unresolvedBindings,omitempty"`
	Duplicates int      `json:"duplicateObjects,omitempty"`
}

// Count returns the number of findings at or above a severity.
func (r Result) Count(threshold Severity) int {
	n := 0
	for _, f := range r.Findings {
		if f.Severity >= threshold && threshold != None {
			n++
		}
	}
	return n
}

type auditor struct {
	g      *rbac.Graph
	opts   Options
	admin  map[string]*adminReason // subject key -> direct reason (effective grants)
	direct map[string][]Finding    // subject key -> permission findings from its own grants
}

type adminReason struct {
	text    string
	matches []rbac.Match
}

// Run audits a resolved graph.
func Run(g *rbac.Graph, opts Options) Result {
	a := &auditor{g: g, opts: opts, admin: map[string]*adminReason{}, direct: map[string][]Finding{}}

	// Every subject we know about: binding subjects and ServiceAccounts.
	all := map[string]rbac.Subject{}
	for _, s := range g.Subjects() {
		all[s.Key()] = s
	}
	for _, s := range g.ServiceAccountsIn("") {
		all[s.Key()] = s
	}
	keys := make([]string, 0, len(all))
	for k := range all {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		s := all[k]
		if r := directAdmin(g.EffectiveGrants(s)); r != nil {
			a.admin[k] = r
		}
		a.direct[k] = a.permissionFindings(s)
	}

	res := Result{Duplicates: g.Duplicates()}
	for _, b := range g.Unresolved() {
		res.Unresolved = append(res.Unresolved, fmt.Sprintf("%s (%s) references %s %s", b.Ref(), b.Source, b.RoleRef.Kind, b.RoleRef.Name))
	}
	res.Findings = append(res.Findings, a.bindingFindings()...)

	for _, k := range keys {
		s := all[k]
		if !opts.IncludeSystem && bootstrap.IsSystem(s) {
			if len(g.DirectGrants(s)) > 0 {
				res.Excluded++
			}
			continue
		}
		if len(g.EffectiveGrants(s)) == 0 {
			continue
		}
		res.Subjects++
		if r := a.admin[k]; r != nil {
			adm := Admin{Subject: s, Reason: r.text, Evidence: matchEvidence(s, r.matches), UsedBy: a.usedBy(s)}
			res.Admins = append(res.Admins, adm)
			res.Findings = append(res.Findings, Finding{
				CheckID: EffectiveAdmin, Severity: High, Subject: ptr(s),
				Message:     fmt.Sprintf("%s effectively holds cluster-admin-equivalent permissions because it %s", s, r.text),
				Location:    firstBindingSource(r.matches),
				Evidence:    adm.Evidence,
				Fingerprint: fp(EffectiveAdmin, s.Key()),
			})
			continue
		}
		// The subject's own risky permissions are still listed when it is
		// admin only through a ServiceAccount: removing that one path would
		// not remove them.
		res.Findings = append(res.Findings, a.direct[k]...)
		pivots, viaAdmin := a.pivotFindings(s)
		res.Findings = append(res.Findings, pivots...)
		if viaAdmin != nil {
			res.Admins = append(res.Admins, *viaAdmin)
			res.Findings = append(res.Findings, Finding{
				CheckID: EffectiveAdmin, Severity: High, Subject: ptr(s),
				Message:     fmt.Sprintf("%s effectively holds cluster-admin-equivalent permissions because it %s", s, viaAdmin.Reason),
				Location:    viaAdmin.Evidence[0].Source,
				Evidence:    viaAdmin.Evidence,
				Fingerprint: fp(EffectiveAdmin, s.Key()),
			})
		}
	}
	sortFindings(res.Findings)
	return res
}

func ptr(s rbac.Subject) *rbac.Subject { return &s }

func fp(parts ...string) string { return strings.Join(parts, "|") }

func sortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		if a.Location.File != b.Location.File {
			return a.Location.File < b.Location.File
		}
		if a.Location.Line != b.Location.Line {
			return a.Location.Line < b.Location.Line
		}
		if a.CheckID != b.CheckID {
			return a.CheckID < b.CheckID
		}
		return a.Message < b.Message
	})
}

func (a *auditor) usedBy(s rbac.Subject) []Evidence {
	var out []Evidence
	for _, w := range a.g.WorkloadsUsing(s) {
		out = append(out, Evidence{Text: "runs as it: " + w.Ref(), Source: w.Source})
	}
	return out
}

// --- binding-level checks ---------------------------------------------------

var broadGroups = map[string]Severity{
	"system:unauthenticated": High,
	"system:authenticated":   Medium,
	"system:serviceaccounts": Medium,
}

func (a *auditor) bindingFindings() []Finding {
	var out []Finding
	for _, b := range a.g.Bindings() {
		if b.Bootstrap() && !a.opts.IncludeSystem {
			continue
		}
		var subjects []string
		for _, s := range b.Subjects {
			if !a.opts.IncludeSystem && bootstrap.IsSystem(s) {
				continue
			}
			subjects = append(subjects, s.String())
		}
		if len(subjects) == 0 {
			continue
		}
		if b.RoleRef.Kind == "ClusterRole" && b.RoleRef.Name == "cluster-admin" {
			sev, scope := High, "the whole cluster"
			if b.Kind == "RoleBinding" {
				sev, scope = Medium, "namespace "+b.Namespace
			}
			out = append(out, Finding{
				CheckID: ClusterAdminBinding, Severity: sev,
				Message:     fmt.Sprintf("%s grants cluster-admin on %s to %s", b.Ref(), scope, strings.Join(subjects, ", ")),
				Location:    b.Source,
				Evidence:    []Evidence{{Text: b.Ref() + " binds ClusterRole cluster-admin", Source: b.Source}},
				Fingerprint: fp(ClusterAdminBinding, b.Kind, b.Namespace, b.Name, strings.Join(subjects, ",")),
			})
		}
		for _, s := range b.Subjects {
			var sev Severity
			switch {
			case s.Kind == rbac.KindGroup:
				sev = broadGroups[s.Name]
			case s.Kind == rbac.KindUser && s.Name == "system:anonymous":
				sev = High
			}
			if sev == None {
				continue
			}
			out = append(out, Finding{
				CheckID: BroadGroupBinding, Severity: sev,
				Message:     fmt.Sprintf("%s grants %s %s to %s", b.Ref(), b.RoleRef.Kind, b.RoleRef.Name, s),
				Location:    b.Source,
				Evidence:    []Evidence{{Text: b.Ref() + " has subject " + s.String(), Source: b.Source}},
				Fingerprint: fp(BroadGroupBinding, b.Kind, b.Namespace, b.Name, s.Key()),
			})
		}
	}
	return out
}

// --- effective admin --------------------------------------------------------

func unrestrictedOrNamed(ms []rbac.Match, name string) []rbac.Match {
	var out []rbac.Match
	for _, m := range ms {
		if m.Grant.ClusterWide() && (m.Names == nil || slices.Contains(m.Names, name)) {
			out = append(out, m)
		}
	}
	return out
}

func wide(ms []rbac.Match) []rbac.Match {
	var out []rbac.Match
	for _, m := range ms {
		if m.Grant.ClusterWide() {
			out = append(out, m)
		}
	}
	return out
}

func clusterWide(ms []rbac.Match) []rbac.Match {
	var out []rbac.Match
	for _, m := range ms {
		if m.Grant.ClusterWide() && m.Names == nil {
			out = append(out, m)
		}
	}
	return out
}

// directAdmin decides whether grants add up to cluster-admin. It returns the
// first reason found, with the matches that prove it.
func directAdmin(grants []*rbac.Grant) *adminReason {
	const rg = rbacv1.GroupName
	if ms := clusterWide(rbac.Can(grants, []string{"*"}, "*", "*")); len(ms) > 0 {
		return &adminReason{"holds every verb on every resource in every API group, cluster-wide", ms[:1]}
	}
	bind := unrestrictedOrNamed(rbac.Can(grants, []string{"bind"}, rg, "clusterroles"), "cluster-admin")
	crb := clusterWide(rbac.Can(grants, []string{"create"}, rg, "clusterrolebindings"))
	if len(bind) > 0 && len(crb) > 0 {
		return &adminReason{"can create ClusterRoleBindings and has bind on ClusterRole cluster-admin, so it can bind itself to cluster-admin", []rbac.Match{crb[0], bind[0]}}
	}
	// escalate + update on a ClusterRole that is already bound to the subject
	// cluster-wide.
	for _, gr := range grants {
		if !gr.ClusterWide() || gr.Role == nil || gr.Role.Kind != "ClusterRole" || gr.Role.Aggregation != nil {
			continue
		}
		name := gr.Role.Name
		esc := unrestrictedOrNamed(rbac.Can(grants, []string{"escalate"}, rg, "clusterroles"), name)
		upd := unrestrictedOrNamed(rbac.Can(grants, []string{"update", "patch"}, rg, "clusterroles"), name)
		if len(esc) > 0 && len(upd) > 0 {
			return &adminReason{fmt.Sprintf("can update ClusterRole %s, which is bound to it, and has escalate, so it can add any permission to it", name), []rbac.Match{upd[0], esc[0]}}
		}
	}
	if ms := unrestrictedOrNamed(rbac.Can(grants, []string{"impersonate"}, "", "groups"), "system:masters"); len(ms) > 0 {
		return &adminReason{"can impersonate the system:masters group", ms[:1]}
	}
	create := clusterWide(rbac.Can(grants, []string{"create"}, "certificates.k8s.io", "certificatesigningrequests"))
	// resourceNames on approval do not help: the subject can create a CSR
	// with one of the allowed names.
	approve := wide(rbac.Can(grants, []string{"update", "patch"}, "certificates.k8s.io", "certificatesigningrequests/approval"))
	signer := signerMatches(grants)
	if len(create) > 0 && len(approve) > 0 && len(signer) > 0 {
		return &adminReason{"can create and approve CertificateSigningRequests for the kubernetes.io/kube-apiserver-client signer, so it can issue a client certificate for the system:masters group", []rbac.Match{create[0], approve[0], signer[0]}}
	}
	return nil
}

// signerMatches finds approve permission for the API server client signer.
// The authorizer checks the signer name and its "kubernetes.io/*" wildcard.
func signerMatches(grants []*rbac.Grant) []rbac.Match {
	var out []rbac.Match
	for _, m := range rbac.Can(grants, []string{"approve"}, "certificates.k8s.io", "signers") {
		if m.Grant.ClusterWide() && (m.Names == nil || slices.Contains(m.Names, "kubernetes.io/kube-apiserver-client") || slices.Contains(m.Names, "kubernetes.io/*")) {
			out = append(out, m)
		}
	}
	return out
}

func firstBindingSource(ms []rbac.Match) rbac.Source {
	if len(ms) == 0 {
		return rbac.Source{}
	}
	return ms[0].Grant.Binding.Source
}

// --- evidence ---------------------------------------------------------------

func ruleText(r *rbac.Rule) string {
	parts := []string{"verbs=" + list(r.Verbs)}
	if len(r.NonResourceURLs) > 0 {
		parts = append(parts, "nonResourceURLs="+list(r.NonResourceURLs))
	} else {
		parts = append(parts, "apiGroups="+list(quoteEmpty(r.APIGroups)), "resources="+list(r.Resources))
	}
	if len(r.ResourceNames) > 0 {
		parts = append(parts, "resourceNames="+list(r.ResourceNames))
	}
	return strings.Join(parts, " ")
}

func quoteEmpty(v []string) []string {
	out := make([]string, len(v))
	for i, s := range v {
		if s == "" {
			s = `""`
		}
		out[i] = s
	}
	return out
}

func list(v []string) string { return "[" + strings.Join(v, ",") + "]" }

func grantEvidence(s rbac.Subject, gr *rbac.Grant) []Evidence {
	who := ""
	if gr.Subject.Key() != s.Key() {
		who = fmt.Sprintf(" (through its membership of %s)", gr.Subject)
	}
	role := gr.Binding.RoleRef.Kind + " " + gr.Binding.RoleRef.Name
	out := []Evidence{
		{Text: fmt.Sprintf("%s binds %s to %s%s", gr.Binding.Ref(), role, gr.Subject, who), Source: gr.Binding.Source},
	}
	if gr.Role != nil {
		text := gr.Role.Ref()
		if gr.Role.Source.Builtin() {
			text += " (Kubernetes default role)"
		}
		out = append(out, Evidence{Text: text, Source: gr.Role.Source})
		if gr.Rule.Origin != nil && gr.Rule.Origin != gr.Role {
			text := "aggregated from " + gr.Rule.Origin.Ref()
			if gr.Rule.Origin.Source.Builtin() {
				text += " (Kubernetes default role)"
			}
			out = append(out, Evidence{Text: text, Source: gr.Rule.Origin.Source})
		}
	}
	out = append(out, Evidence{Text: "rule " + ruleText(gr.Rule), Source: gr.Rule.Source})
	return out
}

func matchEvidence(s rbac.Subject, ms []rbac.Match) []Evidence {
	var out []Evidence
	seen := map[string]bool{}
	for _, m := range ms {
		for _, e := range grantEvidence(s, m.Grant) {
			k := e.Text + "@" + e.Source.String()
			if seen[k] {
				continue
			}
			seen[k] = true
			out = append(out, e)
		}
	}
	return out
}
