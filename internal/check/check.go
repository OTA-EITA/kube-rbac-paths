// Package check audits the effective permissions of every subject against
// the privilege escalation risks listed in the Kubernetes "Role Based Access
// Control Good Practices" page.
package check

import (
	"fmt"
	"strings"

	"github.com/OTA-EITA/kube-rbac-paths/internal/rbac"
)

// Severity of a finding.
type Severity int

// Severities, lowest first.
const (
	None Severity = iota
	Low
	Medium
	High
)

func (s Severity) String() string {
	switch s {
	case Low:
		return "low"
	case Medium:
		return "medium"
	case High:
		return "high"
	}
	return "none"
}

// MarshalText makes severities readable in JSON.
func (s Severity) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// ParseSeverity parses high, medium, low or none.
func ParseSeverity(v string) (Severity, error) {
	switch strings.ToLower(v) {
	case "high":
		return High, nil
	case "medium":
		return Medium, nil
	case "low":
		return Low, nil
	case "none":
		return None, nil
	}
	return None, fmt.Errorf("unknown severity %q (want high, medium, low or none)", v)
}

// DocsURL is the page the checks come from.
const DocsURL = "https://kubernetes.io/docs/concepts/security/rbac-good-practices/"

// Check describes one audit.
type Check struct {
	ID         string `json:"id"`
	Title      string `json:"title"`
	Severities string `json:"severities"`
	// Section is the heading of the good-practices page the check follows.
	Section string `json:"section"`
	Anchor  string `json:"-"`
	Why     string `json:"why"`
	Fix     string `json:"fix"`
}

// URL links to the section of the good-practices page.
func (c Check) URL() string { return DocsURL + "#" + c.Anchor }

// Check IDs.
const (
	ClusterAdminBinding = "KRP001"
	Wildcard            = "KRP002"
	SecretsRead         = "KRP003"
	WorkloadCreate      = "KRP004"
	ServiceAccountPivot = "KRP005"
	PersistentVolume    = "KRP006"
	NodesProxy          = "KRP007"
	EscalateBind        = "KRP008"
	Impersonate         = "KRP009"
	CSRApproval         = "KRP010"
	TokenRequest        = "KRP011"
	AdmissionWebhooks   = "KRP012"
	NamespaceModify     = "KRP013"
	EffectiveAdmin      = "KRP014"
	BroadGroupBinding   = "KRP015"
)

// Checks lists every check, in ID order.
var Checks = []Check{
	{
		ID: ClusterAdminBinding, Title: "Binding to cluster-admin", Severities: "high (ClusterRoleBinding), medium (RoleBinding)",
		Section: "Least privilege", Anchor: "least-privilege",
		Why: "cluster-admin allows every action on every resource; a RoleBinding to it still gives full control of the namespace, including its Roles and RoleBindings.",
		Fix: "bind a Role or ClusterRole that lists only the resources and verbs the subject uses.",
	},
	{
		ID: Wildcard, Title: "Wildcard verbs or resources", Severities: "high (* on * cluster-wide), medium",
		Section: "Least privilege", Anchor: "least-privilege",
		Why: "a wildcard covers every current resource type and every type added later, including custom resources installed after the review.",
		Fix: "list the resources and verbs explicitly.",
	},
	{
		ID: SecretsRead, Title: "Read access to Secrets", Severities: "high (all namespaces), medium (one namespace), low (named Secrets)",
		Section: "Listing secrets", Anchor: "listing-secrets",
		Why: "get reveals a Secret, and list and watch return the contents of every Secret in scope, not just their names.",
		Fix: "drop list and watch, restrict get with resourceNames, or move the Secrets the subject needs into its own namespace.",
	},
	{
		ID: WorkloadCreate, Title: "Workload creation", Severities: "medium (all namespaces), low (one namespace)",
		Section: "Workload creation", Anchor: "workload-creation",
		Why: "a Pod can mount any Secret, ConfigMap or PersistentVolume in its namespace and run as any ServiceAccount there.",
		Fix: "limit workload creation to namespaces that hold nothing more privileged than the subject, and enforce the Baseline or Restricted Pod Security Standard there.",
	},
	{
		ID: ServiceAccountPivot, Title: "Can act as a more privileged ServiceAccount", Severities: "the highest severity among the ServiceAccount's own findings (if it is cluster-admin-equivalent, KRP014 is reported instead)",
		Section: "Workload creation", Anchor: "workload-creation",
		Why: "creating a Pod that uses another ServiceAccount, requesting a token for it, or impersonating it gives the subject that ServiceAccount's permissions.",
		Fix: "move the privileged ServiceAccount to a namespace the subject cannot create workloads or tokens in, or remove the subject's create/impersonate permission there.",
	},
	{
		ID: PersistentVolume, Title: "PersistentVolume creation", Severities: "medium",
		Section: "Persistent volume creation", Anchor: "persistent-volume-creation",
		Why: "a PersistentVolume can be a hostPath volume, which gives a Pod access to the node's filesystem.",
		Fix: "let trusted administrators and the storage provisioner create PersistentVolumes; give others PersistentVolumeClaims.",
	},
	{
		ID: NodesProxy, Title: "nodes/proxy access", Severities: "high",
		Section: "Access to proxy subresource of Nodes", Anchor: "access-to-proxy-subresource-of-nodes",
		Why: "nodes/proxy reaches the kubelet API, which can exec into every Pod on the node; get is enough and the calls bypass audit logging and admission control.",
		Fix: "use nodes/metrics, nodes/stats or nodes/log for monitoring instead of nodes/proxy.",
	},
	{
		ID: EscalateBind, Title: "escalate or bind verb", Severities: "high (cluster-wide), medium",
		Section: "Escalate verb / Bind verb", Anchor: "escalate-verb",
		Why: "escalate lets a subject write Roles with permissions it does not hold, and bind lets it bind Roles it does not hold; both bypass RBAC's escalation protection.",
		Fix: "remove escalate and bind, or restrict bind with resourceNames to the roles the subject must hand out.",
	},
	{
		ID: Impersonate, Title: "impersonate verb", Severities: "high (cluster-wide), medium",
		Section: "Impersonate verb", Anchor: "impersonate-verb",
		Why: "impersonation gives the subject the rights of the users, groups or ServiceAccounts it can impersonate.",
		Fix: "restrict impersonate with resourceNames to specific low-privileged identities.",
	},
	{
		ID: CSRApproval, Title: "CSR approval", Severities: "high (can issue client certificates), medium",
		Section: "CSRs and certificate issuing", Anchor: "csrs-and-certificate-issuing",
		Why: "with create on CSRs and update on certificatesigningrequests/approval, a subject can get client certificates with any name, including system:masters.",
		Fix: "leave approval to the controller manager or a dedicated approver, and restrict the approve verb on signers to the signer it needs.",
	},
	{
		ID: TokenRequest, Title: "ServiceAccount token creation", Severities: "high (all namespaces), medium (one namespace), low (named ServiceAccounts)",
		Section: "Token request", Anchor: "token-request",
		Why: "create on serviceaccounts/token issues tokens for existing ServiceAccounts, which carry their permissions.",
		Fix: "restrict it with resourceNames to the ServiceAccounts the subject must issue tokens for.",
	},
	{
		ID: AdmissionWebhooks, Title: "Admission webhook configuration control", Severities: "high, low (named webhooks only)",
		Section: "Control admission webhooks", Anchor: "control-admission-webhooks",
		Why: "a webhook configuration decides which service sees every admitted object; a mutating webhook can also change them.",
		Fix: "restrict update and patch with resourceNames to the subject's own webhook configuration, and drop create and delete.",
	},
	{
		ID: NamespaceModify, Title: "Namespace modification", Severities: "medium, low (named namespaces only)",
		Section: "Namespace modification", Anchor: "namespace-modification",
		Why: "namespace labels select the Pod Security level and NetworkPolicy peers, so changing them can relax both.",
		Fix: "remove patch and update on namespaces; manage namespace labels from a trusted pipeline.",
	},
	{
		ID: EffectiveAdmin, Title: "Effective cluster-admin", Severities: "high",
		Section: "Privilege escalation risks", Anchor: "privilege-escalation-risks",
		Why: "the subject can do anything in the cluster, directly or in one step through a ServiceAccount it can act as.",
		Fix: "break the chain shown in the evidence: narrow the role, scope the binding to a namespace, or separate the ServiceAccount.",
	},
	{
		ID: BroadGroupBinding, Title: "Binding to all users or all ServiceAccounts", Severities: "high (unauthenticated), medium",
		Section: "Hardening", Anchor: "hardening",
		Why: "system:unauthenticated is anyone who can reach the API server; system:authenticated and system:serviceaccounts are every user or every Pod.",
		Fix: "bind the role to the specific users, groups or ServiceAccounts that need it.",
	},
}

// Lookup returns a check by ID.
func Lookup(id string) (Check, bool) {
	for _, c := range Checks {
		if c.ID == id {
			return c, true
		}
	}
	return Check{}, false
}

// Evidence is one step of the reasoning behind a finding.
type Evidence struct {
	Text   string      `json:"text"`
	Source rbac.Source `json:"source"`
}

// Finding is one audit result.
type Finding struct {
	CheckID  string        `json:"check"`
	Severity Severity      `json:"severity"`
	Subject  *rbac.Subject `json:"subject,omitempty"`
	Message  string        `json:"message"`
	Location rbac.Source   `json:"location"`
	Evidence []Evidence    `json:"evidence,omitempty"`
	// Fingerprint identifies the finding across runs, independent of file
	// names and line numbers; diff mode compares fingerprints.
	Fingerprint string `json:"fingerprint"`
}

// Check returns the check that produced the finding.
func (f Finding) Check() Check {
	c, _ := Lookup(f.CheckID)
	return c
}
