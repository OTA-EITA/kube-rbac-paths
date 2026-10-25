// Package rbac holds the RBAC objects read from manifests and resolves the
// effective permissions of every subject they mention.
package rbac

import (
	"fmt"
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// Source is where an object or a rule was read from.
type Source struct {
	File string `json:"file"`
	Line int    `json:"line"`
}

func (s Source) String() string {
	if s.File == "" {
		return ""
	}
	if s.Line == 0 {
		return s.File
	}
	return fmt.Sprintf("%s:%d", s.File, s.Line)
}

// Builtin reports whether the object comes from the embedded Kubernetes
// bootstrap policy rather than from a file the user passed in.
func (s Source) Builtin() bool { return strings.HasPrefix(s.File, BuiltinPrefix) }

// BuiltinPrefix marks sources of the embedded bootstrap roles.
const BuiltinPrefix = "builtin:"

// Rule is one PolicyRule with the role it was written in.
type Rule struct {
	rbacv1.PolicyRule
	// Origin is the role the rule is written in. For an aggregated
	// ClusterRole this is the labeled ClusterRole it was copied from.
	Origin *Role
	Source Source
}

// Role is a Role or a ClusterRole.
type Role struct {
	Kind        string // "Role" or "ClusterRole"
	Name        string
	Namespace   string // empty for ClusterRole
	Labels      map[string]string
	Rules       []*Rule // rules as written
	Aggregation *rbacv1.AggregationRule
	Source      Source
	// resolved is the rule set after aggregation; nil until resolved.
	resolved []*Rule
}

// Ref is a short human readable reference, e.g. "ClusterRole edit".
func (r *Role) Ref() string {
	if r.Namespace != "" {
		return fmt.Sprintf("%s %s/%s", r.Kind, r.Namespace, r.Name)
	}
	return fmt.Sprintf("%s %s", r.Kind, r.Name)
}

// EffectiveRules returns the rules after aggregation.
func (r *Role) EffectiveRules() []*Rule {
	if r.resolved != nil {
		return r.resolved
	}
	return r.Rules
}

// Binding is a RoleBinding or a ClusterRoleBinding.
type Binding struct {
	Kind      string // "RoleBinding" or "ClusterRoleBinding"
	Name      string
	Namespace string // empty for ClusterRoleBinding
	Labels    map[string]string
	RoleRef   rbacv1.RoleRef
	Subjects  []Subject
	Source    Source
}

// Ref is a short human readable reference.
func (b *Binding) Ref() string {
	if b.Namespace != "" {
		return fmt.Sprintf("%s %s/%s", b.Kind, b.Namespace, b.Name)
	}
	return fmt.Sprintf("%s %s", b.Kind, b.Name)
}

// Bootstrap reports whether the binding is part of the Kubernetes default
// policy (label kubernetes.io/bootstrapping=rbac-defaults).
func (b *Binding) Bootstrap() bool { return b.Labels["kubernetes.io/bootstrapping"] == "rbac-defaults" }

// Subject kinds.
const (
	KindUser           = "User"
	KindGroup          = "Group"
	KindServiceAccount = "ServiceAccount"
)

// Subject is a User, Group or ServiceAccount.
type Subject struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
}

// NormalizeSubject turns the user name form of a service account
// (system:serviceaccount:ns:name) into a ServiceAccount subject, and fills in
// the namespace of a ServiceAccount subject that leaves it out in a
// RoleBinding.
func NormalizeSubject(s Subject, bindingNamespace string) Subject {
	if s.Kind == KindUser && strings.HasPrefix(s.Name, "system:serviceaccount:") {
		parts := strings.SplitN(strings.TrimPrefix(s.Name, "system:serviceaccount:"), ":", 2)
		if len(parts) == 2 && parts[0] != "" && parts[1] != "" {
			return Subject{Kind: KindServiceAccount, Namespace: parts[0], Name: parts[1]}
		}
	}
	if s.Kind == KindServiceAccount && s.Namespace == "" {
		s.Namespace = bindingNamespace
	}
	if s.Kind != KindServiceAccount {
		s.Namespace = ""
	}
	return s
}

func (s Subject) String() string {
	if s.Kind == KindServiceAccount {
		return fmt.Sprintf("ServiceAccount %s/%s", s.Namespace, s.Name)
	}
	return fmt.Sprintf("%s %s", s.Kind, s.Name)
}

// Key is a stable identifier used for sorting and fingerprints.
func (s Subject) Key() string {
	return s.Kind + ":" + s.Namespace + ":" + s.Name
}

// ServiceAccount is a ServiceAccount object.
type ServiceAccount struct {
	Name      string
	Namespace string
	Source    Source
}

// Workload is a Pod or a controller that creates Pods.
type Workload struct {
	Kind           string
	Name           string
	Namespace      string
	ServiceAccount string
	Source         Source
}

// Ref is a short human readable reference.
func (w *Workload) Ref() string {
	return fmt.Sprintf("%s %s/%s", w.Kind, w.Namespace, w.Name)
}

// Inventory is everything read from the inputs.
type Inventory struct {
	Roles           []*Role
	Bindings        []*Binding
	ServiceAccounts []*ServiceAccount
	Workloads       []*Workload
}

// Merge appends other's objects.
func (inv *Inventory) Merge(other *Inventory) {
	inv.Roles = append(inv.Roles, other.Roles...)
	inv.Bindings = append(inv.Bindings, other.Bindings...)
	inv.ServiceAccounts = append(inv.ServiceAccounts, other.ServiceAccounts...)
	inv.Workloads = append(inv.Workloads, other.Workloads...)
}

// selectorMatches reports whether a label selector matches labels.
func selectorMatches(sel metav1.LabelSelector, lbls map[string]string) bool {
	s, err := metav1.LabelSelectorAsSelector(&sel)
	if err != nil {
		return false
	}
	// An empty selector matches every ClusterRole, as in the aggregation
	// controller.
	return s.Matches(labels.Set(lbls))
}
