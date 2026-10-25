// Package bootstrap carries the default RBAC policy of Kubernetes v1.34.1, so
// bindings to built-in roles (cluster-admin, admin, edit, view,
// extension-apiserver-authentication-reader, ...) can be resolved without a cluster, and knows which subjects are the
// cluster's own components.
//
// The files in policy/ are copied unchanged from
// kubernetes/kubernetes v1.34.1,
// plugin/pkg/auth/authorizer/rbac/bootstrappolicy/testdata (Apache-2.0).
package bootstrap

import (
	"embed"
	"strings"
	"sync"

	"github.com/OTA-EITA/kube-rbac-paths/internal/loader"
	"github.com/OTA-EITA/kube-rbac-paths/internal/rbac"
)

// Version is the Kubernetes release the policy was taken from.
const Version = "v1.34.1"

//go:embed policy/*.yaml
var policy embed.FS

var (
	once       sync.Once
	roles      []*rbac.Role
	controller map[string]bool
)

func load() {
	for _, f := range []string{"cluster-roles.yaml", "namespace-roles.yaml"} {
		data, err := policy.ReadFile("policy/" + f)
		if err != nil {
			panic(err)
		}
		inv, err := loader.Parse(rbac.BuiltinPrefix+"kubernetes-"+Version+"/"+f, data, loader.Options{})
		if err != nil {
			panic(err)
		}
		roles = append(roles, inv.Roles...)
	}
	controller = map[string]bool{}
	for _, f := range []string{"policy/controller-role-bindings.yaml", "policy/namespace-role-bindings.yaml"} {
		data, err := policy.ReadFile(f)
		if err != nil {
			panic(err)
		}
		inv, err := loader.Parse(f, data, loader.Options{})
		if err != nil {
			panic(err)
		}
		for _, b := range inv.Bindings {
			for _, s := range b.Subjects {
				if s.Kind == rbac.KindServiceAccount && s.Namespace == "kube-system" {
					controller[s.Name] = true
				}
			}
		}
	}
}

// Roles returns fresh copies of the built-in ClusterRoles and the Roles in
// kube-system and kube-public. Copies are needed
// because aggregation is resolved per analysis.
func Roles() []*rbac.Role {
	once.Do(load)
	out := make([]*rbac.Role, 0, len(roles))
	for _, r := range roles {
		c := *r
		c.Rules = nil
		for _, rule := range r.Rules {
			nr := *rule
			nr.Origin = &c
			c.Rules = append(c.Rules, &nr)
		}
		out = append(out, &c)
	}
	return out
}

// systemGroups are groups that only the cluster's own components belong to.
var systemGroups = map[string]bool{
	"system:masters":    true,
	"system:nodes":      true,
	"system:monitoring": true,
}

// IsSystem reports whether a subject is a built-in Kubernetes identity:
// system:masters, system:nodes, system:bootstrappers*, the control plane
// users (system:kube-controller-manager, system:kube-scheduler,
// system:kube-proxy, system:node:*, ...), and the kube-system
// ServiceAccounts the default policy binds for controllers.
//
// system:anonymous, system:authenticated, system:unauthenticated and the
// system:serviceaccounts groups are not system subjects here: bindings to
// them are something the good-practices page asks operators to review.
func IsSystem(s rbac.Subject) bool {
	once.Do(load)
	switch s.Kind {
	case rbac.KindGroup:
		return systemGroups[s.Name] || strings.HasPrefix(s.Name, "system:bootstrappers")
	case rbac.KindUser:
		return strings.HasPrefix(s.Name, "system:") && s.Name != "system:anonymous"
	case rbac.KindServiceAccount:
		return s.Namespace == "kube-system" && controller[s.Name]
	}
	return false
}
