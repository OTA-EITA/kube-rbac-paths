// Package loader reads Kubernetes manifests (files, directories, multi-document
// YAML, kind: List, stdin) and keeps the RBAC objects, ServiceAccounts and
// workloads with the file and line they came from.
package loader

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
	rbacv1 "k8s.io/api/rbac/v1"

	"github.com/OTA-EITA/kube-rbac-paths/internal/rbac"
)

// Options control how manifests are read.
type Options struct {
	// DefaultNamespace is used for namespaced objects without
	// metadata.namespace, as kubectl does. Empty means "default".
	DefaultNamespace string
	// Stdin is read when a path is "-".
	Stdin io.Reader
}

// Warning is a file inside a directory that could not be parsed. Files named
// explicitly are errors instead, because the user asked for them.
type Warning struct {
	File string
	Err  error
}

func (w Warning) String() string { return fmt.Sprintf("%s: skipped: %v", w.File, w.Err) }

// StdinName is the file name used for objects read from stdin.
const StdinName = "stdin"

// LoadPaths reads every path. Directories are walked recursively for .yaml,
// .yml and .json files; hidden directories are skipped.
func LoadPaths(paths []string, opts Options) (*rbac.Inventory, []Warning, error) {
	inv := &rbac.Inventory{}
	var warnings []Warning
	for _, p := range paths {
		if p == "-" {
			if opts.Stdin == nil {
				return nil, nil, errors.New("stdin is not available")
			}
			data, err := io.ReadAll(opts.Stdin)
			if err != nil {
				return nil, nil, fmt.Errorf("reading stdin: %w", err)
			}
			got, err := Parse(StdinName, data, opts)
			if err != nil {
				return nil, nil, err
			}
			inv.Merge(got)
			continue
		}
		info, err := os.Stat(p)
		if err != nil {
			return nil, nil, err
		}
		if !info.IsDir() {
			got, err := parseFile(p, opts)
			if err != nil {
				return nil, nil, err
			}
			inv.Merge(got)
			continue
		}
		files, err := walk(p)
		if err != nil {
			return nil, nil, err
		}
		for _, f := range files {
			got, err := parseFile(f, opts)
			if err != nil {
				warnings = append(warnings, Warning{File: f, Err: err})
				continue
			}
			inv.Merge(got)
		}
	}
	return inv, warnings, nil
}

func walk(root string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != root && strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		switch strings.ToLower(filepath.Ext(path)) {
		case ".yaml", ".yml", ".json":
			files = append(files, path)
		}
		return nil
	})
	sort.Strings(files)
	return files, err
}

func parseFile(path string, opts Options) (*rbac.Inventory, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- reading the manifests the user named is the point
	if err != nil {
		return nil, err
	}
	return Parse(filepath.ToSlash(path), data, opts)
}

// Parse reads all YAML documents in data. name is recorded as the file of
// every object.
func Parse(name string, data []byte, opts Options) (*rbac.Inventory, error) {
	if opts.DefaultNamespace == "" {
		opts.DefaultNamespace = "default"
	}
	inv := &rbac.Inventory{}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	for {
		var doc yaml.Node
		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		if len(doc.Content) == 0 {
			continue
		}
		if err := addNode(inv, name, doc.Content[0], opts); err != nil {
			return nil, err
		}
	}
	return inv, nil
}

func addNode(inv *rbac.Inventory, file string, n *yaml.Node, opts Options) error {
	if n.Kind != yaml.MappingNode {
		return nil
	}
	kind := scalar(n, "kind")
	apiVersion := scalar(n, "apiVersion")
	src := rbac.Source{File: file, Line: n.Line}
	if strings.HasSuffix(kind, "List") {
		if items := child(n, "items"); items != nil && items.Kind == yaml.SequenceNode {
			for _, it := range items.Content {
				if err := addNode(inv, file, it, opts); err != nil {
					return err
				}
			}
		}
		return nil
	}
	group := strings.SplitN(apiVersion, "/", 2)[0]
	if !strings.Contains(apiVersion, "/") {
		group = ""
	}
	switch {
	case group == rbacv1.GroupName && (kind == "Role" || kind == "ClusterRole"):
		return addRole(inv, n, kind, src, opts)
	case group == rbacv1.GroupName && (kind == "RoleBinding" || kind == "ClusterRoleBinding"):
		return addBinding(inv, n, kind, src, opts)
	case group == "" && kind == "ServiceAccount":
		var sa struct {
			Metadata meta `json:"metadata"`
		}
		if err := decode(n, &sa, src); err != nil {
			return err
		}
		inv.ServiceAccounts = append(inv.ServiceAccounts, &rbac.ServiceAccount{
			Name: sa.Metadata.Name, Namespace: ns(sa.Metadata.Namespace, opts), Source: src,
		})
	default:
		if path, ok := podSpecPath(group, kind); ok {
			return addWorkload(inv, n, kind, path, src, opts)
		}
	}
	return nil
}

type meta struct {
	Name      string            `json:"name"`
	Namespace string            `json:"namespace"`
	Labels    map[string]string `json:"labels"`
}

func ns(v string, opts Options) string {
	if v == "" {
		return opts.DefaultNamespace
	}
	return v
}

func addRole(inv *rbac.Inventory, n *yaml.Node, kind string, src rbac.Source, opts Options) error {
	var r rbacv1.ClusterRole // a superset of Role
	if err := decode(n, &r, src); err != nil {
		return err
	}
	role := &rbac.Role{
		Kind: kind, Name: r.Name, Labels: r.Labels, Aggregation: r.AggregationRule, Source: src,
	}
	if kind == "Role" {
		role.Namespace = ns(r.Namespace, opts)
		role.Aggregation = nil
	}
	var lines []int
	if rules := child(n, "rules"); rules != nil && rules.Kind == yaml.SequenceNode {
		for _, it := range rules.Content {
			lines = append(lines, it.Line)
		}
	}
	for i, pr := range r.Rules {
		line := src.Line
		if i < len(lines) {
			line = lines[i]
		}
		role.Rules = append(role.Rules, &rbac.Rule{
			PolicyRule: pr, Origin: role, Source: rbac.Source{File: src.File, Line: line},
		})
	}
	inv.Roles = append(inv.Roles, role)
	return nil
}

func addBinding(inv *rbac.Inventory, n *yaml.Node, kind string, src rbac.Source, opts Options) error {
	var b rbacv1.RoleBinding // same shape as ClusterRoleBinding
	if err := decode(n, &b, src); err != nil {
		return err
	}
	binding := &rbac.Binding{
		Kind: kind, Name: b.Name, Labels: b.Labels, RoleRef: b.RoleRef, Source: src,
	}
	if kind == "RoleBinding" {
		binding.Namespace = ns(b.Namespace, opts)
	}
	for _, s := range b.Subjects {
		sub := rbac.Subject{Kind: s.Kind, Name: s.Name, Namespace: s.Namespace}
		if kind == "ClusterRoleBinding" && sub.Kind == rbac.KindServiceAccount && sub.Namespace == "" {
			// The API server rejects this; keep it visible in the default
			// namespace rather than dropping it.
			sub.Namespace = opts.DefaultNamespace
		}
		binding.Subjects = append(binding.Subjects, rbac.NormalizeSubject(sub, binding.Namespace))
	}
	inv.Bindings = append(inv.Bindings, binding)
	return nil
}

// podSpecPath returns where the Pod spec lives in a workload kind.
func podSpecPath(group, kind string) ([]string, bool) {
	switch {
	case group == "" && kind == "Pod":
		return []string{"spec"}, true
	case group == "" && kind == "ReplicationController",
		group == "apps" && (kind == "Deployment" || kind == "DaemonSet" || kind == "StatefulSet" || kind == "ReplicaSet"),
		group == "batch" && kind == "Job":
		return []string{"spec", "template", "spec"}, true
	case group == "batch" && kind == "CronJob":
		return []string{"spec", "jobTemplate", "spec", "template", "spec"}, true
	}
	return nil, false
}

func addWorkload(inv *rbac.Inventory, n *yaml.Node, kind string, path []string, src rbac.Source, opts Options) error {
	var obj struct {
		Metadata meta `json:"metadata"`
	}
	if err := decode(n, &obj, src); err != nil {
		return err
	}
	spec := n
	for _, k := range path {
		if spec = child(spec, k); spec == nil {
			break
		}
	}
	sa := ""
	if spec != nil {
		sa = scalar(spec, "serviceAccountName")
		if sa == "" {
			sa = scalar(spec, "serviceAccount")
		}
	}
	if sa == "" {
		sa = "default"
	}
	inv.Workloads = append(inv.Workloads, &rbac.Workload{
		Kind: kind, Name: obj.Metadata.Name, Namespace: ns(obj.Metadata.Namespace, opts), ServiceAccount: sa, Source: src,
	})
	return nil
}

// decode converts a YAML node to a typed object through JSON, so the json
// tags of the Kubernetes API types apply.
func decode(n *yaml.Node, out any, src rbac.Source) error {
	var v any
	if err := n.Decode(&v); err != nil {
		return fmt.Errorf("%s: %w", src, err)
	}
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("%s: %w", src, err)
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("%s: %w", src, err)
	}
	return nil
}

func child(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

func scalar(n *yaml.Node, key string) string {
	c := child(n, key)
	if c == nil || c.Kind != yaml.ScalarNode {
		return ""
	}
	return c.Value
}
