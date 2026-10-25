// Command kube-rbac-paths audits Kubernetes RBAC manifests for the privilege
// escalation risks in the Kubernetes RBAC good-practices guide, and shows
// which subjects end up with cluster-admin-equivalent permissions and why.
// It reads manifests only; it never contacts a cluster.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/OTA-EITA/kube-rbac-paths/internal/bootstrap"
	"github.com/OTA-EITA/kube-rbac-paths/internal/check"
	"github.com/OTA-EITA/kube-rbac-paths/internal/loader"
	"github.com/OTA-EITA/kube-rbac-paths/internal/rbac"
	"github.com/OTA-EITA/kube-rbac-paths/internal/report"
)

var version = "dev"

const usage = `kube-rbac-paths audits Kubernetes RBAC manifests (offline, read-only).

Usage:
  kube-rbac-paths [flags] PATH...                     audit files, directories, or - for stdin
  kube-rbac-paths diff --base DIR --head DIR [flags]  report only findings new in head

Flags:
`

// Exit codes.
const (
	exitOK       = 0
	exitFindings = 1
	exitError    = 2
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

type config struct {
	format        string
	failOn        string
	namespace     string
	includeSystem bool
	noBuiltin     bool
	listChecks    bool
	showVersion   bool
	base, head    string
}

func newFlagSet(cfg *config, diff bool, stderr io.Writer) *flag.FlagSet {
	name := "kube-rbac-paths"
	if diff {
		name += " diff"
	}
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&cfg.format, "format", "text", "output format: "+strings.Join(report.Formats, ", "))
	fs.StringVar(&cfg.failOn, "fail-on", "medium", "exit 1 on findings at least this severe: high, medium, low or none")
	fs.StringVar(&cfg.namespace, "namespace", "default", "namespace for namespaced objects without metadata.namespace")
	fs.BoolVar(&cfg.includeSystem, "include-system", false, "also report built-in subjects (system:masters, system:nodes, control plane users, kube-system controllers)")
	fs.BoolVar(&cfg.noBuiltin, "no-builtin-roles", false, "do not load the Kubernetes "+bootstrap.Version+" default ClusterRoles (cluster-admin, admin, edit, view, ...)")
	fs.BoolVar(&cfg.listChecks, "list-checks", false, "print the checks and exit")
	fs.BoolVar(&cfg.showVersion, "version", false, "print the version and exit")
	if diff {
		fs.StringVar(&cfg.base, "base", "", "manifests before the change (file or directory)")
		fs.StringVar(&cfg.head, "head", "", "manifests after the change (file or directory)")
	}
	fs.Usage = func() {
		fmt.Fprint(stderr, usage)
		fs.PrintDefaults()
	}
	return fs
}

// parse accepts flags before and after positional arguments.
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return pos, nil
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	cfg := &config{}
	diff := len(args) > 0 && args[0] == "diff"
	if diff {
		args = args[1:]
	}
	fs := newFlagSet(cfg, diff, stderr)
	paths, err := parse(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitError
	}
	if cfg.showVersion {
		fmt.Fprintln(stdout, version)
		return exitOK
	}
	if cfg.listChecks {
		listChecks(stdout)
		return exitOK
	}
	failOn, err := check.ParseSeverity(cfg.failOn)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return exitError
	}
	if !validFormat(cfg.format) {
		fmt.Fprintf(stderr, "error: unknown format %q (want %s)\n", cfg.format, strings.Join(report.Formats, ", "))
		return exitError
	}

	var res check.Result
	if diff {
		if cfg.base == "" || cfg.head == "" || len(paths) > 0 {
			fmt.Fprintln(stderr, "error: diff needs --base and --head and no other paths")
			return exitError
		}
		base, err := audit([]string{cfg.base}, cfg, stdin, stderr)
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return exitError
		}
		head, err := audit([]string{cfg.head}, cfg, stdin, stderr)
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return exitError
		}
		res = check.Diff(base, head)
	} else {
		if len(paths) == 0 {
			fs.Usage()
			return exitError
		}
		res, err = audit(paths, cfg, stdin, stderr)
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return exitError
		}
	}
	if err := report.Write(stdout, cfg.format, res, report.Meta{Version: version, Diff: diff}); err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return exitError
	}
	if failOn != check.None && res.Count(failOn) > 0 {
		return exitFindings
	}
	return exitOK
}

func validFormat(f string) bool {
	for _, v := range report.Formats {
		if v == f {
			return true
		}
	}
	return false
}

func audit(paths []string, cfg *config, stdin io.Reader, stderr io.Writer) (check.Result, error) {
	inv, warnings, err := loader.LoadPaths(paths, loader.Options{DefaultNamespace: cfg.namespace, Stdin: stdin})
	if err != nil {
		return check.Result{}, err
	}
	for _, w := range warnings {
		fmt.Fprintln(stderr, "warning:", w)
	}
	if !cfg.noBuiltin {
		inv.Merge(&rbac.Inventory{Roles: bootstrap.Roles()})
	}
	return check.Run(rbac.Build(inv), check.Options{IncludeSystem: cfg.includeSystem}), nil
}

func listChecks(w io.Writer) {
	for _, c := range check.Checks {
		fmt.Fprintf(w, "%s  %s\n    severity: %s\n    why: %s\n    fix: %s\n    see: %s\n\n", c.ID, c.Title, c.Severities, c.Why, c.Fix, c.URL())
	}
}
