# kube-rbac-paths

[![ci](https://github.com/OTA-EITA/kube-rbac-paths/actions/workflows/ci.yml/badge.svg)](https://github.com/OTA-EITA/kube-rbac-paths/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/OTA-EITA/kube-rbac-paths/badge)](https://securityscorecards.dev/viewer/?uri=github.com/OTA-EITA/kube-rbac-paths)

**Find out which identities in your Kubernetes manifests end up with cluster-admin, and which bindings get them there, before the manifests reach a cluster.**

kube-rbac-paths is a read-only RBAC audit for cluster operators and CI. It reads Roles, ClusterRoles, bindings, ServiceAccounts and workloads from YAML (including `helm template` and `kustomize build` output), works out what every User, Group and ServiceAccount can effectively do, and reports the permissions that the Kubernetes [RBAC Good Practices](https://kubernetes.io/docs/concepts/security/rbac-good-practices/) page lists as privilege escalation risks. It never talks to a cluster.

Two things it does that a rule-by-rule review misses:

- **Paths through ServiceAccounts.** If a subject can create Pods, change a workload's Pod template, change a running Pod, request tokens or impersonate in a namespace where a powerful ServiceAccount lives, it can act as that ServiceAccount. kube-rbac-paths follows those steps, through up to four ServiceAccounts, and shows the shortest chain with file and line numbers.
- **Pull request diffs.** `kube-rbac-paths diff --base old/ --head new/` reports only what the change adds, so a pull request is judged on its own RBAC changes.

Real output on Argo CD's `manifests/install.yaml` (aca50bb), trimmed:

```text
$ kube-rbac-paths --namespace argocd manifests/install.yaml
Effective cluster-admin (2)

  ServiceAccount argocd/argocd-application-controller
    holds every verb on every resource in every API group, cluster-wide
      ClusterRoleBinding argocd-application-controller binds ClusterRole argocd-application-controller to ServiceAccount argocd/argocd-application-controller  manifests/install.yaml:34487
      ClusterRole argocd-application-controller  manifests/install.yaml:34238
      rule verbs=[*] apiGroups=[*] resources=[*]  manifests/install.yaml:34247
      runs as it: StatefulSet argocd/argocd-application-controller  manifests/install.yaml:36616

  ServiceAccount argocd/argocd-server
    can create jobs in every namespace, including argocd, where ServiceAccount argocd/argocd-application-controller lives, and ServiceAccount argocd/argocd-application-controller holds every verb on every resource in every API group, cluster-wide. It can also patch replicationcontrollers, deployments, daemonsets and 3 more in every namespace, including argocd, to set serviceAccountName in their Pod template to that ServiceAccount; patch pods, pods/ephemeralcontainers of StatefulSet argocd/argocd-application-controller to replace a container image or add an ephemeral container
      ClusterRoleBinding argocd-server binds ClusterRole argocd-server to ServiceAccount argocd/argocd-server  manifests/install.yaml:34521
      ClusterRole argocd-server  manifests/install.yaml:34333
      rule verbs=[create] apiGroups=[batch] resources=[jobs]  manifests/install.yaml:34378
      rule verbs=[delete,get,patch] apiGroups=[*] resources=[*]  manifests/install.yaml:34342
      StatefulSet argocd/argocd-application-controller runs as ServiceAccount argocd/argocd-application-controller  manifests/install.yaml:36616
      ServiceAccount argocd/argocd-application-controller  manifests/install.yaml:33920
      ClusterRoleBinding argocd-application-controller binds ClusterRole argocd-application-controller to ServiceAccount argocd/argocd-application-controller  manifests/install.yaml:34487
      ClusterRole argocd-application-controller  manifests/install.yaml:34238
      rule verbs=[*] apiGroups=[*] resources=[*]  manifests/install.yaml:34247
      runs as it: Deployment argocd/argocd-server  manifests/install.yaml:36063

Findings

manifests/install.yaml:34487  HIGH   KRP014  ServiceAccount argocd/argocd-application-controller effectively holds cluster-admin-equivalent permissions because it holds every verb on every resource in every API group, cluster-wide
    why: the subject can do anything in the cluster, directly or through a chain of up to four ServiceAccounts it can act as.
    fix: break the chain shown in the evidence: narrow the role, scope the binding to a namespace, or separate the ServiceAccount.
    see: https://kubernetes.io/docs/concepts/security/rbac-good-practices/#privilege-escalation-risks

…

manifests/install.yaml:34521  HIGH   KRP007  ServiceAccount argocd/argocd-server can get, patch, delete nodes/proxy cluster-wide
      ClusterRoleBinding argocd-server binds ClusterRole argocd-server to ServiceAccount argocd/argocd-server  manifests/install.yaml:34521
      ClusterRole argocd-server  manifests/install.yaml:34333
      rule verbs=[delete,get,patch] apiGroups=[*] resources=[*]  manifests/install.yaml:34342
    why: nodes/proxy reaches the kubelet API, which can exec into every Pod on the node; get is enough and the calls bypass audit logging and admission control.
    fix: use nodes/metrics, nodes/stats or nodes/log for monitoring instead of nodes/proxy.
    see: https://kubernetes.io/docs/concepts/security/rbac-good-practices/#access-to-proxy-subresource-of-nodes
…
6 subject(s) audited, 2 cluster-admin-equivalent, 14 finding(s): 6 high, 7 medium, 1 low
```

The application controller's rights are by design: Argo CD's [installation guide](https://argo-cd.readthedocs.io/en/stable/operator-manual/installation/) describes `install.yaml` as the "installation with cluster-admin access". The second entry is the kind of thing this tool is for: `argocd-server` is not bound to anything like cluster-admin, but its ClusterRole lets it create Jobs in any namespace, including `argocd`, and a Job there can run as the application controller. Removing `create` on Jobs would not close the path: its `patch` on `*` also lets it point any Deployment or StatefulSet at the controller's ServiceAccount, or replace the image of the controller's own Pods.

## Tested on real manifests

The numbers below are the actual output of this version. The checks were adjusted against these runs (for example, a namespaced finding is dropped when the same subject already has the same verbs cluster-wide, a cluster-admin-equivalent subject is not also listed for every individual permission that implies, and workload modification is not reported where the subject can already create workloads).

| Input | RBAC objects | Result |
| --- | --- | --- |
| [Argo CD](https://github.com/argoproj/argo-cd) `manifests/install.yaml` (aca50bb), `--namespace argocd` | 18 | 2 cluster-admin-equivalent: `argocd-application-controller` (`*` on `*`, intended) and `argocd-server` through a Job running as the controller; the same entry now also lists its `patch` on `*` as two further ways to run as the controller (Pod templates of Deployments and the other controllers, and the controller's own Pods). 14 findings: 6 high, 7 medium, 1 low. `argocd-server`'s `delete,get,patch` on `*` also gives it nodes/proxy, webhook configurations, CSR approval and namespace labels |
| Argo CD `manifests/namespace-install.yaml` (aca50bb), `--namespace argocd` | 12 | No admin path. 6 findings: 5 ServiceAccounts read Secrets in `argocd` (medium), redis reads one named Secret (low) |
| [cert-manager](https://github.com/cert-manager/cert-manager) release `cert-manager.yaml` v1.21.3 | 29 | No admin path. 6 findings: 4 high, 1 medium, 1 low. The controller and cainjector read Secrets in every namespace; cainjector can update every webhook configuration (it injects CA bundles, so this is by design); the controller can create Pods in every namespace (ACME solvers), which also lets it run a Pod as cainjector (KRP005) |
| [ingress-nginx](https://github.com/kubernetes/ingress-nginx) `deploy/static/provider/cloud/deploy.yaml` (dbb11b9) | 8 | No admin path. 4 findings: 2 high (controller lists and watches Secrets in every namespace; the admission job can update every ValidatingWebhookConfiguration), 2 medium |
| [kube-prometheus](https://github.com/prometheus-operator/kube-prometheus) `manifests/` (f71fb6c) | 18 | No admin path. 3 findings: kube-state-metrics and prometheus-operator read Secrets in every namespace (high), prometheus-operator creates StatefulSets in every namespace (medium) |
| Kubernetes v1.34.1 default policy (bootstrap roles and bindings) | 6 files | 0 findings, 48 built-in subjects excluded. With `--include-system`: 12 cluster-admin-equivalent, among them `system:masters`, the `clusterrole-aggregation-controller` ServiceAccount (escalate + update on its own ClusterRole), and the `generic-garbage-collector` ServiceAccount, whose `update,patch` on `*` lets it switch a workload's Pod template to `clusterrole-aggregation-controller`; 116 findings (the garbage collector's KRP014, KRP016 and one KRP005 to `persistent-volume-binder`). All 10 admin paths through a ServiceAccount are one step long, and no KRP005 needs a longer chain |

The cert-manager checkout (fe479f2) only contains the Helm chart; it was not rendered for this table, so the release YAML is used instead.

## Checks

Every check follows a section of the [RBAC Good Practices](https://kubernetes.io/docs/concepts/security/rbac-good-practices/) page. "Cluster-wide" means a ClusterRoleBinding; a RoleBinding only ever reaches its own namespace, and rules with `resourceNames` are reported as narrower (or not at all where they grant nothing, such as `create` with `resourceNames`).

| ID | Severity | Finding | Source |
| --- | --- | --- | --- |
| KRP001 | high (ClusterRoleBinding), medium (RoleBinding) | Binding to `cluster-admin` | [Least privilege](https://kubernetes.io/docs/concepts/security/rbac-good-practices/#least-privilege) |
| KRP002 | high (`*` on `*` cluster-wide), medium | Wildcard verbs or resources in a role you wrote | [Least privilege](https://kubernetes.io/docs/concepts/security/rbac-good-practices/#least-privilege) |
| KRP003 | high (all namespaces), medium (one), low (named) | `get`, `list` or `watch` on Secrets | [Listing secrets](https://kubernetes.io/docs/concepts/security/rbac-good-practices/#listing-secrets) |
| KRP004 | medium (all namespaces), low (one) | Can create Pods, Deployments, DaemonSets, StatefulSets, ReplicaSets, ReplicationControllers, Jobs or CronJobs | [Workload creation](https://kubernetes.io/docs/concepts/security/rbac-good-practices/#workload-creation) |
| KRP005 | the highest severity of the target's own findings | Can act as another ServiceAccount that holds more, directly or through up to four ServiceAccounts (see below) | [Workload creation](https://kubernetes.io/docs/concepts/security/rbac-good-practices/#workload-creation), [Token request](https://kubernetes.io/docs/concepts/security/rbac-good-practices/#token-request) |
| KRP006 | medium | Can create PersistentVolumes (hostPath) | [Persistent volume creation](https://kubernetes.io/docs/concepts/security/rbac-good-practices/#persistent-volume-creation) |
| KRP007 | high | Any access to `nodes/proxy` (`get` is enough) | [Access to proxy subresource of Nodes](https://kubernetes.io/docs/concepts/security/rbac-good-practices/#access-to-proxy-subresource-of-nodes) |
| KRP008 | high (cluster-wide), medium, low (named) | `escalate` or `bind` on roles or clusterroles | [Escalate verb](https://kubernetes.io/docs/concepts/security/rbac-good-practices/#escalate-verb), [Bind verb](https://kubernetes.io/docs/concepts/security/rbac-good-practices/#bind-verb) |
| KRP009 | high (cluster-wide), medium | `impersonate` on users, groups, serviceaccounts or uids | [Impersonate verb](https://kubernetes.io/docs/concepts/security/rbac-good-practices/#impersonate-verb) |
| KRP010 | medium | Can approve CertificateSigningRequests | [CSRs and certificate issuing](https://kubernetes.io/docs/concepts/security/rbac-good-practices/#csrs-and-certificate-issuing) |
| KRP011 | high (all namespaces), medium (one), low (named) | `create` on `serviceaccounts/token` | [Token request](https://kubernetes.io/docs/concepts/security/rbac-good-practices/#token-request) |
| KRP012 | high, low (named only) | Can create, change or delete admission webhook configurations | [Control admission webhooks](https://kubernetes.io/docs/concepts/security/rbac-good-practices/#control-admission-webhooks) |
| KRP013 | medium, low (named) | `patch` or `update` on Namespaces (a RoleBinding reaches its own Namespace) | [Namespace modification](https://kubernetes.io/docs/concepts/security/rbac-good-practices/#namespace-modification) |
| KRP014 | high | Effective cluster-admin, with the chain as evidence | [Privilege escalation risks](https://kubernetes.io/docs/concepts/security/rbac-good-practices/#privilege-escalation-risks) |
| KRP015 | high (`system:unauthenticated`, `system:anonymous`), medium | Binding to `system:authenticated`, `system:unauthenticated` or all ServiceAccounts | [Hardening](https://kubernetes.io/docs/concepts/security/rbac-good-practices/#hardening) |
| KRP016 | medium (all namespaces), low (one, or named objects) | `update` or `patch` on Deployments, DaemonSets, StatefulSets, ReplicaSets, ReplicationControllers, CronJobs, Pods or `pods/ephemeralcontainers`; not reported where the subject can already create workloads | [Workload creation](https://kubernetes.io/docs/concepts/security/rbac-good-practices/#workload-creation), [Pod templates](https://kubernetes.io/docs/concepts/workloads/pods/#pod-templates), [Pod update and replacement](https://kubernetes.io/docs/concepts/workloads/pods/#pod-update-and-replacement) |

`kube-rbac-paths --list-checks` prints the same list with the "why" and "how to reduce" text.

A subject is reported as cluster-admin-equivalent (KRP014) when, cluster-wide, it:

- holds `*` verbs on `*` resources in `*` API groups;
- can create ClusterRoleBindings and has `bind` on ClusterRole `cluster-admin`;
- has `escalate` and `update`/`patch` on a ClusterRole that is already bound to it;
- can impersonate the `system:masters` group;
- can create CSRs, approve them and `approve` for the `kubernetes.io/kube-apiserver-client` signer;
- or reaches a ServiceAccount that matches one of the above through a chain of up to four ServiceAccounts.

A cluster-admin-equivalent subject gets KRP014 instead of one finding per permission. When the path goes through another ServiceAccount, the subject's own findings are still listed, because closing that one path would not remove them.

### Acting as another ServiceAccount

A subject can act as a ServiceAccount when it can, in the ServiceAccount's namespace (or cluster-wide):

- **create a workload** (Pod, Deployment, DaemonSet, StatefulSet, ReplicaSet, ReplicationController, Job or CronJob), which can run as any ServiceAccount there. This is the good-practices page's [Workload creation](https://kubernetes.io/docs/concepts/security/rbac-good-practices/#workload-creation) risk.
- **change a workload's Pod template** (`update` or `patch` on Deployments, DaemonSets, StatefulSets, ReplicaSets, ReplicationControllers or CronJobs). The controller creates new Pods from the changed template ([Pod templates](https://kubernetes.io/docs/concepts/workloads/pods/#pod-templates)), so the template can name any ServiceAccount in the namespace, even when `resourceNames` limits the subject to one workload. The good-practices page only names creation; this is the same effect through an existing object. Jobs are left out: their Pod template is immutable apart from scheduling directives.
- **change a running Pod** (`update` or `patch` on `pods`, or on `pods/ephemeralcontainers`). A Pod's `serviceAccountName` cannot change, but its container images can, and an ephemeral container can be added ([Pod update and replacement](https://kubernetes.io/docs/concepts/workloads/pods/#pod-update-and-replacement)); either runs code with the Pod's ServiceAccount. This only reaches ServiceAccounts that a workload in the inputs runs as, and with `resourceNames` only bare Pods of those names.
- **request a token** for it (`create` on `serviceaccounts/token`) or **impersonate** it.

The search runs breadth first from every subject, through up to four ServiceAccounts and never through the same one twice, so each ServiceAccount is shown with its shortest chain; the evidence lists the bindings and rules of every step. It stops at the first cluster-admin-equivalent ServiceAccount (KRP014, with the chain under `chain` in JSON). A ServiceAccount further than one step away gets a KRP005 only if it holds something that neither the subject nor a ServiceAccount on a shorter chain already holds. Workload creation, workload modification and token creation on the target are followed as further steps rather than listed as what it holds.

### What it resolves

- Bindings to the built-in roles (`cluster-admin`, `admin`, `edit`, `view`, `extension-apiserver-authentication-reader`, ...) using the Kubernetes v1.34.1 default policy, which is embedded. `--no-builtin-roles` turns that off.
- `aggregationRule`: a ClusterRole gets the union of the ClusterRoles its selectors match, recursively, as the aggregation controller does. So a chart that labels a role `aggregate-to-view` and grants Secrets in it shows up on everyone bound to `view`.
- ServiceAccounts get the grants of `system:serviceaccounts`, `system:serviceaccounts:<namespace>` and `system:authenticated`. A User named `system:serviceaccount:<ns>:<name>` is treated as that ServiceAccount.
- Workloads (Pod, Deployment, DaemonSet, StatefulSet, ReplicaSet, ReplicationController, Job, CronJob) tell it which ServiceAccount runs where; it is shown as "runs as it", and it decides which ServiceAccounts a subject that can change running Pods can reach.

Built-in identities are left out unless `--include-system` is set: `system:masters`, `system:nodes`, `system:monitoring`, `system:bootstrappers*`, Users named `system:*` (the control plane, `system:node:*`), the kube-system controller ServiceAccounts from the default policy, and bindings labeled `kubernetes.io/bootstrapping: rbac-defaults`. `system:anonymous`, `system:authenticated` and `system:unauthenticated` are always audited. The built-in ServiceAccounts are still followed as targets: a user who can create Pods in `kube-system` is reported.

### Limits

- It sees only the manifests you give it. A binding to a role that is not in the inputs (and not built in) is listed as a note and grants nothing in the analysis.
- Chains stop after four ServiceAccounts, and only the shortest chain to each ServiceAccount is shown. Once an admin-equivalent ServiceAccount is found, longer chains from the same subject are not searched.
- The steps between ServiceAccounts use each ServiceAccount's own bindings. Grants to the groups it belongs to (`system:serviceaccounts`, `system:serviceaccounts:<namespace>`, `system:authenticated`) count towards what it holds, not towards the steps it can take; those grants are reported on the group.
- Running code in an existing Pod through `pods/exec`, `pods/attach` or `nodes/proxy` is not followed as a step (nodes/proxy is still reported as KRP007). Changing a running Pod only reaches ServiceAccounts that a workload in the inputs runs as.
- It does not know Pod Security admission, admission policies or webhooks that would block a Pod, so a path it reports may be closed by those in a real cluster.
- Custom resources are treated as namespaced.
- Namespaced objects without `metadata.namespace` are placed in `--namespace` (default `default`), as `kubectl apply` would.

## Usage

```sh
go install github.com/OTA-EITA/kube-rbac-paths/cmd/kube-rbac-paths@latest

kube-rbac-paths [flags] PATH...                     # files, directories, or - for stdin
kube-rbac-paths diff --base DIR --head DIR [flags]  # only findings new in head

helm template my-release ./chart | kube-rbac-paths --namespace my-ns -
kubectl kustomize overlays/prod | kube-rbac-paths -
```

Directories are searched recursively for `.yaml`, `.yml` and `.json`; hidden directories are skipped, and a file that does not parse (for example an unrendered Helm template) is skipped with a warning. Multi-document YAML and `kind: List` are read.

| Flag | Default | |
| --- | --- | --- |
| `--format` | `text` | `text`, `json`, `markdown` or `sarif` (SARIF 2.1.0 with file and line, and the evidence as related locations) |
| `--fail-on` | `medium` | Exit 1 on findings at least this severe: `high`, `medium`, `low` or `none` |
| `--namespace` | `default` | Namespace for namespaced objects without one |
| `--include-system` | `false` | Also report the cluster's built-in identities |
| `--no-builtin-roles` | `false` | Do not load the Kubernetes default roles |
| `--list-checks` | | Print the checks |
| `--version` | | Print the version |

Exit codes: 0 no findings at or above `--fail-on`, 1 findings, 2 usage or input error.

In diff mode, findings are matched by a fingerprint of check, subject and scope (not file or line), so moving or reformatting manifests does not produce new findings.

### GitHub Actions

```yaml
on: pull_request
permissions:
  contents: read
  security-events: write
jobs:
  rbac:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
        with:
          persist-credentials: false
      - uses: actions/checkout@v5
        with:
          persist-credentials: false
          ref: ${{ github.base_ref }}
          path: .base
      # Render charts here if needed, e.g. helm template into two directories.
      - uses: OTA-EITA/kube-rbac-paths@v0.1.0 # pin to a commit SHA in real use
        id: rbac
        with:
          base: .base/deploy
          head: deploy
          fail-on: high
      - uses: github/codeql-action/upload-sarif@v4
        if: always()
        with:
          sarif_file: ${{ steps.rbac.outputs.sarif-file }}
          category: kube-rbac-paths
```

The action runs diff mode, writes a Markdown summary to the job summary, and sets the `sarif-file` and `findings` outputs. Inputs: `base`, `head`, `fail-on` (default `medium`), `namespace`, `include-system`, `sarif-file`. Keep `head` a path inside the repository so code scanning can place the annotations.

## Related work

- [rbac-police](https://github.com/PaloAltoNetworks/rbac-police) (Palo Alto Networks): collects the permissions of ServiceAccounts, pods, nodes, users and groups from a cluster and evaluates them with Rego policies; its library of more than 20 policies covers many escalation paths.
- [KubiScan](https://github.com/cyberark/KubiScan) (CyberArk): scans a cluster for risky RBAC permissions.
- [kubectl-who-can](https://github.com/aquasecurity/kubectl-who-can) (Aqua Security): shows which subjects can perform a verb on a resource in a cluster.
- [rakkess](https://github.com/corneliusweig/rakkess): shows an access matrix of server resources for a user or ServiceAccount.
- [krane](https://github.com/appvia/krane) (Appvia): RBAC risk rules and a dashboard, against a cluster or, in CI, against a directory of exported `roles`, `clusterroles`, `rolebindings` and `clusterrolebindings` files.
- [rbac-tool](https://github.com/alcideio/rbac-tool) (Alcide): visualizes, analyzes, looks up and generates RBAC policies for a cluster.

Most of these read a live cluster, which sees bindings that are not in any repository; kube-rbac-paths does not replace that. What it does differently: it reads manifests as they are (multi-document files, `helm template` output, workloads included) with no cluster or credentials, follows the step from workload creation or token requests to the ServiceAccounts in that namespace, has a pull request diff mode that reports only new findings, and writes SARIF with file and line for code scanning.

## Development

```sh
make test    # go test -race
make cover
make lint    # golangci-lint v2.15.0
make build
```

Dependencies are `k8s.io/api` and `k8s.io/apimachinery` v0.34.1 (types only, no client-go) and `gopkg.in/yaml.v3` v3.0.1. Workflows are pinned to commit SHAs and checked with [gha-guard](https://github.com/OTA-EITA/gha-guard).

## License

MIT. `internal/bootstrap/policy/` holds unmodified copies of the Kubernetes v1.34.1 default RBAC policy test data (`plugin/pkg/auth/authorizer/rbac/bootstrappolicy/testdata`), which is Apache-2.0 licensed by The Kubernetes Authors; the license text is in [`internal/bootstrap/policy/LICENSE`](internal/bootstrap/policy/LICENSE).
