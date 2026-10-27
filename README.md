# Kubernetes manifest checker

![tests](https://github.com/twistedsol/k8s-checker/actions/workflows/tests.yml/badge.svg)

A small Python tool that reads Kubernetes YAML files and flags risky settings, with line numbers. It checks Pods and the workloads that contain a Pod (Deployment, StatefulSet, DaemonSet, ReplicaSet, Job, CronJob). It only reads files. It never connects to a cluster. Standard library only, no installs.

## Run it

```
python k8s_checker.py sample_manifests/01_risky.yml
python k8s_checker.py sample_manifests/*.yml
python k8s_checker.py sample_manifests/01_risky.yml --format json
```

On Windows I use `py -3.13` instead of `python`. A file can hold several documents separated by `---`. Other kinds (Service, ConfigMap and so on) are skipped.

Three sample files are included. They are made up for practice:

| File | What it is | Findings |
|---|---|---|
| `01_risky.yml` | A Deployment and a Pod written badly | 17 (6 high) |
| `02_okay_with_gaps.yml` | A decent Deployment that leaves gaps | 2 (0 high) |
| `03_hardened.yml` | A hardened Deployment | 0 |

## What it checks

| Rule | Severity | Flags |
|---|---|---|
| privileged | high | `privileged: true` |
| host-namespace | high | `hostNetwork`, `hostPID` or `hostIPC` set to true |
| run-as-root | high | `runAsUser: 0` (container or pod level) |
| dangerous-capability | high | `capabilities.add` with ALL, SYS_ADMIN, NET_ADMIN, SYS_MODULE and similar |
| sensitive-hostpath | high | A `hostPath` volume on `/`, `/etc`, `/root`, `/proc` and similar, or the Docker socket |
| hardcoded-secret | high | A password, token or key with its value written in `env:` |
| hostpath-volume | medium | Any other `hostPath` volume |
| allow-privilege-escalation | medium | `allowPrivilegeEscalation: false` not set |
| image-latest-tag | medium | An image with no tag or the `latest` tag |
| no-run-as-non-root | medium | Nothing says the container must run as non-root |
| no-resource-limits | medium | No `resources.limits` |
| no-readonly-root-fs | low | `readOnlyRootFilesystem: true` not set |
| no-cap-drop-all | low | Capabilities are not all dropped |

Container settings win over pod-level settings, as in Kubernetes. Init containers are checked too. Secret values are never printed. Values from `secretKeyRef` are treated as fine.

## Options

- `--format text|json` (default text)
- `--min-severity low|medium|high` hides findings below that level
- `--fail-on low|medium|high` sets which level makes the exit code 1 (default high)

Exit codes: `0` nothing at or above `--fail-on`, `1` findings, `2` bad input (missing or unreadable file, Helm template, or YAML it cannot read).

## Test it

```
python -m unittest -v
```

The tests cover the YAML reader, multi-document files, each rule and its edges, bad input, the command line and the sample files. GitHub Actions runs them on Python 3.10 and 3.12.

## How I built it

I used AI to help write the code and tests. I reused the small YAML reader from my docker-compose checker and added multi-document support. I ran everything myself and checked the sample results by hand. One test failed at first because I had forgotten to copy an error class across, which is exactly what tests are for.

## What I learned

- A Kubernetes setting that is not written in the file is often the dangerous one. If `allowPrivilegeEscalation` or `runAsNonRoot` is missing, the default is not safe.
- Container settings beat pod-level settings, so a checker has to read both and decide which one wins.
- A Kubernetes file can hold several documents separated by `---`. I had to keep the line numbers correct for each one.
- My tests caught a real bug: I had copied the reader code but left out its error class. Without tests I would have found out only when a user hit a missing file.
- "Not set in this file" is not the same as "not set in the cluster", so the README lists that honestly under Limits.
-
- ## Limits

- It reads files only. It does not know what is running in a cluster, or what policies, admission controllers or namespaces add on top.
- It does not support Helm templates (`{{ }}`), Kustomize overlays, YAML anchors or merge keys. It stops with an error instead of guessing.
- It checks only the Pod specification. It does not check Services, Ingresses, RBAC roles, NetworkPolicies or Secrets.
- Settings can come from outside the file (default service accounts, namespace Pod Security settings), so "not set" means "not set in this file".

## Next ideas

- RBAC checks (roles with `*` permissions, cluster-admin bindings).
- NetworkPolicy checks (a namespace with no policy).
- Check `automountServiceAccountToken` and liveness probes.

- 
