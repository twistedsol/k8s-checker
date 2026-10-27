#!/usr/bin/env python3
"""Kubernetes manifest checker.

Reads Kubernetes YAML files (Pod, Deployment, StatefulSet, DaemonSet, ReplicaSet,
Job, CronJob) and flags risky settings, with line numbers. It only reads the
files. It never connects to a cluster.

It uses a small built-in reader for plain YAML (maps, lists, quotes, comments,
several documents separated by ---). It does not support anchors, merge keys or
Helm templates ({{ }}); it says so instead of guessing.

Exit codes: 0 = nothing at or above --fail-on, 1 = findings, 2 = bad input.
"""
import argparse
import json
import re
import sys

SEVERITIES = {"low": 1, "medium": 2, "high": 3}

WORKLOADS = {"Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob"}
DANGEROUS_CAPS = {"ALL", "SYS_ADMIN", "SYS_MODULE", "SYS_PTRACE", "SYS_RAWIO", "DAC_READ_SEARCH", "NET_ADMIN"}
SENSITIVE_PATHS = ("/", "/etc", "/root", "/proc", "/sys", "/boot", "/dev", "/var/lib/kubelet", "/var/lib/docker")
SECRET_NAME = re.compile(r"(PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY|CREDENTIAL)", re.I)
KEY_VALUE = re.compile(r"^(\"[^\"]*\"|'[^']*'|[^\s:#\"'][^:#]*?)\s*:(?:\s+(.*))?$")
BLOCK_SCALAR = re.compile(r"^[|>][+-]?\d*$")
TRUE_VALUES = {"true", "yes", "on"}

class ManifestError(Exception):
    """Raised when a manifest file cannot be used."""


# ---------- reading the file ----------

def load_manifest(path):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read().splitlines()
    except FileNotFoundError:
        raise ManifestError("file not found: %s" % path)
    except UnicodeDecodeError:
        raise ManifestError("not a text file: %s" % path)
    except OSError as exc:
        raise ManifestError("cannot read %s: %s" % (path, exc.strerror))


def strip_comment(text):
    """Remove a trailing # comment that is not inside quotes."""
    quote = None
    for i, ch in enumerate(text):
        if quote:
            if ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
        elif ch == "#" and (i == 0 or text[i - 1] in " \t"):
            return text[:i].rstrip()
    return text.rstrip()


def unquote(text):
    text = text.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        return text[1:-1]
    return text


def tokenize(lines):
    """Return [indent, text, line_number] for each meaningful line.
    Lines inside block scalars (| or >) are dropped but remembered as the value."""
    tokens = []
    i = 0
    while i < len(lines):
        raw = lines[i]
        if "\t" in raw[: len(raw) - len(raw.lstrip())]:
            raise ManifestError("line %d uses a tab for indentation; YAML needs spaces" % (i + 1))
        text = strip_comment(raw)
        if not text.strip() or text.strip() in ("---", "..."):
            i += 1
            continue
        indent = len(text) - len(text.lstrip(" "))
        body = text.strip()
        tokens.append([indent, body, i + 1])
        value = body.split(":", 1)[1].strip() if ":" in body else ""
        if body.startswith("- "):
            value = body[2:].split(":", 1)[1].strip() if ":" in body[2:] else ""
        if BLOCK_SCALAR.match(value):
            j = i + 1
            while j < len(lines) and (not lines[j].strip() or len(lines[j]) - len(lines[j].lstrip(" ")) > indent):
                j += 1
            tokens[-1][1] = body[: len(body) - len(value)] + "<block>"
            i = j
            continue
        i += 1
    return tokens


def parse_inline_list(text, line):
    inner = text.strip()[1:-1]
    return [(line, unquote(p)) for p in inner.split(",") if p.strip()]


def scalar_or_inline(text, line):
    text = text.strip()
    if text.startswith("[") and text.endswith("]"):
        return parse_inline_list(text, line)
    if text.startswith("{"):
        return text
    return unquote(text)


def parse_block(tokens, pos, indent):
    """Parse a map or a list starting at tokens[pos]. Returns (value, new_pos).
    A map is {key: (line, value)}; a list is [(line, value)]."""
    if tokens[pos][1] == "-" or tokens[pos][1].startswith("- "):
        return parse_list(tokens, pos, indent)
    return parse_map(tokens, pos, indent)


def parse_map(tokens, pos, indent):
    result = {}
    while pos < len(tokens) and tokens[pos][0] == indent:
        _, body, line = tokens[pos]
        if body == "-" or body.startswith("- "):
            break
        match = KEY_VALUE.match(body)
        if not match:
            raise ManifestError("line %d is not understood: %s" % (line, body))
        key = unquote(match.group(1))
        value = (match.group(2) or "").strip()
        pos += 1
        if value.startswith("&") or value.startswith("*") or key == "<<":
            raise ManifestError("line %d uses YAML anchors or merge keys, which this tool does not support" % line)
        if value == "<block>":
            result[key] = (line, "<block>")
        elif value:
            result[key] = (line, scalar_or_inline(value, line))
        elif pos < len(tokens) and (
            tokens[pos][0] > indent
            or (tokens[pos][0] == indent and (tokens[pos][1] == "-" or tokens[pos][1].startswith("- ")))
        ):
            child, pos = parse_block(tokens, pos, tokens[pos][0])
            result[key] = (line, child)
        else:
            result[key] = (line, None)
    return result, pos


def parse_list(tokens, pos, indent):
    result = []
    while pos < len(tokens) and tokens[pos][0] == indent and (tokens[pos][1] == "-" or tokens[pos][1].startswith("- ")):
        _, body, line = tokens[pos]
        content = body[1:].lstrip()
        if not content:
            pos += 1
            if pos < len(tokens) and tokens[pos][0] > indent:
                child, pos = parse_block(tokens, pos, tokens[pos][0])
                result.append((line, child))
            else:
                result.append((line, None))
        elif KEY_VALUE.match(content) and content[0] not in "\"'[{" and not re.match(r"^[^\s:]+:[^\s]", content):
            offset = len(body) - len(content)
            tokens[pos] = [indent + offset, content, line]
            child, pos = parse_map(tokens, pos, indent + offset)
            result.append((line, child))
        else:
            result.append((line, scalar_or_inline(content, line)))
            pos += 1
    return result, pos


def parse_document(lines):
    tokens = tokenize(lines)
    if not tokens:
        return {}
    root, pos = parse_block(tokens, 0, tokens[0][0])
    if pos < len(tokens):
        raise ManifestError("line %d could not be read (check the indentation)" % tokens[pos][2])
    if not isinstance(root, dict):
        raise ManifestError("this does not look like a compose file (no top-level keys)")
    return root




def split_documents(lines):
    """Split on lines that are exactly '---'. Each document keeps its original line
    numbers (other lines are blanked), so findings point at the right line."""
    ranges, start = [], 0
    for i, line in enumerate(lines):
        if line.strip() == "---":
            ranges.append((start, i))
            start = i + 1
    ranges.append((start, len(lines)))
    docs = []
    for a, b in ranges:
        if any(l.strip() and not l.lstrip().startswith("#") for l in lines[a:b]):
            docs.append([l if a <= n < b else "" for n, l in enumerate(lines)])
    return docs


# ---------- the rules ----------

def _finding(rule, severity, line, message, fix):
    return {"rule": rule, "severity": severity, "line": line, "message": message, "fix": fix}


def get(mapping, key):
    entry = mapping.get(key) if isinstance(mapping, dict) else None
    return entry if entry else (None, None)


def dig(mapping, *keys):
    """Follow keys through nested maps. Returns (line, value) or (None, None)."""
    line, value = None, mapping
    for key in keys:
        line, value = get(value, key)
        if value is None:
            return None, None
    return line, value


def is_true(value):
    return isinstance(value, str) and value.strip().lower() in TRUE_VALUES


def items(value):
    """List entries as (line, value) pairs, or [] if this is not a list."""
    return value if isinstance(value, list) else []


def pod_spec_of(kind, root):
    if kind == "Pod":
        return dig(root, "spec")
    if kind == "CronJob":
        return dig(root, "spec", "jobTemplate", "spec", "template", "spec")
    return dig(root, "spec", "template", "spec")


def image_problem(image):
    if "@sha256:" in image:
        return None
    last = image.rsplit("/", 1)[-1]
    if ":" not in last:
        return "has no tag (that means 'latest')"
    if last.split(":", 1)[1].lower() == "latest":
        return "uses the 'latest' tag"
    return None


def check_pod_spec(label, spec, findings):
    for key, name in (("hostNetwork", "network"), ("hostPID", "PID namespace"), ("hostIPC", "IPC namespace")):
        line, value = get(spec, key)
        if is_true(value):
            findings.append(_finding(
                "host-namespace", "high", line,
                "%s shares the host's %s (%s: true)." % (label, name, key),
                "Remove %s: true." % key))

    for line, volume in items(get(spec, "volumes")[1]):
        if not isinstance(volume, dict):
            continue
        path_line, path = dig(volume, "hostPath", "path")
        if not isinstance(path, str):
            continue
        clean = path.rstrip("/") or "/"
        sensitive = "docker.sock" in clean or clean in SENSITIVE_PATHS or any(
            clean.startswith(p + "/") for p in SENSITIVE_PATHS if p != "/")
        if sensitive:
            findings.append(_finding(
                "sensitive-hostpath", "high", path_line,
                "%s mounts the host path %s." % (label, clean),
                "Use a PersistentVolume, ConfigMap or emptyDir. Never mount the container runtime socket."))
        else:
            findings.append(_finding(
                "hostpath-volume", "medium", path_line,
                "%s mounts the host folder %s." % (label, clean),
                "Prefer a PersistentVolume, and mount read-only if you must use hostPath."))

    pod_context = get(spec, "securityContext")[1] or {}
    for group in ("initContainers", "containers"):
        for _, container in items(get(spec, group)[1]):
            if isinstance(container, dict):
                check_container(label, container, pod_context, findings)


def check_container(label, container, pod_context, findings):
    name_line, name = get(container, "name")
    name = name if isinstance(name, str) else "?"
    anchor = name_line or 1
    where = "%s, container '%s'" % (label, name)
    context = get(container, "securityContext")[1]
    context = context if isinstance(context, dict) else {}

    line, value = get(context, "privileged")
    if is_true(value):
        findings.append(_finding(
            "privileged", "high", line,
            "%s runs privileged, with almost full access to the host." % where,
            "Remove privileged: true and add only the capability it needs."))

    def effective(key):
        """Container setting wins; otherwise the pod-level one."""
        value = get(context, key)
        return value if value[1] is not None else get(pod_context, key)

    user_line, user = effective("runAsUser")
    user = user if isinstance(user, str) else None
    if user == "0":
        findings.append(_finding(
            "run-as-root", "high", user_line or anchor,
            "%s runs as user 0 (root)." % where,
            "Set runAsUser to a non-zero number and runAsNonRoot: true."))
    elif not is_true(effective("runAsNonRoot")[1]) and not (user and user.isdigit()):
        findings.append(_finding(
            "no-run-as-non-root", "medium", anchor,
            "%s does not say it must run as a non-root user." % where,
            "Add securityContext: runAsNonRoot: true (and a numeric runAsUser)."))

    caps = get(context, "capabilities")[1]
    caps = caps if isinstance(caps, dict) else {}
    for line, cap in items(get(caps, "add")[1]):
        if isinstance(cap, str) and cap.upper().replace("CAP_", "") in DANGEROUS_CAPS:
            findings.append(_finding(
                "dangerous-capability", "high", line,
                "%s adds the powerful capability %s." % (where, cap),
                "Remove it. Add only the narrowest capability that is needed."))
    drops = [c.upper() for _, c in items(get(caps, "drop")[1]) if isinstance(c, str)]
    if "ALL" not in drops:
        findings.append(_finding(
            "no-cap-drop-all", "low", anchor,
            "%s does not drop all capabilities." % where,
            "Add capabilities: drop: [\"ALL\"] and add back only what is needed."))

    if not (get(context, "allowPrivilegeEscalation")[1] is not None
            and not is_true(get(context, "allowPrivilegeEscalation")[1])):
        findings.append(_finding(
            "allow-privilege-escalation", "medium", anchor,
            "%s does not set allowPrivilegeEscalation: false, so a process can gain extra rights." % where,
            "Add allowPrivilegeEscalation: false under securityContext."))

    if not is_true(get(context, "readOnlyRootFilesystem")[1]):
        findings.append(_finding(
            "no-readonly-root-fs", "low", anchor,
            "%s can write to its own filesystem." % where,
            "Add readOnlyRootFilesystem: true and mount an emptyDir where it must write."))

    image_line, image = get(container, "image")
    if isinstance(image, str) and "{{" not in image:
        problem = image_problem(image)
        if problem:
            findings.append(_finding(
                "image-latest-tag", "medium", image_line,
                "%s image '%s' %s and can change without warning." % (where, image, problem),
                "Pin a version tag, or better a digest (@sha256:...)."))

    limits = dig(container, "resources", "limits")[1]
    if not isinstance(limits, dict) or not limits:
        findings.append(_finding(
            "no-resource-limits", "medium", anchor,
            "%s has no resource limits, so one bug can use up the whole node." % where,
            "Add resources: limits: cpu and memory."))

    for line, env in items(get(container, "env")[1]):
        if not isinstance(env, dict):
            continue
        env_name = get(env, "name")[1]
        env_value = get(env, "value")[1]
        if (isinstance(env_name, str) and SECRET_NAME.search(env_name)
                and isinstance(env_value, str) and env_value):
            findings.append(_finding(
                "hardcoded-secret", "high", line,
                "%s has a value for %s written in the file." % (where, env_name),
                "Use valueFrom: secretKeyRef and keep the Secret out of git."))


def check_manifest(lines):
    """Return (findings, workloads_checked)."""
    findings = []
    checked = 0
    for doc_lines in split_documents(lines):
        root = parse_document(doc_lines)
        kind = get(root, "kind")[1]
        if kind not in WORKLOADS:
            continue
        name = dig(root, "metadata", "name")[1]
        label = "%s '%s'" % (kind, name if isinstance(name, str) else "?")
        _, spec = pod_spec_of(kind, root)
        if isinstance(spec, dict):
            checked += 1
            check_pod_spec(label, spec, findings)
    findings.sort(key=lambda f: (-SEVERITIES[f["severity"]], f["line"], f["rule"]))
    return findings, checked


# ---------- output and command line ----------

def filter_findings(findings, min_severity):
    floor = SEVERITIES[min_severity]
    return [f for f in findings if SEVERITIES[f["severity"]] >= floor]


def format_text(results):
    out = []
    for name, findings, checked in results:
        out.append("%s: %d finding(s) in %d workload(s)" % (name, len(findings), checked))
        for f in findings:
            out.append("  [%s] line %d  %s: %s" % (f["severity"].upper(), f["line"], f["rule"], f["message"]))
            out.append("      Fix: %s" % f["fix"])
        if not findings:
            out.append("  No findings.")
        out.append("")
    return "\n".join(out).rstrip() + "\n"


def format_json(results):
    return json.dumps([{"file": n, "workloads_checked": c, "findings": f} for n, f, c in results], indent=2) + "\n"


def build_parser():
    parser = argparse.ArgumentParser(description="Check Kubernetes manifest files for risky settings.")
    parser.add_argument("files", nargs="+", help="manifest file(s)")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--min-severity", choices=tuple(SEVERITIES), default="low",
                        help="hide findings below this level")
    parser.add_argument("--fail-on", choices=tuple(SEVERITIES), default="high",
                        help="exit 1 if any finding is at or above this level")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    results = []
    worst = 0
    for path in args.files:
        try:
            lines = load_manifest(path)
            if any("{{" in l for l in lines):
                raise ManifestError("this looks like a Helm template ({{ }}); render it first with 'helm template'")
            if not any(l.strip() and not l.lstrip().startswith("#") for l in lines):
                print("note: %s is empty." % path, file=sys.stderr)
                results.append((path, [], 0))
                continue
            findings, checked = check_manifest(lines)
        except ManifestError as exc:
            print("error: %s: %s" % (path, exc), file=sys.stderr)
            return 2
        if checked == 0:
            print("note: %s has no Pod or workload to check." % path, file=sys.stderr)
        for f in findings:
            worst = max(worst, SEVERITIES[f["severity"]])
        results.append((path, filter_findings(findings, args.min_severity), checked))
    output = format_json(results) if args.format == "json" else format_text(results)
    sys.stdout.write(output)
    return 1 if worst >= SEVERITIES[args.fail_on] else 0


if __name__ == "__main__":
    sys.exit(main())
