import json
import os
import subprocess
import sys
import tempfile
import unittest

import k8s_checker as kc

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLES = os.path.join(HERE, "sample_manifests")
TOOL = os.path.join(HERE, "k8s_checker.py")

SAFE_CONTAINER = """\
    - name: app
      image: example/app:1.0
      securityContext:
        runAsNonRoot: true
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop: ["ALL"]
      resources:
        limits:
          cpu: "1"
"""


def pod(container=SAFE_CONTAINER, spec_extra=""):
    extra = "".join("  %s\n" % line for line in spec_extra.splitlines())
    return "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\nspec:\n%s  containers:\n%s" % (extra, container)


def run(text):
    return kc.check_manifest(text.splitlines())


def rules(text):
    return [f["rule"] for f in run(text)[0]]


def container(extra_security="", extra=""):
    """A container block with a custom securityContext (6-space children)."""
    return ("    - name: app\n      image: example/app:1.0\n      securityContext:\n%s%s"
            % (extra_security, extra))


BASE_SC = ("        runAsNonRoot: true\n        allowPrivilegeEscalation: false\n"
           "        readOnlyRootFilesystem: true\n        capabilities:\n          drop: [\"ALL\"]\n")
LIMITS = "      resources:\n        limits:\n          cpu: \"1\"\n"


class ReaderTests(unittest.TestCase):
    def test_multi_document_line_numbers(self):
        text = "kind: ConfigMap\n---\nkind: Pod\nmetadata:\n  name: a\nspec:\n  containers:\n    - name: c\n      image: x:1\n"
        findings, checked = run(text)
        self.assertEqual(checked, 1)
        self.assertTrue(all(f["line"] >= 3 for f in findings))

    def test_split_documents_blanks_other_docs(self):
        docs = kc.split_documents(["a: 1", "---", "b: 2"])
        self.assertEqual(len(docs), 2)
        self.assertEqual(docs[1], ["", "", "b: 2"])

    def test_empty_documents_skipped(self):
        self.assertEqual(len(kc.split_documents(["---", "# nothing", "---", "a: 1"])), 1)

    def test_comments_ignored(self):
        text = pod().replace("kind: Pod", "kind: Pod  # a pod")
        self.assertEqual(run(text)[1], 1)

    def test_inline_lists(self):
        root = kc.parse_document(["a:", "  b: [x, y]"])
        self.assertEqual([v for _, v in root["a"][1]["b"][1]], ["x", "y"])

    def test_list_of_maps(self):
        root = kc.parse_document(["env:", "  - name: A", "    value: b"])
        self.assertEqual(root["env"][1][0][1]["name"][1], "A")

    def test_anchor_is_an_error(self):
        with self.assertRaises(kc.ManifestError):
            kc.parse_document(["a: &x", "  b: 1"])

    def test_tab_is_an_error(self):
        with self.assertRaises(kc.ManifestError):
            kc.parse_document(["a:", "\tb: 1"])


class WorkloadTests(unittest.TestCase):
    def test_clean_pod(self):
        self.assertEqual(rules(pod()), [])

    def test_deployment_is_checked(self):
        text = ("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: d\nspec:\n  template:\n    spec:\n"
                "      hostNetwork: true\n      containers:\n" + SAFE_CONTAINER.replace("\n    ", "\n        ").replace("    - name", "        - name", 1))
        self.assertIn("host-namespace", rules(text))

    def test_cronjob_is_checked(self):
        text = ("kind: CronJob\nmetadata:\n  name: c\nspec:\n  jobTemplate:\n    spec:\n      template:\n"
                "        spec:\n          hostPID: true\n          containers: []\n")
        self.assertIn("host-namespace", rules(text))

    def test_other_kinds_ignored(self):
        findings, checked = run("kind: Service\nmetadata:\n  name: s\n")
        self.assertEqual((findings, checked), ([], 0))

    def test_init_containers_checked(self):
        text = "kind: Pod\nmetadata:\n  name: p\nspec:\n  initContainers:\n    - name: i\n      image: x\n  containers: []\n"
        self.assertIn("image-latest-tag", rules(text))

    def test_pod_name_in_message(self):
        findings, _ = run(pod(spec_extra="hostNetwork: true"))
        self.assertIn("Pod 'p'", findings[0]["message"])


class PodRuleTests(unittest.TestCase):
    def test_host_network_pid_ipc(self):
        for key in ("hostNetwork", "hostPID", "hostIPC"):
            self.assertIn("host-namespace", rules(pod(spec_extra="%s: true" % key)))

    def test_host_network_false_ok(self):
        self.assertNotIn("host-namespace", rules(pod(spec_extra="hostNetwork: false")))

    def test_docker_socket(self):
        extra = "volumes:\n  - name: d\n    hostPath:\n      path: /var/run/docker.sock"
        self.assertIn("sensitive-hostpath", rules(pod(spec_extra=extra)))

    def test_sensitive_hostpath(self):
        for path in ("/", "/etc", "/etc/kubernetes", "/root", "/proc"):
            extra = "volumes:\n  - name: d\n    hostPath:\n      path: %s" % path
            self.assertIn("sensitive-hostpath", rules(pod(spec_extra=extra)), path)

    def test_other_hostpath_is_medium(self):
        extra = "volumes:\n  - name: d\n    hostPath:\n      path: /var/log"
        findings = run(pod(spec_extra=extra))[0]
        self.assertEqual([f["severity"] for f in findings], ["medium"])
        self.assertEqual(findings[0]["rule"], "hostpath-volume")

    def test_emptydir_ok(self):
        extra = "volumes:\n  - name: d\n    emptyDir: {}"
        self.assertEqual(rules(pod(spec_extra=extra)), [])

    def test_hostpath_line_number(self):
        extra = "volumes:\n  - name: d\n    hostPath:\n      path: /etc"
        findings = run(pod(spec_extra=extra))[0]
        self.assertEqual(findings[0]["line"], 9)


class ContainerRuleTests(unittest.TestCase):
    def test_privileged(self):
        text = pod(container(BASE_SC + "        privileged: true\n", LIMITS))
        self.assertIn("privileged", rules(text))

    def test_run_as_root(self):
        text = pod(container(BASE_SC + "        runAsUser: 0\n", LIMITS))
        self.assertIn("run-as-root", rules(text))

    def test_run_as_root_at_pod_level(self):
        text = pod(container(BASE_SC, LIMITS), spec_extra="securityContext:\n  runAsUser: 0")
        self.assertIn("run-as-root", rules(text))

    def test_container_user_beats_pod_user(self):
        text = pod(container(BASE_SC + "        runAsUser: 1000\n", LIMITS), spec_extra="securityContext:\n  runAsUser: 0")
        self.assertNotIn("run-as-root", rules(text))

    def test_non_root_user_number_ok(self):
        sc = BASE_SC.replace("        runAsNonRoot: true\n", "        runAsUser: 1000\n")
        self.assertNotIn("no-run-as-non-root", rules(pod(container(sc, LIMITS))))

    def test_missing_non_root_flagged(self):
        sc = BASE_SC.replace("        runAsNonRoot: true\n", "")
        self.assertIn("no-run-as-non-root", rules(pod(container(sc, LIMITS))))

    def test_pod_level_non_root_counts(self):
        sc = BASE_SC.replace("        runAsNonRoot: true\n", "")
        text = pod(container(sc, LIMITS), spec_extra="securityContext:\n  runAsNonRoot: true")
        self.assertNotIn("no-run-as-non-root", rules(text))

    def test_dangerous_capability(self):
        sc = BASE_SC.replace('          drop: ["ALL"]\n', '          drop: ["ALL"]\n          add: ["SYS_ADMIN"]\n')
        self.assertIn("dangerous-capability", rules(pod(container(sc, LIMITS))))

    def test_harmless_capability_ok(self):
        sc = BASE_SC.replace('          drop: ["ALL"]\n', '          drop: ["ALL"]\n          add: ["NET_BIND_SERVICE"]\n')
        self.assertEqual(rules(pod(container(sc, LIMITS))), [])

    def test_missing_cap_drop_all(self):
        sc = BASE_SC.replace('        capabilities:\n          drop: ["ALL"]\n', "")
        self.assertIn("no-cap-drop-all", rules(pod(container(sc, LIMITS))))

    def test_privilege_escalation(self):
        sc = BASE_SC.replace("allowPrivilegeEscalation: false", "allowPrivilegeEscalation: true")
        self.assertIn("allow-privilege-escalation", rules(pod(container(sc, LIMITS))))

    def test_privilege_escalation_missing(self):
        sc = BASE_SC.replace("        allowPrivilegeEscalation: false\n", "")
        self.assertIn("allow-privilege-escalation", rules(pod(container(sc, LIMITS))))

    def test_readonly_root_missing(self):
        sc = BASE_SC.replace("        readOnlyRootFilesystem: true\n", "")
        self.assertIn("no-readonly-root-fs", rules(pod(container(sc, LIMITS))))

    def test_no_security_context_at_all(self):
        text = pod("    - name: app\n      image: example/app:1.0\n" + LIMITS)
        found = rules(text)
        for rule in ("no-run-as-non-root", "no-cap-drop-all", "allow-privilege-escalation", "no-readonly-root-fs"):
            self.assertIn(rule, found)

    def test_no_limits(self):
        self.assertIn("no-resource-limits", rules(pod(container(BASE_SC))))

    def test_empty_limits_flagged(self):
        text = pod(container(BASE_SC, "      resources:\n        requests:\n          cpu: 1\n"))
        self.assertIn("no-resource-limits", rules(text))

    def test_image_tags(self):
        self.assertIn("image-latest-tag", rules(pod(container(BASE_SC, LIMITS).replace("app:1.0", "app:latest"))))
        self.assertIn("image-latest-tag", rules(pod(container(BASE_SC, LIMITS).replace("example/app:1.0", "nginx"))))

    def test_registry_port_not_a_tag(self):
        self.assertIsNotNone(kc.image_problem("registry.local:5000/team/app"))
        self.assertIsNone(kc.image_problem("registry.local:5000/team/app:1.2"))

    def test_digest_ok(self):
        self.assertIsNone(kc.image_problem("app@sha256:" + "a" * 64))

    def test_hardcoded_secret(self):
        env = "      env:\n        - name: API_TOKEN\n          value: abc123\n"
        self.assertIn("hardcoded-secret", rules(pod(container(BASE_SC, LIMITS + env))))

    def test_secret_from_secret_ref_ok(self):
        env = ("      env:\n        - name: API_TOKEN\n          valueFrom:\n"
               "            secretKeyRef:\n              name: s\n              key: k\n")
        self.assertEqual(rules(pod(container(BASE_SC, LIMITS + env))), [])

    def test_plain_env_ok(self):
        env = "      env:\n        - name: LOG_LEVEL\n          value: debug\n"
        self.assertEqual(rules(pod(container(BASE_SC, LIMITS + env))), [])

    def test_secret_value_never_printed(self):
        env = "      env:\n        - name: API_TOKEN\n          value: abc123\n"
        for f in run(pod(container(BASE_SC, LIMITS + env)))[0]:
            self.assertNotIn("abc123", json.dumps(f))

    def test_multiple_containers(self):
        second = SAFE_CONTAINER.replace("name: app", "name: sidecar").replace("example/app:1.0", "x:latest")
        findings = run(pod(SAFE_CONTAINER + second))[0]
        self.assertEqual([f["rule"] for f in findings], ["image-latest-tag"])
        self.assertIn("sidecar", findings[0]["message"])

    def test_sorted_high_first(self):
        findings = run(pod(spec_extra="hostNetwork: true"))[0]
        order = [kc.SEVERITIES[f["severity"]] for f in findings]
        self.assertEqual(order, sorted(order, reverse=True))


def run_tool(*args):
    return subprocess.run([sys.executable, TOOL] + list(args), capture_output=True, text=True)


def temp_file(text, suffix=".yml", mode="w"):
    handle = tempfile.NamedTemporaryFile(mode, suffix=suffix, delete=False)
    handle.write(text)
    handle.close()
    return handle.name


class CommandLineTests(unittest.TestCase):
    def sample(self, name):
        return os.path.join(SAMPLES, name)

    def test_risky_exits_1(self):
        self.assertEqual(run_tool(self.sample("01_risky.yml")).returncode, 1)

    def test_hardened_exits_0(self):
        result = run_tool(self.sample("03_hardened.yml"))
        self.assertEqual(result.returncode, 0)
        self.assertIn("No findings.", result.stdout)

    def test_gaps_exit_0_by_default(self):
        self.assertEqual(run_tool(self.sample("02_okay_with_gaps.yml")).returncode, 0)

    def test_fail_on_low(self):
        self.assertEqual(run_tool(self.sample("02_okay_with_gaps.yml"), "--fail-on", "low").returncode, 1)

    def test_min_severity(self):
        out = run_tool(self.sample("01_risky.yml"), "--min-severity", "high").stdout
        self.assertNotIn("[LOW]", out)
        self.assertNotIn("[MEDIUM]", out)

    def test_json_output(self):
        data = json.loads(run_tool(self.sample("01_risky.yml"), "--format", "json").stdout)
        self.assertEqual(len(data[0]["findings"]), 17)
        self.assertEqual(data[0]["workloads_checked"], 2)

    def test_missing_file(self):
        result = run_tool("nope.yml")
        self.assertEqual(result.returncode, 2)
        self.assertIn("file not found", result.stderr)

    def test_helm_template_rejected(self):
        name = temp_file("kind: Pod\nmetadata:\n  name: {{ .Values.name }}\n")
        try:
            result = run_tool(name)
            self.assertEqual(result.returncode, 2)
            self.assertIn("Helm", result.stderr)
        finally:
            os.unlink(name)

    def test_no_workload_note(self):
        name = temp_file("kind: Service\nmetadata:\n  name: s\n")
        try:
            result = run_tool(name)
            self.assertEqual(result.returncode, 0)
            self.assertIn("no Pod or workload", result.stderr)
        finally:
            os.unlink(name)

    def test_empty_file_note(self):
        name = temp_file("# nothing\n")
        try:
            result = run_tool(name)
            self.assertEqual(result.returncode, 0)
            self.assertIn("empty", result.stderr)
        finally:
            os.unlink(name)

    def test_binary_file(self):
        name = temp_file(b"\xff\xfe\x00", mode="wb")
        try:
            self.assertEqual(run_tool(name).returncode, 2)
        finally:
            os.unlink(name)

    def test_several_files(self):
        out = run_tool(self.sample("01_risky.yml"), self.sample("03_hardened.yml")).stdout
        self.assertIn("01_risky.yml", out)
        self.assertIn("03_hardened.yml", out)


class SampleTests(unittest.TestCase):
    def counts(self, name):
        findings, checked = kc.check_manifest(kc.load_manifest(os.path.join(SAMPLES, name)))
        return len(findings), sum(1 for f in findings if f["severity"] == "high"), checked

    def test_risky(self):
        self.assertEqual(self.counts("01_risky.yml"), (17, 6, 2))

    def test_gaps(self):
        self.assertEqual(self.counts("02_okay_with_gaps.yml"), (2, 0, 1))

    def test_hardened(self):
        self.assertEqual(self.counts("03_hardened.yml"), (0, 0, 1))


if __name__ == "__main__":
    unittest.main()
