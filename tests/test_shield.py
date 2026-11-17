"""Tests for agent-shield. Stdlib unittest; run with:
    python3 -m unittest discover -s tests -v
from the repository root.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent_shield.scan import redact_tree, scan_tree, score  # noqa: E402
from agent_shield.cli import main  # noqa: E402

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
LEAKY = os.path.join(FIXTURES, "leaky")
CLEAN = os.path.join(FIXTURES, "clean")


def rules_of(findings):
    return {f.rule for f in findings}


class TestDetection(unittest.TestCase):
    def test_aws_key_is_critical(self):
        findings = scan_tree(LEAKY)
        aws = [f for f in findings if f.rule == "aws-access-key"]
        self.assertEqual(len(aws), 1)
        self.assertEqual(aws[0].severity, "critical")

    def test_named_key_beats_generic_assignment(self):
        # sk_live_... line must yield exactly one finding (stripe, not
        # stripe + assigned-credential).
        findings = scan_tree(LEAKY)
        stripe_lines = [f for f in findings
                        if f.path.endswith("config.py")
                        and "API_KEY" in f.snippet]
        self.assertEqual(len(stripe_lines), 1)
        self.assertEqual(stripe_lines[0].rule, "stripe-live-key")

    def test_github_token_and_db_string_detected(self):
        rules = rules_of(scan_tree(LEAKY))
        self.assertIn("github-pat", rules)
        self.assertIn("db-connection-string", rules)

    def test_leakage_categories_detected(self):
        rules = rules_of(scan_tree(LEAKY))
        self.assertIn("internal-endpoint", rules)
        self.assertIn("credential-hint-in-comment", rules)
        self.assertIn("architecture-map", rules)
        self.assertIn("env-file-with-values", rules)

    def test_placeholders_and_hashes_not_flagged(self):
        findings = scan_tree(CLEAN)
        self.assertEqual(findings, [], f"clean tree flagged: {findings}")

    def test_secret_never_printed_in_full(self):
        findings = scan_tree(LEAKY)
        for f in findings:
            self.assertNotIn("AKIAIOSFODNN7EXAMPLE", f.snippet)
            self.assertNotIn("s3cretP@ssw0rd", f.snippet)
            self.assertNotIn("Sup3rSecret99", f.snippet)


class TestScoring(unittest.TestCase):
    def test_clean_tree_scores_zero_grade_a(self):
        result = score(scan_tree(CLEAN))
        self.assertEqual(result["exposure"], 0)
        self.assertEqual(result["grade"], "A")

    def test_leaky_tree_scores_high_grade_f(self):
        result = score(scan_tree(LEAKY))
        self.assertGreaterEqual(result["exposure"], 70)
        self.assertEqual(result["grade"], "F")
        self.assertGreater(result["by_severity"]["critical"], 0)

    def test_score_caps_at_100(self):
        from agent_shield.scan import Finding
        many = [Finding("x.py", i, "secret", "critical", "aws-access-key")
                for i in range(10)]
        self.assertEqual(score(many)["exposure"], 100)


class TestRedaction(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_redacted_copy_has_no_secrets_source_untouched(self):
        outdir = os.path.join(self.tmp, "redacted")
        findings = scan_tree(LEAKY)
        manifest = redact_tree(LEAKY, outdir, findings)
        self.assertGreater(manifest["values_redacted"], 0)
        self.assertGreater(manifest["files_redacted"], 0)

        redacted = scan_tree(outdir)
        secrets_left = [f for f in redacted if f.category == "secret"]
        self.assertEqual(secrets_left, [],
                         f"secrets survived redaction: {secrets_left}")

        # Source tree untouched.
        with open(os.path.join(LEAKY, "config.py")) as fh:
            self.assertIn("AKIAIOSFODNN7EXAMPLE", fh.read())

        # Structure preserved.
        with open(os.path.join(outdir, "config.py")) as fh:
            text = fh.read()
        self.assertIn("***REDACTED***", text)
        self.assertIn("INTERNAL_API", text)  # non-secret code stays

    def test_env_values_redacted(self):
        outdir = os.path.join(self.tmp, "redacted")
        redact_tree(LEAKY, outdir, scan_tree(LEAKY))
        with open(os.path.join(outdir, ".env")) as fh:
            text = fh.read()
        self.assertNotIn("Sup3rSecret99", text)
        self.assertNotIn("sk_live_0123456789ABCDEF", text)
        self.assertIn("DEBUG=false", text)  # non-secret line preserved


class TestCLI(unittest.TestCase):
    def _run(self, *argv):
        return main(list(argv))

    def test_clean_exits_zero(self):
        self.assertEqual(self._run("audit", CLEAN), 0)

    def test_leaky_exits_one(self):
        self.assertEqual(self._run("audit", LEAKY), 1)

    def test_fail_on_never_exits_zero(self):
        self.assertEqual(self._run("audit", LEAKY, "--fail-on", "never"), 0)

    def test_missing_directory_exits_two(self):
        self.assertEqual(self._run("audit", "/no/such/dir"), 2)

    def test_json_output_is_valid(self):
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = self._run("audit", LEAKY, "--json")
        self.assertEqual(code, 1)
        data = json.loads(buf.getvalue())
        self.assertEqual(data["grade"], "F")
        self.assertIn("findings_list", data)
        self.assertTrue(all("rule" in f for f in data["findings_list"]))

    def test_cli_redact_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            outdir = os.path.join(tmp, "out")
            code = self._run("audit", LEAKY, "--redact", outdir,
                             "--fail-on", "never")
            self.assertEqual(code, 0)
            self.assertTrue(os.path.exists(os.path.join(outdir, "config.py")))


if __name__ == "__main__":
    unittest.main()
