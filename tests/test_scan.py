from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lily_sweep.cli import main
from lily_sweep.engine import scan_path


class LilySweepScanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = Path(__file__).resolve().parents[1] / "examples" / "unsafe_warehouse_agent"

    def test_fixture_triggers_expected_findings(self) -> None:
        report = scan_path(self.fixture)
        finding_ids = {finding.id for finding in report.findings}
        finding_locations = {finding.location for finding in report.findings}
        ros_evidence = {
            finding.evidence
            for finding in report.findings
            if finding.id in {"ros-dangerous-topic", "ros-dangerous-service", "ros-dangerous-action"}
        }

        self.assertIn("dangerous-shell-exec", finding_ids)
        self.assertIn("wildcard-tool-allowlist", finding_ids)
        self.assertIn("unguarded-actuator-endpoint", finding_ids)
        self.assertIn("missing-human-approval-gate", finding_ids)
        self.assertIn("scenario-heavy-machinery", finding_ids)
        self.assertIn("rosbridge-wildcard-exposure", finding_ids)
        self.assertIn("ros-sim-real-mixed-control", finding_ids)
        self.assertIn("/dock_lock/release", ros_evidence)
        self.assertIn("/door_power_cycle", ros_evidence)
        self.assertNotIn("ignored/ignored_agent.py", finding_locations)

    def test_cli_json_output_and_threshold_exit(self) -> None:
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            exit_code = main(
                [
                    "scan",
                    str(self.fixture),
                    "--format",
                    "json",
                    "--config",
                    str(self.fixture / "lilysweep.json"),
                    "--fail-on",
                    "high",
                ]
            )

        payload = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, 2)
        self.assertGreater(payload["finding_count"], 0)
        self.assertEqual(payload["root"], str(self.fixture.resolve()))

    def test_baseline_can_accept_existing_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            baseline_path = Path(tmpdir) / "baseline.json"
            with redirect_stdout(io.StringIO()):
                baseline_exit = main(["baseline", str(self.fixture), "--output", str(baseline_path)])

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                scan_exit = main(["scan", str(self.fixture), "--baseline", str(baseline_path), "--fail-on", "high"])

            payload_text = stdout.getvalue()
            self.assertEqual(baseline_exit, 0)
            self.assertEqual(scan_exit, 0)
            self.assertIn("Findings: 0", payload_text)

    def test_sarif_output_includes_rules_results_and_fingerprints(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            sarif_path = Path(tmpdir) / "lily-sweep.sarif"
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                exit_code = main(["scan", str(self.fixture), "--format", "sarif", "--output", str(sarif_path)])

            payload = json.loads(sarif_path.read_text(encoding="utf-8"))
            run = payload["runs"][0]
            result_ids = {result["ruleId"] for result in run["results"]}
            rule_ids = {rule["id"] for rule in run["tool"]["driver"]["rules"]}
            rosbridge_result = next(result for result in run["results"] if result["ruleId"] == "rosbridge-wildcard-exposure")

            self.assertEqual(exit_code, 0)
            self.assertIn("Wrote sarif scan report", stdout.getvalue())
            self.assertEqual(payload["version"], "2.1.0")
            self.assertIn("rosbridge-wildcard-exposure", result_ids)
            self.assertIn("rosbridge-wildcard-exposure", rule_ids)
            self.assertEqual(rosbridge_result["level"], "error")
            self.assertIn("primaryLocationLineHash", rosbridge_result["partialFingerprints"])

    def test_init_dry_run_does_not_write_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "repo"
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                exit_code = main(["init", str(target), "--dry-run", "--with-baseline"])

            self.assertEqual(exit_code, 0)
            self.assertIn("LilySweep init would create", stdout.getvalue())
            self.assertFalse(target.exists())

    def test_init_writes_config_workflow_and_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "repo"
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                exit_code = main(["init", str(target), "--with-baseline"])

            config_path = target / "lilysweep.json"
            workflow_path = target / ".github" / "workflows" / "lilysweep.yml"
            baseline_path = target / "lilysweep-baseline.json"
            baseline_payload = json.loads(baseline_path.read_text(encoding="utf-8"))

            self.assertEqual(exit_code, 0)
            self.assertTrue(config_path.exists())
            self.assertTrue(workflow_path.exists())
            self.assertTrue(baseline_path.exists())
            self.assertEqual(baseline_payload["accepted_findings"], [])
            self.assertIn("Wrote", stdout.getvalue())

    def test_init_skips_existing_files_without_force(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "repo"
            target.mkdir()
            config_path = target / "lilysweep.json"
            config_path.write_text('{"existing": true}\n', encoding="utf-8")

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                exit_code = main(["init", str(target), "--no-github"])

            self.assertEqual(exit_code, 0)
            self.assertIn("Skipped existing", stdout.getvalue())
            self.assertEqual(json.loads(config_path.read_text(encoding="utf-8")), {"existing": True})


if __name__ == "__main__":
    unittest.main()
