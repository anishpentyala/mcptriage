"""Optional harness checks. Run with unittest inside the pinned SDK environment."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


class RunnerTests(unittest.TestCase):
    def invoke(self, *args, runner=None, optimize=False):
        return subprocess.run(
            [sys.executable]
            + (["-O"] if optimize else [])
            + [str(runner or HERE / "run.py"), *map(str, args)],
            capture_output=True,
            text=True,
            timeout=45,
            cwd="/",
        )

    def test_current_source_whole_lifecycle(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "new"
            result = self.invoke("--head", ROOT, "--output", out)
            self.assertEqual(result.returncode, 0, result.stderr)
            summary = json.loads((out / "result.json").read_text())
            self.assertEqual(summary["rows"], 18)
            self.assertIsNone(summary["baseline"])
            self.assertIsNone(summary["baseline_root"])
            self.assertEqual(len((out / "capture.jsonl").read_text().splitlines()), 18)
            self.assertEqual(set(summary["source_fingerprints"]), {"head"})

    def test_current_source_is_not_a_successful_negative_control(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "new"
            result = self.invoke("--head", ROOT, "--baseline", ROOT, "--output", out)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("AssertionError", result.stderr)
            self.assertTrue((out / "capture.jsonl").exists())
            self.assertFalse((out / "result.json").exists())

    def test_relative_root_is_resolved_before_diagnostic_subprocess(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "new"
            relative = Path(*ROOT.parts[1:])
            result = self.invoke("--head", relative, "--output", out)
            self.assertEqual(result.returncode, 0, result.stderr)
            summary = json.loads((out / "result.json").read_text())
            self.assertEqual(summary["head_root"], str(ROOT))

    def test_invalid_root_does_not_create_output(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "new"
            result = self.invoke("--head", d, "--output", out)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("source root must contain", result.stderr)
            self.assertFalse(out.exists())

    def test_existing_directory_is_not_modified(self):
        with tempfile.TemporaryDirectory() as d:
            marker = Path(d) / "marker"
            marker.write_text("untouched")
            result = self.invoke("--head", ROOT, "--output", d)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(marker.read_text(), "untouched")
            self.assertEqual(list(Path(d).iterdir()), [marker])

    def test_optimized_python_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "new"
            result = self.invoke("--head", ROOT, "--output", out, optimize=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("requires assertions", result.stderr)
            self.assertFalse(out.exists())

    def test_silent_server_times_out_without_success_artifact(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            runner = root / "run.py"
            runner.write_text(
                (HERE / "run.py")
                .read_text()
                .replace("anyio.fail_after(30)", "anyio.fail_after(0.5)")
            )
            (root / "server.py").write_text("import time; time.sleep(60)\n")
            out = root / "out"
            result = self.invoke("--head", ROOT, "--output", out, runner=runner)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("TimeoutError", result.stderr)
            self.assertFalse((out / "result.json").exists())


if __name__ == "__main__":
    unittest.main()
