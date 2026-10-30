import contextlib
import io
import json
import os
import tempfile
import unittest

from mcptriage.cli import main

INIT_OK = (
    '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{}}}\n'
    '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{}},"serverInfo":{}}}\n'
    '{"jsonrpc":"2.0","method":"notifications/initialized"}'
)
HEALTHY = (
    INIT_OK
    + '\n{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}\n'
    + '{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"a","inputSchema":{"type":"object"}}]}}'
)
NO_CAPS = (
    '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{}}}\n'
    '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{},"serverInfo":{}}}'
)


def run(argv, stdin_text=None):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        if stdin_text is not None:
            import sys
            old = sys.stdin
            sys.stdin = io.StringIO(stdin_text)
            try:
                code = main(argv)
            finally:
                sys.stdin = old
        else:
            code = main(argv)
    return code, out.getvalue()


class CliTest(unittest.TestCase):
    def _write(self, text, suffix=".jsonl"):
        fd, path = tempfile.mkstemp(suffix=suffix)
        with os.fdopen(fd, "w") as fh:
            fh.write(text)
        self.addCleanup(os.unlink, path)
        return path

    def test_healthy_exit_zero(self):
        path = self._write(HEALTHY)
        code, out = run(["diagnose", path])
        self.assertEqual(code, 0)
        self.assertIn("no problems found", out)

    def test_high_finding_exit_one(self):
        path = self._write(NO_CAPS)
        code, out = run(["diagnose", path])
        self.assertEqual(code, 1)
        self.assertIn("MISSING_TOOLS_CAPABILITY", out)

    def test_exit_zero_flag(self):
        path = self._write(NO_CAPS)
        code, _ = run(["diagnose", path, "--exit-zero"])
        self.assertEqual(code, 0)

    def test_json_format(self):
        path = self._write(NO_CAPS)
        code, out = run(["diagnose", path, "--format", "json"])
        payload = json.loads(out)
        self.assertEqual(payload["finding_count"] >= 1, True)
        self.assertEqual(payload["findings"][0]["code"], "MISSING_TOOLS_CAPABILITY")

    def test_stdin(self):
        code, out = run(["diagnose", "-"], stdin_text=HEALTHY)
        self.assertEqual(code, 0)
        self.assertIn("<stdin>", out)

    def test_diagnose_with_config(self):
        log = self._write(HEALTHY)
        cfg = self._write('{"mcpServers": {"s": {}}}', suffix=".json")
        code, out = run(["diagnose", log, "--config", cfg])
        self.assertEqual(code, 1)
        self.assertIn("CFG_SHAPE", out)

    def test_check_config_subcommand(self):
        cfg = self._write('{"mcpServers": {}}', suffix=".json")
        code, out = run(["check-config", cfg])
        self.assertEqual(code, 1)
        self.assertIn("CFG_NO_SERVERS", out)

    def test_check_config_json_format(self):
        cfg = self._write('{"mcpServers": {}}', suffix=".json")
        code, out = run(["check-config", cfg, "--format", "json"])
        self.assertEqual(json.loads(out)["findings"][0]["code"], "CFG_NO_SERVERS")

    def test_examples_in_repo(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        healthy = os.path.join(root, "examples", "healthy.jsonl")
        code, _ = run(["diagnose", healthy])
        self.assertEqual(code, 0)
        healthy_2026 = os.path.join(root, "examples", "healthy-2026.jsonl")
        code, out = run(["diagnose", healthy_2026])
        self.assertEqual(code, 0)
        self.assertIn("no problems found", out)
        for name, expected in [
            ("connected-but-no-tools.jsonl", "MISSING_TOOLS_CAPABILITY"),
            ("tools-list-error.jsonl", "TOOLS_LIST_ERROR"),
            ("arg-mismatch.jsonl", "TOOL_CALL_ARG_MISMATCH"),
            ("polluted-stdio.jsonl", "STDIO_POLLUTION"),
            ("pagination.jsonl", "PAGINATION_INCOMPLETE"),
        ]:
            code, out = run(["diagnose", os.path.join(root, "examples", name)])
            self.assertIn(expected, out, name)


if __name__ == "__main__":
    unittest.main()
