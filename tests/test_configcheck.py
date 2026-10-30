import json
import os
import tempfile
import unittest

from mcptriage.configcheck import check_config_file, check_config_text


def codes(findings):
    return {f.code for f in findings}


class ConfigCheckTest(unittest.TestCase):
    def test_invalid_json(self):
        findings = check_config_text('{"mcpServers": {,}', "x.json")
        self.assertEqual(codes(findings), {"CFG_JSON_ERROR"})
        self.assertIn("x.json:1", findings[0].evidence)

    def test_no_servers_key(self):
        findings = check_config_text('{"other": true}')
        self.assertEqual(codes(findings), {"CFG_NO_SERVERS"})

    def test_empty_servers(self):
        findings = check_config_text('{"mcpServers": {}}')
        self.assertEqual(codes(findings), {"CFG_NO_SERVERS"})

    def test_vscode_servers_key(self):
        findings = check_config_text(json.dumps({"servers": {"ok": {"command": "python"}}}))
        self.assertNotIn("CFG_NO_SERVERS", codes(findings))

    def test_clean_stdio_server(self):
        text = json.dumps({"mcpServers": {"fs": {"command": "python", "args": ["srv.py"]}}})
        findings = check_config_text(text)
        self.assertEqual(findings, [])

    def test_server_not_object(self):
        text = json.dumps({"mcpServers": {"bad": "oops"}})
        self.assertIn("CFG_SHAPE", codes(check_config_text(text)))

    def test_neither_command_nor_url(self):
        text = json.dumps({"mcpServers": {"empty": {}}})
        findings = check_config_text(text)
        self.assertIn("CFG_SHAPE", codes(findings))
        self.assertEqual([f for f in findings if f.code == "CFG_SHAPE"][0].severity, "high")

    def test_both_command_and_url(self):
        text = json.dumps({"mcpServers": {"s": {"command": "python", "url": "https://x.invalid"}}})
        self.assertIn("CFG_SHAPE", codes(check_config_text(text)))

    def test_unknown_type(self):
        text = json.dumps({"mcpServers": {"s": {"command": "python", "type": "carrier-pigeon"}}})
        self.assertIn("CFG_SHAPE", codes(check_config_text(text)))

    def test_command_not_on_path(self):
        text = json.dumps({"mcpServers": {"s": {"command": "definitely-not-real-cmd-xyz"}}})
        self.assertIn("CFG_COMMAND_MISSING", codes(check_config_text(text)))

    def test_command_missing_path(self):
        text = json.dumps({"mcpServers": {"s": {"command": "/no/such/path/server"}}})
        findings = check_config_text(text)
        f = [f for f in findings if f.code == "CFG_COMMAND_MISSING"][0]
        self.assertEqual(f.severity, "high")

    def test_command_existing_path_ok(self):
        text = json.dumps({"mcpServers": {"s": {"command": "/bin/sh"}}})
        self.assertNotIn("CFG_COMMAND_MISSING", codes(check_config_text(text)))

    def test_args_not_array(self):
        text = json.dumps({"mcpServers": {"s": {"command": "python", "args": "serve"}}})
        self.assertIn("CFG_SHAPE", codes(check_config_text(text)))

    def test_env_ref_unset(self):
        os.environ.pop("MCPTRIAGE_TEST_UNSET_VAR", None)
        text = json.dumps({"mcpServers": {"s": {"command": "python", "env": {"K": "${env:MCPTRIAGE_TEST_UNSET_VAR}"}}}})
        self.assertIn("CFG_ENV_UNSET", codes(check_config_text(text)))

    def test_env_ref_set_ok(self):
        os.environ["MCPTRIAGE_TEST_SET_VAR"] = "1"
        try:
            text = json.dumps({"mcpServers": {"s": {"command": "python", "env": {"K": "${env:MCPTRIAGE_TEST_SET_VAR}"}}}})
            self.assertNotIn("CFG_ENV_UNSET", codes(check_config_text(text)))
        finally:
            os.environ.pop("MCPTRIAGE_TEST_SET_VAR", None)

    def test_envfile_missing(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "mcp.json")
            with open(path, "w") as fh:
                json.dump({"mcpServers": {"s": {"command": "python", "envFile": ".env.missing"}}}, fh)
            self.assertIn("CFG_ENVFILE_MISSING", codes(check_config_file(path)))

    def test_envfile_present_ok(self):
        with tempfile.TemporaryDirectory() as d:
            env_path = os.path.join(d, ".env")
            open(env_path, "w").write("A=1\n")
            path = os.path.join(d, "mcp.json")
            with open(path, "w") as fh:
                json.dump({"mcpServers": {"s": {"command": "python", "envFile": ".env"}}}, fh)
            self.assertNotIn("CFG_ENVFILE_MISSING", codes(check_config_file(path)))


if __name__ == "__main__":
    unittest.main()
