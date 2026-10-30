import unittest

from mcptriage.rules import HIGH, diagnose, validate_arguments
from mcptriage.transcript import parse_text

INIT_OK = (
    '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"c","version":"1"}}}\n'
    '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{}},"serverInfo":{"name":"s","version":"1"}}}\n'
    '{"jsonrpc":"2.0","method":"notifications/initialized"}'
)


def codes(findings):
    return {f.code for f in findings}


class ValidateArgumentsTest(unittest.TestCase):
    def test_missing_required(self):
        problems = validate_arguments(
            {"type": "object", "properties": {"city": {"type": "string"}}, "required": ["city"]},
            {},
        )
        self.assertEqual(problems, ["missing required argument 'city'"])

    def test_type_mismatch(self):
        problems = validate_arguments(
            {"type": "object", "properties": {"days": {"type": "integer"}}},
            {"days": "three"},
        )
        self.assertTrue(any("days" in p for p in problems))

    def test_bool_is_not_integer(self):
        problems = validate_arguments(
            {"type": "object", "properties": {"n": {"type": "integer"}}},
            {"n": True},
        )
        self.assertTrue(any("n" in p for p in problems))

    def test_enum_violation(self):
        problems = validate_arguments(
            {"type": "object", "properties": {"u": {"enum": ["a", "b"]}}},
            {"u": "c"},
        )
        self.assertTrue(any("enum" in p or "one of" in p for p in problems))

    def test_additional_properties_false(self):
        problems = validate_arguments(
            {"type": "object", "properties": {}, "additionalProperties": False},
            {"x": 1},
        )
        self.assertTrue(any("unexpected" in p for p in problems))

    def test_valid_args_no_problems(self):
        problems = validate_arguments(
            {"type": "object",
             "properties": {"city": {"type": "string"}, "days": {"type": "integer"}},
             "required": ["city"]},
            {"city": "Seattle", "days": 3},
        )
        self.assertEqual(problems, [])

    def test_non_dict_inputs_safe(self):
        self.assertEqual(validate_arguments(None, {}), [])
        self.assertEqual(validate_arguments({}, "x"), [])


class TranscriptRulesTest(unittest.TestCase):
    def test_healthy_session_no_findings(self):
        text = (
            INIT_OK
            + '\n{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}\n'
            + '{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"a","inputSchema":{"type":"object"}}]}}\n'
            + '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"a","arguments":{}}}\n'
            + '{"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"ok"}],"isError":false}}'
        )
        self.assertEqual(diagnose(parse_text(text)), [])

    def test_stdio_pollution(self):
        findings = diagnose(parse_text("banner\n" + INIT_OK), strict_stdio=True)
        self.assertIn("STDIO_POLLUTION", codes(findings))

    def test_pollution_not_flagged_without_json(self):
        findings = diagnose(parse_text("just some text log"), strict_stdio=False)
        self.assertNotIn("STDIO_POLLUTION", codes(findings))

    def test_missing_tools_capability(self):
        text = (
            '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{}}}\n'
            '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{},"serverInfo":{}}}'
        )
        findings = diagnose(parse_text(text))
        self.assertIn("MISSING_TOOLS_CAPABILITY", codes(findings))
        self.assertIn("MISSING_INITIALIZED", codes(findings))

    def test_capability_present_no_finding(self):
        findings = diagnose(parse_text(INIT_OK))
        self.assertNotIn("MISSING_TOOLS_CAPABILITY", codes(findings))

    def test_tools_list_error_codes(self):
        for code in (-32601, -32602, -32603, -32022, -32020):
            text = (
                INIT_OK
                + '\n{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}\n'
                + '{"jsonrpc":"2.0","id":2,"error":{"code":%d,"message":"x"}}' % code
            )
            findings = diagnose(parse_text(text))
            self.assertIn("TOOLS_LIST_ERROR", codes(findings), code)

    def test_tools_list_error_32022_reports_supported(self):
        text = (
            INIT_OK
            + '\n{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}\n'
            + '{"jsonrpc":"2.0","id":2,"error":{"code":-32022,"message":"x","data":{"supported":["2026-07-28"]}}}'
        )
        findings = diagnose(parse_text(text))
        f = [f for f in findings if f.code == "TOOLS_LIST_ERROR"][0]
        self.assertIn("2026-07-28", f.why)

    def test_tools_list_hang(self):
        text = INIT_OK + '\n{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
        findings = diagnose(parse_text(text))
        self.assertIn("TOOLS_LIST_HANG", codes(findings))

    def test_empty_tools_list(self):
        text = (
            INIT_OK
            + '\n{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}\n'
            + '{"jsonrpc":"2.0","id":2,"result":{"tools":[]}}'
        )
        findings = diagnose(parse_text(text))
        self.assertIn("EMPTY_TOOLS_LIST", codes(findings))

    def test_auth_on_list(self):
        text = (
            INIT_OK
            + '\n{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}\n'
            + '{"jsonrpc":"2.0","id":2,"error":{"code":-32603,"message":"401 Unauthorized"}}'
        )
        findings = diagnose(parse_text(text))
        self.assertIn("AUTH_ON_LIST", codes(findings))

    def test_version_downshift(self):
        text = (
            '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{}}}\n'
            '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26","capabilities":{"tools":{}},"serverInfo":{}}}\n'
            '{"jsonrpc":"2.0","method":"notifications/initialized"}'
        )
        findings = diagnose(parse_text(text))
        self.assertIn("VERSION_DOWNSHIFT", codes(findings))

    def test_pagination_incomplete(self):
        text = (
            INIT_OK
            + '\n{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}\n'
            + '{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"t1","inputSchema":{"type":"object"}}],"nextCursor":"p2"}}'
        )
        findings = diagnose(parse_text(text))
        self.assertIn("PAGINATION_INCOMPLETE", codes(findings))

    def test_pagination_followed_ok(self):
        text = (
            INIT_OK
            + '\n{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}\n'
            + '{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"t1","inputSchema":{"type":"object"}}],"nextCursor":"p2"}}\n'
            + '{"jsonrpc":"2.0","id":3,"method":"tools/list","params":{"cursor":"p2"}}\n'
            + '{"jsonrpc":"2.0","id":3,"result":{"tools":[{"name":"t2","inputSchema":{"type":"object"}}]}}'
        )
        findings = diagnose(parse_text(text))
        self.assertNotIn("PAGINATION_INCOMPLETE", codes(findings))

    def test_schema_issues(self):
        text = (
            INIT_OK
            + '\n{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}\n'
            + '{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"no-schema"},{"name":"bad","inputSchema":{"type":"array"}}]}}'
        )
        findings = diagnose(parse_text(text))
        self.assertIn("SCHEMA_ISSUES", codes(findings))

    def test_orphan_responses(self):
        findings = diagnose(parse_text('{"jsonrpc":"2.0","id":5,"result":{}}'))
        self.assertIn("ORPHAN_RESPONSES", codes(findings))

    def test_era_mix(self):
        text = (
            INIT_OK
            + '\n{"jsonrpc":"2.0","id":2,"method":"server/discover","params":{}}\n'
            + '{"jsonrpc":"2.0","id":2,"result":{"tools":[]}}'
        )
        findings = diagnose(parse_text(text))
        self.assertIn("ERA_MIX", codes(findings))

    def test_session_id_lost(self):
        text = (
            INIT_OK
            + '\nPOST /mcp HTTP/1.1 (Mcp-Session-Id: abc123)\n'
            + 'HTTP/1.1 404 session not found'
        )
        findings = diagnose(parse_text(text))
        self.assertIn("SESSION_ID_LOST", codes(findings))

    def test_session_header_without_failure_no_finding(self):
        text = INIT_OK + "\nMcp-Session-Id: abc123 assigned"
        findings = diagnose(parse_text(text))
        self.assertNotIn("SESSION_ID_LOST", codes(findings))

    def test_tool_call_arg_mismatch_details(self):
        text = (
            INIT_OK
            + '\n{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}\n'
            + '{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"f","inputSchema":{"type":"object","properties":{"city":{"type":"string"}},"required":["city"]}}]}}\n'
            + '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"f","arguments":{}}}\n'
            + '{"jsonrpc":"2.0","id":3,"error":{"code":-32602,"message":"Invalid params"}}'
        )
        findings = diagnose(parse_text(text))
        f = [f for f in findings if f.code == "TOOL_CALL_ARG_MISMATCH"][0]
        self.assertIn("missing required argument 'city'", f.why)
        self.assertEqual(f.severity, HIGH)

    def test_tool_call_iserror(self):
        text = (
            INIT_OK
            + '\n{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}\n'
            + '{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"f","inputSchema":{"type":"object"}}]}}\n'
            + '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"f","arguments":{}}}\n'
            + '{"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"db down"}],"isError":true}}'
        )
        findings = diagnose(parse_text(text))
        f = [f for f in findings if f.code == "TOOL_CALL_FAILED"][0]
        self.assertIn("db down", f.why)

    def test_findings_sorted_by_severity(self):
        text = "banner\n" + INIT_OK + '\n{"jsonrpc":"2.0","id":9,"result":{}}'
        findings = diagnose(parse_text(text), strict_stdio=True)
        severities = [f.severity for f in findings]
        self.assertEqual(severities, sorted(severities, key={"high": 0, "medium": 1, "low": 2}.get))


if __name__ == "__main__":
    unittest.main()

class RefinementTest(unittest.TestCase):
    def test_http_log_lines_not_pollution(self):
        text = (
            INIT_OK
            + '\nPOST /mcp HTTP/1.1\n'
            + 'HTTP/1.1 200 OK\n'
            + '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}\n'
            + '{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"a","inputSchema":{"type":"object"}}]}}'
        )
        findings = diagnose(parse_text(text))
        self.assertNotIn("STDIO_POLLUTION", {f.code for f in findings})

    def test_http_lines_still_pollution_in_strict_mode(self):
        text = INIT_OK + "\nPOST /mcp HTTP/1.1\n" + '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
        findings = diagnose(parse_text(text), strict_stdio=True)
        self.assertIn("STDIO_POLLUTION", {f.code for f in findings})

    def test_auth_response_not_double_reported(self):
        text = (
            INIT_OK
            + '\n{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}\n'
            + '{"jsonrpc":"2.0","id":2,"error":{"code":-32603,"message":"401 Unauthorized"}}'
        )
        codes_ = {f.code for f in diagnose(parse_text(text))}
        self.assertIn("AUTH_ON_LIST", codes_)
        self.assertNotIn("TOOLS_LIST_ERROR", codes_)

    def test_non_auth_error_still_reported(self):
        text = (
            INIT_OK
            + '\n{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}\n'
            + '{"jsonrpc":"2.0","id":2,"error":{"code":-32601,"message":"Method not found"}}'
        )
        codes_ = {f.code for f in diagnose(parse_text(text))}
        self.assertIn("TOOLS_LIST_ERROR", codes_)
        self.assertNotIn("AUTH_ON_LIST", codes_)

class CaptureQualityTest(unittest.TestCase):
    def test_capture_starting_mid_session_flagged(self):
        text = '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}\n{"jsonrpc":"2.0","id":2,"result":{"tools":[]}}'
        self.assertIn("CAPTURE_INCOMPLETE", {f.code for f in diagnose(parse_text(text))})

    def test_capture_starting_at_initialize_not_flagged(self):
        self.assertNotIn("CAPTURE_INCOMPLETE", {f.code for f in diagnose(parse_text(INIT_OK))})

    def test_server_initiated_requests_flag_direction(self):
        text = (
            INIT_OK
            + '\n{"jsonrpc":"2.0","id":7,"method":"sampling/createMessage","params":{"messages":[]}}\n'
            + '{"jsonrpc":"2.0","id":7,"result":{"role":"assistant","content":{"type":"text","text":"x"}}}'
        )
        codes_ = {f.code for f in diagnose(parse_text(text))}
        self.assertIn("DIRECTION_AMBIGUOUS", codes_)

    def test_duplicate_inflight_id_flagged(self):
        text = (
            INIT_OK
            + '\n{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}\n'
            + '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}\n'
            + '{"jsonrpc":"2.0","id":2,"result":{"tools":[]}}'
        )
        self.assertIn("DIRECTION_AMBIGUOUS", {f.code for f in diagnose(parse_text(text))})

    def test_one_direction_clean(self):
        text = (
            INIT_OK
            + '\n{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}\n'
            + '{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"a","inputSchema":{"type":"object"}}]}}'
        )
        self.assertNotIn("DIRECTION_AMBIGUOUS", {f.code for f in diagnose(parse_text(text))})


class RedactionTest(unittest.TestCase):
    def test_bearer_token_masked_in_evidence(self):
        from mcptriage.rules import redact
        self.assertEqual(redact("Authorization: Bearer sk-abc123secret"), "Authorization: ***")
        self.assertNotIn("sk-abc123secret", redact("Authorization: Bearer sk-abc123secret"))

    def test_json_secret_fields_masked(self):
        from mcptriage.rules import redact
        out = redact('{"env":{"API_KEY":"hunter2","note":"keep"}}')
        self.assertNotIn("hunter2", out)
        self.assertIn('"note":"keep"', out)

    def test_evidence_uses_redaction(self):
        text = (
            INIT_OK
            + '\n{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{},"authorization":"Bearer topsecrettoken"}\n'
            + '{"jsonrpc":"2.0","id":2,"error":{"code":-32601,"message":"Method not found"}}'
        )
        findings = diagnose(parse_text(text))
        f = [f for f in findings if f.code == "TOOLS_LIST_ERROR"][0]
        self.assertNotIn("topsecrettoken", f.evidence)

    def test_boolean_schemas(self):
        self.assertEqual(validate_arguments(
            {"type": "object", "properties": {"a": True}}, {"a": 123}), [])
        problems = validate_arguments(
            {"type": "object", "properties": {"a": False}}, {"a": 123})
        self.assertTrue(any("not allowed" in p for p in problems))


class SeverityUncertaintyTest(unittest.TestCase):
    HANG = (
        INIT_OK
        + '\n{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
    )

    def test_hang_high_on_complete_capture(self):
        f = [x for x in diagnose(parse_text(self.HANG)) if x.code == "TOOLS_LIST_HANG"][0]
        self.assertEqual(f.severity, "high")

    def test_hang_lowered_when_capture_incomplete(self):
        # capture starts at the initialized notification: handshake happened earlier
        text = '\n'.join(self.HANG.splitlines()[1:])
        findings = diagnose(parse_text(text))
        self.assertIn("CAPTURE_INCOMPLETE", {x.code for x in findings})
        f = [x for x in findings if x.code == "TOOLS_LIST_HANG"][0]
        self.assertEqual(f.severity, "medium")
        self.assertIn("outside this capture", f.why)

    def test_hang_lowered_when_direction_ambiguous(self):
        text = (
            self.HANG
            + '\n{"jsonrpc":"2.0","id":9,"method":"roots/list","params":{}}'
        )
        findings = diagnose(parse_text(text))
        self.assertIn("DIRECTION_AMBIGUOUS", {x.code for x in findings})
        f = [x for x in findings if x.code == "TOOLS_LIST_HANG"][0]
        self.assertEqual(f.severity, "medium")

    def test_missing_capability_lowered_when_ambiguous(self):
        text = (
            '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{}}}\n'
            '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{},"serverInfo":{}}}\n'
            '{"jsonrpc":"2.0","id":3,"method":"elicitation/create","params":{}}'
        )
        findings = diagnose(parse_text(text))
        f = [x for x in findings if x.code == "MISSING_TOOLS_CAPABILITY"][0]
        self.assertEqual(f.severity, "medium")

    def test_direct_evidence_stays_high(self):
        # error responses are direct evidence; capture flags must not soften them
        text = (
            '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}\n'
            '{"jsonrpc":"2.0","id":2,"error":{"code":-32601,"message":"Method not found"}}'
        )
        findings = diagnose(parse_text(text))
        f = [x for x in findings if x.code == "TOOLS_LIST_ERROR"][0]
        self.assertEqual(f.severity, "high")

    def test_url_credentials_redacted(self):
        from mcptriage.rules import redact
        out = redact("GET https://u:p@api.example.com/mcp?api_key=sekrit&q=1 HTTP/1.1")
        self.assertNotIn("sekrit", out)
        self.assertNotIn("u:p@", out)
        self.assertIn("q=1", out)
