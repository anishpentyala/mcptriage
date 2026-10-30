import unittest

from mcptriage.transcript import parse_text


def init_pair(version="2025-11-25", tools=True):
    caps = '"tools":{"listChanged":true}' if tools else ""
    return (
        '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"%s","capabilities":{},"clientInfo":{"name":"c","version":"1"}}}\n'
        '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"%s","capabilities":{%s},"serverInfo":{"name":"s","version":"1"}}}'
        % (version, version, caps)
    )


class ParseTest(unittest.TestCase):
    def test_bare_json_lines(self):
        s = parse_text(init_pair())
        self.assertEqual(len(s.parsed), 2)
        self.assertEqual(s.unparsed, [])
        kinds = [m.kind for m in s.parsed]
        self.assertEqual(kinds, ["request", "response"])

    def test_log_prefix_extraction(self):
        s = parse_text('2026-10-29T12:00:00 [mcp] ' + init_pair().splitlines()[0])
        self.assertEqual(len(s.parsed), 1)
        self.assertTrue(s.parsed[0].extracted)

    def test_unparsed_lines_kept(self):
        s = parse_text("Server starting...\n" + init_pair().splitlines()[0])
        self.assertEqual(len(s.unparsed), 1)
        self.assertEqual(s.unparsed[0].line_no, 1)

    def test_blank_lines_ignored(self):
        s = parse_text("\n\n" + init_pair().replace("\n", "\n\n"))
        self.assertEqual(len(s.parsed), 2)

    def test_notification_classification(self):
        s = parse_text('{"jsonrpc":"2.0","method":"notifications/initialized"}')
        self.assertEqual(s.parsed[0].kind, "notification")

    def test_json_without_rpc_shape_is_unparsed(self):
        s = parse_text('{"some":"other json"}')
        self.assertEqual(len(s.unparsed), 1)
        self.assertEqual(s.parsed, [])

    def test_array_json_is_unparsed(self):
        s = parse_text('[1,2,3]')
        self.assertEqual(len(s.unparsed), 1)


class SessionModelTest(unittest.TestCase):
    def test_response_for_matches_id(self):
        s = parse_text(init_pair())
        req = s.requests("initialize")[0]
        resp = s.response_for(req)
        self.assertIsNotNone(resp)
        self.assertEqual(resp.msg_id, 1)

    def test_response_for_ignores_earlier_lines(self):
        text = (
            '{"jsonrpc":"2.0","id":9,"result":{"tools":[]}}\n'
            '{"jsonrpc":"2.0","id":9,"method":"tools/list","params":{}}\n'
            '{"jsonrpc":"2.0","id":9,"result":{"tools":[]}}'
        )
        s = parse_text(text)
        req = s.requests("tools/list")[0]
        resp = s.response_for(req)
        self.assertEqual(resp.line_no, 3)

    def test_orphan_responses(self):
        s = parse_text('{"jsonrpc":"2.0","id":7,"result":{}}')
        self.assertEqual(len(s.orphan_responses()), 1)

    def test_tools_by_name_collects_schemas(self):
        text = (
            init_pair()
            + '\n{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}\n'
            + '{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"a","inputSchema":{"type":"object"}},{"name":"b"}]}}'
        )
        s = parse_text(text)
        tools = s.tools_by_name()
        self.assertEqual(set(tools), {"a", "b"})
        self.assertEqual(tools["b"], {})

    def test_tools_by_name_respects_before_line(self):
        text = (
            init_pair()
            + '\n{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}\n'
            + '{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"a","inputSchema":{"type":"object"}}]}}'
        )
        s = parse_text(text)
        self.assertEqual(s.tools_by_name(before_line=4), {})

    def test_modern_markers_server_discover(self):
        s = parse_text('{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{}}')
        self.assertTrue(s.has_modern_markers())

    def test_modern_markers_meta_version(self):
        s = parse_text(
            '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"protocolVersion":"2026-07-28"}}}'
        )
        self.assertTrue(s.has_modern_markers())

    def test_no_modern_markers_in_legacy(self):
        s = parse_text(init_pair())
        self.assertFalse(s.has_modern_markers())


if __name__ == "__main__":
    unittest.main()
