"""Call outcomes that do not validate arguments must not rebuild catalogs."""

import json
import pytest
from mcptriage.rules import diagnose
from mcptriage.transcript import Session, parse_text


@pytest.mark.parametrize(
    "response",
    [
        {"result": {"content": []}},
        {"result": {"isError": False}},
        {"result": {"isError": True, "content": [{"text": "failed"}]}},
        {"error": {"code": -32603}},
        {"error": {"code": -32602}},
    ],
)
@pytest.mark.parametrize("arguments", [None, [], {}, {"x": 1}])
def test_only_object_arguments_on_invalid_params_need_catalog(
    monkeypatch, response, arguments
):
    calls = []
    original = Session.tools_by_name

    def watched(self, *args, **kwargs):
        calls.append(kwargs.get("before_line"))
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Session, "tools_by_name", watched)
    text = "\n".join(
        map(
            json.dumps,
            [
                {
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": "x", "arguments": arguments},
                },
                dict(id=1, **response),
            ],
        )
    )
    diagnose(parse_text(text))
    needed = response.get("error", {}).get("code") == -32602 and isinstance(
        arguments, dict
    )
    assert len(calls) == int(needed)


class CountedMessages(list):
    def __init__(self, values):
        super().__init__(values)
        self.visited = 0

    def __iter__(self):
        for value in super().__iter__():
            self.visited += 1
            yield value


def measured(n):
    rows = [
        {"id": 0, "method": "initialize"},
        {"id": 0, "result": {"capabilities": {"tools": {}}}},
        {"method": "notifications/initialized"},
        {"id": -1, "method": "tools/list"},
        {"id": -1, "result": {"tools": [{"name": "x", "inputSchema": {}}]}},
    ]
    for i in range(1, n + 1):
        rows += [
            {"id": i, "method": "tools/call", "params": {"name": "x", "arguments": {}}},
            {"id": i, "result": {"content": []}},
        ]
    session = parse_text("\n".join(map(json.dumps, rows)))
    session.messages = CountedMessages(session.messages)
    assert diagnose(session) == []
    return session.messages.visited


def test_successful_call_diagnosis_does_not_scan_catalog_for_each_call():
    small = measured(40)
    large = measured(160)
    assert large <= 5 * small


@pytest.mark.parametrize(
    "response",
    [
        {"result": {}, "error": {"code": -32602}},
        {"error": {"code": "-32602"}},
        {"error": {"code": True}},
        {"error": None},
        {"result": None},
    ],
)
def test_unusable_envelopes_never_read_call_catalog(monkeypatch, response):
    def forbidden(*args, **kwargs):
        pytest.fail("unusable outcomes must not rebuild the catalog")

    monkeypatch.setattr(Session, "tools_by_name", forbidden)
    rows = [
        {"id": 1, "method": "tools/call", "params": {"name": "x", "arguments": {}}},
        dict(id=1, **response),
    ]
    diagnose(parse_text("\n".join(map(json.dumps, rows))))


@pytest.mark.parametrize("strict", [False, True])
@pytest.mark.parametrize("changed_after_call", [False, True])
def test_lazy_lookup_keeps_request_time_schema(monkeypatch, strict, changed_after_call):
    old = {"name": "x", "inputSchema": {"type": "object", "required": ["old"]}}
    new = {"name": "x", "inputSchema": {"type": "object", "required": ["new"]}}
    rows = [{"id": 0, "method": "tools/list"}, {"id": 0, "result": {"tools": [old]}}]
    call = {"id": 1, "method": "tools/call", "params": {"name": "x", "arguments": {}}}
    update = [{"id": 2, "method": "tools/list"}, {"id": 2, "result": {"tools": [new]}}]
    rows += [call] + update if changed_after_call else update + [call]
    rows += [{"id": 1, "error": {"code": -32602}}]
    calls = []
    original = Session.tools_by_name

    def watched(self, *args, **kwargs):
        calls.append(kwargs.get("before_line"))
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Session, "tools_by_name", watched)
    session = parse_text("\n".join(map(json.dumps, rows)))
    findings = diagnose(session, strict_stdio=strict)
    mismatch = next(f for f in findings if f.code == "TOOL_CALL_ARG_MISMATCH")
    expected = "old" if changed_after_call else "new"
    unexpected = "new" if changed_after_call else "old"
    assert "'%s'" % expected in mismatch.why
    assert "'%s'" % unexpected not in mismatch.why
    assert calls == [session.requests("tools/call")[0].line_no]
