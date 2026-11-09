"""Repeated names in one list response cannot select a schema by array order."""
import copy
import itertools
import json
import pytest
from mcptriage.rules import diagnose
from mcptriage.transcript import parse_text

def tool(name, required):
    return {"name": name, "inputSchema": {"required": [required]}}

def listing(identifier, tools):
    return [{"id": identifier, "method": "tools/list"}, {"id": identifier, "result": {"tools": tools}}]

def call(identifier, name):
    return [{"id": identifier, "method": "tools/call", "params": {"name": name, "arguments": {}}}, {"id": identifier, "error": {"code": -32602}}]

def session(rows):
    return parse_text("\n".join(map(json.dumps, rows)))

@pytest.mark.parametrize("definitions", list(itertools.permutations([tool("x", "a"), tool("x", "b"), tool("safe", "s")])))
@pytest.mark.parametrize("strict", [False, True])
def test_duplicate_definition_order_cannot_choose_schema(definitions, strict):
    s = session(listing(1, definitions) + call(2, "x") + call(3, "safe"))
    old = copy.deepcopy(s.messages)
    assert s.tools_by_name() == {"safe": {"required": ["s"]}}
    findings = diagnose(s, strict_stdio=strict)
    assert any(f.code == "DUPLICATE_TOOL_NAMES" for f in findings)
    calls = [f for f in findings if f.code in ('TOOL_CALL_ARG_MISMATCH', 'TOOL_CALL_PROTOCOL_ERROR')]
    x = next(f for f in calls if "'x'" in f.title)
    safe = next(f for f in calls if "'safe'" in f.title)
    assert "missing required" not in x.why
    assert "missing required argument 's'" in safe.why
    assert s.messages == old

@pytest.mark.parametrize("same", [False, True])
def test_duplicate_clears_older_schema_without_guessing_equality(same):
    duplicate = [tool("x", "new"), tool("x", "new" if same else "other")]
    s = session(listing(1, [tool("x", "old")]) + listing(2, duplicate) + call(3, "x"))
    assert "x" not in s.tools_by_name()
    assert "missing required" not in next(f.why for f in diagnose(s) if f.code in ('TOOL_CALL_ARG_MISMATCH', 'TOOL_CALL_PROTOCOL_ERROR'))

@pytest.mark.parametrize("changed_after_call", [False, True])
def test_later_unique_response_recovers_without_rewriting_request_time(changed_after_call):
    rows = listing(1, [tool("x", "a"), tool("x", "b")])
    c = call(3, "x")
    update = listing(2, [tool("x", "new")])
    rows += [c[0]] + update + [c[1]] if changed_after_call else update + c
    s = session(rows)
    finding = next(f for f in diagnose(s) if f.code in ('TOOL_CALL_ARG_MISMATCH', 'TOOL_CALL_PROTOCOL_ERROR'))
    assert ("missing required argument 'new'" in finding.why) is not changed_after_call
    assert s.tools_by_name() == {"x": {"required": ["new"]}}

@pytest.mark.parametrize("method", ["initialize", "resources/list", "tools/call"])
def test_other_methods_do_not_produce_catalog_duplicate_finding(method):
    rows = [{"id": 1, "method": method}, {"id": 1, "result": {"tools": [tool("x", "a"), tool("x", "b")]}}]
    assert not any(f.code == "DUPLICATE_TOOL_NAMES" for f in diagnose(session(rows)))

@pytest.mark.parametrize("names", [["x", "X"], ["x", "y"], [], ["x"]])
def test_case_sensitive_unique_names_stay_usable(names):
    s = session(listing(1, [tool(n, n) for n in names]))
    assert set(s.tools_by_name()) == set(names)
    assert not any(f.code == "DUPLICATE_TOOL_NAMES" for f in diagnose(s))

@pytest.mark.parametrize("mode", ["text", "json"])
def test_cli_surfaces_duplicate_without_invented_schema(tmp_path, capsys, mode):
    from mcptriage.cli import main
    path = tmp_path / "capture.jsonl"
    path.write_text("\n".join(map(json.dumps, listing(1, [tool("x", "a"), tool("x", "b")]) + call(2, "x"))))
    assert main(["diagnose", str(path), "--format", mode]) == 1
    out = capsys.readouterr()
    assert not out.err
    assert "DUPLICATE_TOOL_NAMES" in out.out
    assert "missing required" not in out.out

@pytest.mark.parametrize("rows", [
    [{"id": 1, "result": {"tools": [tool("x", "a"), tool("x", "b")]}}],
    [{"id": 1, "method": "tools/list"}, {"id": "1", "result": {"tools": [tool("x", "a"), tool("x", "b")]}}],
    [{"id": 1, "method": "tools/list"}, {"id": 1, "result": {"tools": [tool("x", "a"), tool("x", "b")]}, "error": {"code": -32603}}],
    [{"id": 1, "method": "tools/list"}, {"id": 1, "error": {"code": -32603}}, {"id": 1, "result": {"tools": [tool("x", "a"), tool("x", "b")]}}],
])
def test_unproven_or_unusable_response_not_called_duplicate_catalog(rows):
    assert not any(f.code == "DUPLICATE_TOOL_NAMES" for f in diagnose(session(rows)))


def test_counts_repeated_names_not_extra_entries():
    s = session(listing(1, [tool("x", "a"), tool("x", "b"), tool("x", "c")]))
    findings = [f for f in diagnose(s) if f.code == "DUPLICATE_TOOL_NAMES"]
    assert len(findings) == 1
    assert findings[0].title == "tools/list response repeats 1 tool name(s)"


def test_separate_paginated_lists_are_not_one_duplicated_array():
    s = session(listing(1, [tool("x", "a")]) + listing(2, [tool("x", "b")]))
    assert s.tools_by_name() == {"x": {"required": ["b"]}}
    assert not any(f.code == "DUPLICATE_TOOL_NAMES" for f in diagnose(s))
