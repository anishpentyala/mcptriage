"""Top-level property types include null and valid JSON Schema type unions."""
import copy
import json
import pytest
from mcptriage.rules import diagnose, validate_arguments
from mcptriage.transcript import parse_text

VALUES = [None, True, False, 0, 1.0, 1.5, "x", [], {}]
TYPES = {
    "null": [None], "boolean": [True, False], "integer": [0, 1.0],
    "number": [0, 1.0, 1.5], "string": ["x"], "array": [[]], "object": [{}],
}

def same(left, right):
    return type(left) is type(right) and left == right

@pytest.mark.parametrize("declared", list(TYPES))
@pytest.mark.parametrize("value", VALUES)
def test_nullable_union_retains_exact_supported_type_semantics(declared, value):
    schema = {"properties": {"x": {"type": [declared, "null"] if declared != "null" else ["null"]}}}
    allowed = value is None or any(same(value, item) for item in TYPES[declared])
    assert bool(validate_arguments(schema, {"x": value})) is not allowed

@pytest.mark.parametrize("value", VALUES)
def test_single_null_type_only_accepts_null(value):
    assert bool(validate_arguments({"properties": {"x": {"type": "null"}}}, {"x": value})) is (value is not None)

@pytest.mark.parametrize("declared", [[], ["string", "unknown"], ["null", "null"],
                                    ["string", {}], ["null", []], [1], [True], [None]])
def test_malformed_union_is_not_partially_used_as_type_evidence(declared):
    assert validate_arguments({"properties": {"x": {"type": declared}}}, {"x": 42}) == []

@pytest.mark.parametrize("strict", [False, True])
@pytest.mark.parametrize("value", [None, "ok", 42, True])
def test_captured_union_explanation_and_request_time_schema(strict, value):
    rows = [
        {"id": 1, "method": "tools/list"},
        {"id": 1, "result": {"tools": [{"name": "x", "inputSchema": {
            "properties": {"arg": {"type": ["string", "null"]}}}}]}},
        {"id": 2, "method": "tools/call", "params": {"name": "x", "arguments": {"arg": value}}},
        {"id": 3, "method": "tools/list"},
        {"id": 3, "result": {"tools": [{"name": "x", "inputSchema": {"properties": {"arg": {"type": "boolean"}}}}]}},
        {"id": 2, "error": {"code": -32602}},
    ]
    text = "\n".join(map(json.dumps, rows))
    session = parse_text(text)
    before = copy.deepcopy(session.messages)
    finding = next(f for f in diagnose(session, strict_stdio=strict) if f.code in ('TOOL_CALL_ARG_MISMATCH', 'TOOL_CALL_PROTOCOL_ERROR'))
    assert ("should be string or null" in finding.why) is (value is not None and not isinstance(value, str))
    assert "should be boolean" not in finding.why
    assert session.messages == before

@pytest.mark.parametrize("declared", ["null", ["string", "null"]])
def test_required_is_presence_not_nullable_value(declared):
    schema = {"required": ["x"], "properties": {"x": {"type": declared}}}
    assert validate_arguments(schema, {}) == ["missing required argument 'x'"]
    assert validate_arguments(schema, {"x": None}) == []

@pytest.mark.parametrize("value", [None, "ok", 42])
def test_union_does_not_override_enum_constraint(value):
    schema = {"properties": {"x": {"type": ["string", "null"], "enum": ["ok"]}}}
    problems = validate_arguments(schema, {"x": value})
    assert any("not one of" in p for p in problems) is (value != "ok")
    assert any("should be" in p for p in problems) is (value == 42)

@pytest.mark.parametrize("mode", ["text", "json"])
@pytest.mark.parametrize("source", ["file", "stdin"])
@pytest.mark.parametrize("value", [None, "ok", 42])
def test_cli_union_detail_preserves_generic_invalid_params(tmp_path, capsys, monkeypatch, mode, source, value):
    import io
    from mcptriage.cli import main
    rows = [
        {"id": 1, "method": "tools/list"},
        {"id": 1, "result": {"tools": [{"name": "x", "inputSchema": {"properties": {"arg": {"type": ["string", "null"]}}}}]}},
        {"id": 2, "method": "tools/call", "params": {"name": "x", "arguments": {"arg": value}}},
        {"id": 2, "error": {"code": -32602}},
    ]
    text = "\n".join(map(json.dumps, rows))
    path = tmp_path / "capture.jsonl"
    path.write_text(text)
    monkeypatch.setattr("sys.stdin", io.StringIO(text))
    assert main(["diagnose", str(path) if source == "file" else "-", "--format", mode]) == 1
    out = capsys.readouterr()
    assert not out.err
    assert ("TOOL_CALL_ARG_MISMATCH" if value == 42 else "TOOL_CALL_PROTOCOL_ERROR") in out.out
    assert ("should be string or null" in out.out) is (value == 42)
