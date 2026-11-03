"""Deep or long server version-detail data must not abort a diagnosis."""

import json
import pytest
from mcptriage.rules import diagnose
from mcptriage.transcript import parse_text


def wire(value):
    return "\n".join(
        [
            '{"id":0,"method":"initialize"}',
            '{"id":0,"result":{"capabilities":{"tools":{}}}}',
            '{"method":"notifications/initialized"}',
            '{"id":1,"method":"tools/list"}',
            '{"id":1,"error":{"code":-32022,"message":"version mismatch","data":{"supported":'
            + value
            + "}}}",
        ]
    )


@pytest.mark.parametrize("kind", ["array", "object"])
@pytest.mark.parametrize("depth", [30, 1200, 2400])
def test_deep_supported_detail_does_not_abort_diagnosis(kind, depth):
    value = '"v-next"'
    for _ in range(depth):
        value = "[" + value + "]" if kind == "array" else '{"v":' + value + "}"
    text = wire(value)
    session = parse_text(text)
    findings = diagnose(session)
    if len(session.parsed) == 5:
        found = [f for f in findings if f.code == "TOOLS_LIST_ERROR"]
        assert len(found) == 1 and found[0].severity == "high"
        assert len(found[0].why) < 700
    else:
        assert session.unparsed and any(f.code == "TOOLS_LIST_HANG" for f in findings)


@pytest.mark.parametrize("value", [["v-next"] * 10000, "x" * 10000, {"v": "x" * 10000}])
def test_large_detail_is_bounded_without_changing_error(value):
    findings = diagnose(parse_text(wire(json.dumps(value))))
    found = next(f for f in findings if f.code == "TOOLS_LIST_ERROR")
    assert len(found.why) < 700
    assert "Server supports:" in found.why


@pytest.mark.parametrize("value", [["2026-07-28"], ["a", "b"], "next", {"v": "next"}])
def test_short_detail_keeps_existing_readable_representation(value):
    found = next(
        f
        for f in diagnose(parse_text(wire(json.dumps(value))))
        if f.code == "TOOLS_LIST_ERROR"
    )
    assert "Server supports: %s." % value in found.why


@pytest.mark.parametrize("value", [None, False, 0, [], {}, ""])
def test_empty_detail_keeps_existing_no_extra_claim(value):
    found = next(
        f
        for f in diagnose(parse_text(wire(json.dumps(value))))
        if f.code == "TOOLS_LIST_ERROR"
    )
    assert "Server supports:" not in found.why


@pytest.mark.parametrize("mode", ["text", "json"])
@pytest.mark.parametrize("source", ["file", "stdin"])
def test_cli_accepted_deep_detail_has_no_traceback_and_bounded_output(
    tmp_path, mode, source
):
    import subprocess, sys

    text = wire("[" * 2000 + '"v-next"' + "]" * 2000)
    accepted = len(parse_text(text).parsed) == 5
    path = tmp_path / "versions.jsonl"
    path.write_text(text)
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "mcptriage",
            "diagnose",
            str(path) if source == "file" else "-",
            "--format",
            mode,
        ],
        input=text if source == "stdin" else None,
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert not result.stderr, (
        "CLI must not emit a traceback for accepted deep version details"
    )
    assert result.returncode == 1 and len(result.stdout) < 3000
    if accepted:
        assert "TOOLS_LIST_ERROR" in result.stdout
        if mode == "json":
            assert json.loads(result.stdout)["finding_count"] == 1
    else:
        assert "TOOLS_LIST_HANG" in result.stdout


@pytest.mark.parametrize("mode", ["text", "json"])
def test_known_json_credential_is_masked_before_detail_clipping(mode):
    from mcptriage.report import render_json, render_text

    secret = "SYNTHETIC_PRIVATE_SUFFIX" * 60
    text = wire(json.dumps(json.dumps({"token": secret, "version": "next"})))
    findings = diagnose(parse_text(text))
    output = (render_json if mode == "json" else render_text)(findings, "synthetic")
    assert "SYNTHETIC_PRIVATE_SUFFIX" not in output
    assert "***" in output
    if mode == "json":
        json.loads(output)


@pytest.mark.parametrize("escape", ['quote"', "backslash\\"])
@pytest.mark.parametrize("mode", ["text", "json"])
def test_long_escaped_supported_detail_omits_synthetic_secret(escape, mode):
    from mcptriage.report import render_json, render_text

    value = [json.dumps({"token": escape + "SYNTHETIC_VERSION_CANARY" * 60})]
    fs = diagnose(parse_text(wire(json.dumps(value))))
    output = (render_json if mode == "json" else render_text)(fs, "synthetic")
    assert "SYNTHETIC_VERSION_CANARY" not in output
    assert "TOOLS_LIST_ERROR" in output


@pytest.mark.parametrize("length", [319, 320, 321])
@pytest.mark.parametrize("shape", ["string", "array", "object"])
def test_summary_budget_boundary_preserves_short_values_and_omits_long(length, shape):
    if shape == "string":
        value = "v" * length
    elif shape == "array":
        value = ["v" * (length - 4)]
    else:
        value = {"v": "v" * (length - 9)}
    assert len(str(value)) == length
    found = next(
        f
        for f in diagnose(parse_text(wire(json.dumps(value))))
        if f.code == "TOOLS_LIST_ERROR"
    )
    if length <= 320:
        assert "Server supports: %s." % value in found.why
    else:
        assert "[version details too long to display]" in found.why
        assert "v" * 50 not in found.why


@pytest.mark.parametrize("code", [-32602, -32603, -32000])
def test_other_error_codes_do_not_claim_supported_versions(code):
    text = wire(json.dumps(["unexpected-version"])).replace(
        '"code":-32022', '"code":%s' % code
    )
    found = next(f for f in diagnose(parse_text(text)) if f.code == "TOOLS_LIST_ERROR")
    assert "Server supports:" not in found.why
    assert "unexpected-version" not in found.why
