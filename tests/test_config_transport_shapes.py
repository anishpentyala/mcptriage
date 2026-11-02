"""Malformed transport fields are data, not text to echo or recurse through."""

import json
import pytest
from mcptriage.configcheck import check_config_text

BAD_TYPES = [
    None,
    False,
    True,
    0,
    1,
    0.5,
    [],
    {},
    ["SYNTHETIC_TRANSPORT_SECRET"],
    {"key": "SYNTHETIC_TRANSPORT_SECRET"},
]


def findings(value):
    return check_config_text(
        json.dumps(
            {"mcpServers": {"x": {"url": "https://example.test/mcp", "type": value}}}
        )
    )


@pytest.mark.parametrize("value", BAD_TYPES)
def test_non_string_transport_is_reported_without_echo(value):
    fs = findings(value)
    assert any(
        f.code == "CFG_SHAPE" and "type" in f.title and f.severity == "medium"
        for f in fs
    )
    assert all("SYNTHETIC_TRANSPORT_SECRET" not in str(f) for f in fs)


@pytest.mark.parametrize("value", ["stdio", "sse", "http", "streamable-http"])
def test_known_transport_string_does_not_change(value):
    assert not any(f.code == "CFG_SHAPE" for f in findings(value))


def test_unknown_string_keeps_existing_low_severity():
    fs = findings("future-transport")
    assert any(
        f.code == "CFG_SHAPE" and f.severity == "low" and "unrecognized" in f.title
        for f in fs
    )


def test_missing_transport_is_not_a_new_requirement():
    fs = check_config_text('{"mcpServers":{"x":{"url":"https://example.test/mcp"}}}')
    assert not any(f.code == "CFG_SHAPE" for f in fs)


@pytest.mark.parametrize("mode", ["text", "json"])
@pytest.mark.parametrize("value", BAD_TYPES)
def test_cli_reports_malformed_transport_without_secret_or_traceback(
    tmp_path, capsys, mode, value
):
    from mcptriage.cli import main

    path = tmp_path / "config.json"
    path.write_text(
        json.dumps(
            {"mcpServers": {"x": {"url": "https://example.test/mcp", "type": value}}}
        )
    )
    status = main(["check-config", str(path), "--format", mode])
    output = capsys.readouterr()
    assert "CFG_SHAPE" in output.out
    assert "SYNTHETIC_TRANSPORT_SECRET" not in output.out
    assert not output.err
    assert (
        status == 0
    )  # Malformed transport is medium, not a newly fatal endpoint error.


@pytest.mark.parametrize("mode", ["text", "json"])
def test_accepted_deep_transport_does_not_crash_cli(tmp_path, capsys, mode):
    from mcptriage.cli import main

    value = "[" * 2000 + '"SYNTHETIC_TRANSPORT_SECRET"' + "]" * 2000
    text = (
        '{"mcpServers":{"x":{"url":"https://example.test/mcp","type":' + value + "}}}"
    )
    path = tmp_path / "deep.json"
    path.write_text(text)
    accepted = True
    try:
        json.loads(text)
    except RecursionError:
        accepted = False
    status = main(["check-config", str(path), "--format", mode])
    output = capsys.readouterr()
    assert "SYNTHETIC_TRANSPORT_SECRET" not in output.out and not output.err
    assert ("CFG_SHAPE" if accepted else "CFG_JSON_LIMIT") in output.out
    assert status == (0 if accepted else 1)
