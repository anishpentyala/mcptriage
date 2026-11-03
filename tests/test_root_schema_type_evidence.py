"""Malformed root type values are facts to classify, not report payloads."""
import copy
import json
import pytest
from mcptriage.rules import diagnose
from mcptriage.transcript import parse_text

MARKER = 'ordinary_synthetic_value'
VALUES = [MARKER, MARKER * 10000, [MARKER], {'nested': MARKER},
          ['object'], ['object', 'null'], [], {}, True, False, 1, 1.5]


def capture(declared):
    return '\n'.join(map(json.dumps, [
        {'id': 1, 'method': 'tools/list'},
        {'id': 1, 'result': {'tools': [{'name': 'x', 'inputSchema': {'type': declared}}]}},
    ]))


@pytest.mark.parametrize('declared', VALUES)
@pytest.mark.parametrize('strict', [False, True])
def test_noncanonical_root_type_is_classified_without_echo_or_mutation(declared, strict):
    session = parse_text(capture(declared))
    before = copy.deepcopy(session.messages)
    findings = [f for f in diagnose(session, strict_stdio=strict) if f.code == 'SCHEMA_ISSUES']
    assert len(findings) == 1
    evidence = findings[0].evidence
    assert 'non-object type declaration' in evidence
    assert 'value omitted' in evidence
    assert MARKER not in evidence
    assert len(evidence) < 160
    assert session.messages == before


@pytest.mark.parametrize('declared', ['string', 'number', 'integer', 'boolean', 'array', 'null'])
def test_canonical_nonobject_types_keep_existing_diagnostic(declared):
    finding = next(f for f in diagnose(parse_text(capture(declared))) if f.code == 'SCHEMA_ISSUES')
    assert "inputSchema type is %r (clients expect 'object')" % declared in finding.evidence


@pytest.mark.parametrize('declared', ['object', None])
def test_object_and_unspecified_root_type_keep_existing_behavior(declared):
    assert not any(f.code == 'SCHEMA_ISSUES' for f in diagnose(parse_text(capture(declared))))


@pytest.mark.parametrize('declared', [MARKER * 10000, {MARKER: [MARKER]}])
@pytest.mark.parametrize('mode', ['text', 'json'])
@pytest.mark.parametrize('stdin', [False, True])
def test_cli_never_repeats_noncanonical_type_value(tmp_path, capsys, monkeypatch, declared, mode, stdin):
    from mcptriage.cli import main
    import io
    text = capture(declared)
    if stdin:
        monkeypatch.setattr('sys.stdin', io.StringIO(text))
        path = '-'
    else:
        path = str(tmp_path / 'capture.jsonl')
        (tmp_path / 'capture.jsonl').write_text(text)
    main(['diagnose', path, '--format', mode])
    output = capsys.readouterr().out
    assert 'SCHEMA_ISSUES' in output
    assert 'value omitted' in output
    assert MARKER not in output
    assert len(output) < 5000
