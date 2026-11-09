"""A malformed declared property is not evidence of an undeclared argument."""
import copy
import json
import pytest
from mcptriage.rules import diagnose, validate_arguments
from mcptriage.transcript import parse_text

BAD = [None, [], ['string'], 'string', 0, 1, 1.5]


@pytest.mark.parametrize('spec', BAD)
@pytest.mark.parametrize('value', [None, 1, 'x', True, [], {}])
def test_declared_malformed_property_not_called_additional(spec, value):
    schema = {'properties': {'x': spec}, 'additionalProperties': False}
    args = {'x': value}
    before = copy.deepcopy([schema, args])
    assert validate_arguments(schema, args) == []
    assert [schema, args] == before


@pytest.mark.parametrize('spec', BAD)
def test_actual_undeclared_argument_still_rejected(spec):
    schema = {'properties': {'x': spec}, 'additionalProperties': False}
    assert validate_arguments(schema, {'x': 1, 'other': 2}) == [
        "unexpected argument 'other' (schema sets additionalProperties: false)"]


@pytest.mark.parametrize('spec,expected', [(True, []), (False, ["argument 'x' is not allowed by the schema"]),
                                         ({}, []), ({'type': 'string'}, ["argument 'x' should be string but got int"])])
def test_usable_declared_property_behavior_unchanged(spec, expected):
    assert validate_arguments({'properties': {'x': spec}, 'additionalProperties': False}, {'x': 1}) == expected


@pytest.mark.parametrize('spec', BAD)
@pytest.mark.parametrize('strict', [False, True])
def test_transcript_generic_invalidparams_has_no_fabricated_additional_detail(spec, strict):
    rows = [{'id': 1, 'method': 'tools/list'},
            {'id': 1, 'result': {'tools': [{'name': 'x', 'inputSchema': {
                'properties': {'arg': spec}, 'additionalProperties': False}}]}},
            {'id': 2, 'method': 'tools/call', 'params': {'name': 'x', 'arguments': {'arg': 1}}},
            {'id': 2, 'error': {'code': -32602}}]
    session = parse_text('\n'.join(map(json.dumps, rows)))
    finding = next(f for f in diagnose(session, strict_stdio=strict) if f.code=='TOOL_CALL_PROTOCOL_ERROR')
    assert 'unexpected argument' not in finding.why


@pytest.mark.parametrize('mode', ['text', 'json'])
def test_cli_keeps_real_unexpected_argument_and_omits_declared_one(tmp_path, capsys, mode):
    from mcptriage.cli import main
    rows = [{'id': 1, 'method': 'tools/list'},
            {'id': 1, 'result': {'tools': [{'name': 'x', 'inputSchema': {
                'properties': {'arg': None}, 'additionalProperties': False}}]}},
            {'id': 2, 'method': 'tools/call', 'params': {'name': 'x', 'arguments': {'arg': 1, 'other': 2}}},
            {'id': 2, 'error': {'code': -32602}}]
    path = tmp_path / 'capture.jsonl'
    path.write_text('\n'.join(map(json.dumps, rows)))
    assert main(['diagnose', str(path), '--format', mode]) == 1
    output = capsys.readouterr().out
    assert "unexpected argument 'arg'" not in output
    assert "unexpected argument 'other'" in output
