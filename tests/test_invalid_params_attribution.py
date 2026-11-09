"""An invalid-params code does not independently establish bad tool arguments."""
import copy
import json
import subprocess
import sys

import pytest

from mcptriage.rules import diagnose
from mcptriage.transcript import parse_text


INIT = [
    {'jsonrpc': '2.0', 'id': 'init', 'method': 'initialize'},
    {'jsonrpc': '2.0', 'id': 'init', 'result': {'capabilities': {'tools': {}}}},
    {'jsonrpc': '2.0', 'method': 'notifications/initialized'},
]
SCHEMA = {'type': 'object', 'properties': {'x': {'type': 'integer'}}, 'required': ['x']}
PRIVATE = 'PRIVATE_UNTRUSTED_ERROR_MESSAGE'


def listing(schema=SCHEMA, name='known', identifier='list'):
    return [
        {'jsonrpc': '2.0', 'id': identifier, 'method': 'tools/list'},
        {'jsonrpc': '2.0', 'id': identifier, 'result': {'tools': [{'name': name, 'inputSchema': schema}]}},
    ]


def call(arguments=None, name='known', code=-32602):
    return [
        {'jsonrpc': '2.0', 'id': 'call', 'method': 'tools/call',
         'params': {'name': name, 'arguments': {} if arguments is None else arguments}},
        {'jsonrpc': '2.0', 'id': 'call', 'error': {'code': code, 'message': PRIVATE}},
    ]


def call_findings(rows):
    return [f for f in diagnose(parse_text('\n'.join(json.dumps(row) for row in INIT + rows)))
            if f.code.startswith('TOOL_CALL_')]


UNPROVEN = [
    call(name='invalid_tool_name'),  # Official MCP protocol-error example.
    listing() + call({'x': 1}),
    listing() + call({}, name='not_in_catalog'),
    listing({'type': 'object'}) + call(),
    listing({'properties': {'x': {'pattern': '^a'}}}) + call({'x': 'b'}),
    call() + listing(),  # A later schema cannot explain an earlier rejection.
    listing() + [{'jsonrpc': '2.0', 'method': 'notifications/tools/list_changed'}] + call(),
    listing() + call('not-an-object'),
    listing() + call([], name='known'),
    listing({'properties': {'x': {'type': ['integer', 'bogus']}}}) + call({'x': 'text'}),
    listing({'properties': {}, 'patternProperties': {'^x': {}}, 'additionalProperties': False}) + call({'x': 1}),
]


@pytest.mark.parametrize('rows', UNPROVEN)
def test_unproven_invalid_params_keeps_generic_protocol_error(rows):
    findings = call_findings(rows)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.code == 'TOOL_CALL_PROTOCOL_ERROR'
    assert finding.severity == 'high'
    assert 'does not prove' in finding.why
    assert 'inputSchema' not in finding.fix
    assert PRIVATE not in finding.why and PRIVATE not in finding.fix


@pytest.mark.parametrize('arguments', [{}, {'x': 'bad'}, {'x': False}, {'x': 1.5}])
def test_independent_schema_violation_keeps_argument_diagnosis(arguments):
    finding, = call_findings(listing() + call(arguments))
    assert finding.code == 'TOOL_CALL_ARG_MISMATCH'
    assert 'Arguments violate' in finding.why
    assert finding.severity == 'high'


@pytest.mark.parametrize('arguments', [{}, {'x': 'bad'}])
@pytest.mark.parametrize('kind', ['success', 'execution-error'])
def test_schema_violation_does_not_invent_rejection_on_other_results(arguments, kind):
    rows = listing() + call(arguments)
    rows[-1] = {'jsonrpc': '2.0', 'id': 'call', 'result': {'content': [], 'isError': kind == 'execution-error'}}
    findings = call_findings(rows)
    assert [f.code for f in findings] == (['TOOL_CALL_FAILED'] if kind == 'execution-error' else [])


@pytest.mark.parametrize('code', [-32601, -32603, -32000])
def test_other_protocol_codes_never_promote_schema_violation(code):
    finding, = call_findings(listing() + call({}, code=code))
    assert finding.code == 'TOOL_CALL_PROTOCOL_ERROR'


@pytest.mark.parametrize('mode', ['text', 'json'])
def test_actual_cli_unknown_tool_retains_high_exit_and_no_unproved_argument_claim(tmp_path, mode):
    path = tmp_path / 'unknown-tool.jsonl'
    path.write_text('\n'.join(json.dumps(row) for row in INIT + call(name='invalid_tool_name')), encoding='utf-8')
    result = subprocess.run([sys.executable, '-m', 'mcptriage', 'diagnose', str(path), '--format', mode],
                            capture_output=True, text=True)
    assert result.returncode == 1
    assert 'TOOL_CALL_PROTOCOL_ERROR' in result.stdout
    assert 'TOOL_CALL_ARG_MISMATCH' not in result.stdout
    assert 'Fix the caller to send arguments matching' not in result.stdout


def test_no_input_mutation_and_repeat_determinism():
    rows = listing() + call({'x': 1})
    before = copy.deepcopy(rows)
    first = call_findings(rows)
    assert call_findings(rows) == first
    assert rows == before


@pytest.mark.parametrize('message', ['Unknown tool: known', 'arguments are invalid', PRIVATE, '', None])
@pytest.mark.parametrize('violated', [False, True])
def test_untrusted_error_message_never_selects_attribution(message, violated):
    rows = listing() + call({} if violated else {'x': 1})
    rows[-1]['error']['message'] = message
    finding, = call_findings(rows)
    assert finding.code == ('TOOL_CALL_ARG_MISMATCH' if violated else 'TOOL_CALL_PROTOCOL_ERROR')
    if violated:
        assert 'not proof of the server' in finding.why


@pytest.mark.parametrize('wire', ['-32602.0', '-32602e0'])
def test_integral_wire_code_has_same_conservative_meaning(wire):
    text = '\n'.join(json.dumps(row) for row in INIT + call(name='invalid_tool_name'))
    text = text.replace('"code": -32602', '"code": ' + wire)
    finding, = [f for f in diagnose(parse_text(text)) if f.code.startswith('TOOL_CALL_')]
    assert finding.code == 'TOOL_CALL_PROTOCOL_ERROR'
    assert finding.severity == 'high'


@pytest.mark.parametrize('mode', ['text', 'json'])
@pytest.mark.parametrize('override', [False, True])
def test_shipped_unknown_tool_example_category_and_exit(mode, override):
    from pathlib import Path
    path = Path(__file__).resolve().parents[1] / 'examples' / 'unknown-tool-invalid-params.jsonl'
    args = [sys.executable, '-m', 'mcptriage', 'diagnose', str(path), '--format', mode]
    if override:
        args.append('--exit-zero')
    result = subprocess.run(args, capture_output=True, text=True)
    assert result.returncode == (0 if override else 1)
    assert not result.stderr
    assert 'TOOL_CALL_PROTOCOL_ERROR' in result.stdout
    assert 'TOOL_CALL_ARG_MISMATCH' not in result.stdout
    if mode == 'json':
        payload = json.loads(result.stdout)
        assert [f['code'] for f in payload['findings']] == ['TOOL_CALL_PROTOCOL_ERROR']
        assert payload['findings'][0]['severity'] == 'high'
