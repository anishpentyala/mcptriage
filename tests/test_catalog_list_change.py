"""A list change makes old schema assumptions stale, not newly authoritative."""
import copy
import json
import pytest
from mcptriage.rules import diagnose
from mcptriage.transcript import parse_text


def listing(identifier, required='old'):
    return [{'id': identifier, 'method': 'tools/list'},
            {'id': identifier, 'result': {'tools': [{'name': 'x', 'inputSchema': {
                'type': 'object', 'required': [required]}}]}}]


def call(identifier):
    return [{'id': identifier, 'method': 'tools/call', 'params': {'name': 'x', 'arguments': {}}},
            {'id': identifier, 'error': {'code': -32602}}]


def session(rows):
    return parse_text('\n'.join(map(json.dumps, rows)))


CHANGE = {'method': 'notifications/tools/list_changed'}


@pytest.mark.parametrize('strict', [False, True])
@pytest.mark.parametrize('refresh', [[], [{'id': 5, 'method': 'tools/list'}],
                                    [{'id': 5, 'result': {'tools': []}}],
                                    [{'id': 5, 'method': 'tools/list'},
                                     {'id': 5, 'error': {'code': -32603}}]])
def test_list_change_omits_stale_argument_explanation(strict, refresh):
    s = session(listing(1) + [CHANGE] + refresh + call(10))
    before = copy.deepcopy(s.messages)
    findings = diagnose(s, strict_stdio=strict)
    mismatch = next(f for f in findings if f.code in ('TOOL_CALL_ARG_MISMATCH', 'TOOL_CALL_PROTOCOL_ERROR'))
    assert 'missing required' not in mismatch.why
    assert s.tools_by_name() == {}
    assert s.messages == before


@pytest.mark.parametrize('count', [1, 2, 3])
def test_fresh_paired_catalog_recovers_after_changes(count):
    s = session(listing(1) + [CHANGE] * count + listing(2, 'new') + call(3))
    mismatch = next(f for f in diagnose(s) if f.code in ('TOOL_CALL_ARG_MISMATCH', 'TOOL_CALL_PROTOCOL_ERROR'))
    assert "missing required argument 'new'" in mismatch.why
    assert "missing required argument 'old'" not in mismatch.why


@pytest.mark.parametrize('position', ['before-call', 'between-call-and-error', 'after-error'])
def test_invalidation_is_scoped_to_request_time(position):
    rows = listing(1)
    request, error = call(2)
    if position == 'before-call':
        rows += [CHANGE, request, error]
    elif position == 'between-call-and-error':
        rows += [request, CHANGE, error]
    else:
        rows += [request, error, CHANGE]
    s = session(rows)
    mismatch = next(f for f in diagnose(s) if f.code in ('TOOL_CALL_ARG_MISMATCH', 'TOOL_CALL_PROTOCOL_ERROR'))
    assert ("missing required argument 'old'" in mismatch.why) is (position != 'before-call')
    assert s.tools_by_name() == {}


@pytest.mark.parametrize('method', ['notifications/resources/list_changed',
                                  'notifications/prompts/list_changed',
                                  'notifications/tools/changed', 'tools/list'])
def test_unrelated_notification_does_not_clear_tools(method):
    s = session(listing(1) + [{'method': method}] + call(2))
    mismatch = next(f for f in diagnose(s) if f.code in ('TOOL_CALL_ARG_MISMATCH', 'TOOL_CALL_PROTOCOL_ERROR'))
    assert "missing required argument 'old'" in mismatch.why


def test_request_with_notification_name_is_not_a_notification():
    s = session(listing(1) + [{'id': 20, 'method': CHANGE['method']}] + call(2))
    mismatch = next(f for f in diagnose(s) if f.code in ('TOOL_CALL_ARG_MISMATCH', 'TOOL_CALL_PROTOCOL_ERROR'))
    assert "missing required argument 'old'" in mismatch.why


@pytest.mark.parametrize('mode', ['text', 'json'])
@pytest.mark.parametrize('strict', [False, True])
def test_cli_preserves_generic_error_without_stale_detail(tmp_path, capsys, mode, strict):
    from mcptriage.cli import main
    p = tmp_path / 'capture.jsonl'
    p.write_text('\n'.join(map(json.dumps, listing(1) + [CHANGE] + call(2))))
    main(['diagnose', str(p), '--format', mode] + (['--stdio'] if strict else []))
    output = capsys.readouterr().out
    assert any(code in output for code in ('TOOL_CALL_ARG_MISMATCH', 'TOOL_CALL_PROTOCOL_ERROR'))
    assert 'missing required' not in output


def test_catalog_requested_before_change_cannot_repopulate_stale_evidence():
    request, response = listing(2, 'in-flight')
    s = session(listing(1) + [request, CHANGE, response] + call(3))
    finding = next(f for f in diagnose(s) if f.code in ('TOOL_CALL_ARG_MISMATCH', 'TOOL_CALL_PROTOCOL_ERROR'))
    assert 'missing required' not in finding.why
    assert s.tools_by_name() == {}


def test_change_again_after_fresh_catalog_invalidates_it_again():
    s = session(listing(1) + [CHANGE] + listing(2, 'new') + [CHANGE] + call(3))
    finding = next(f for f in diagnose(s) if f.code in ('TOOL_CALL_ARG_MISMATCH', 'TOOL_CALL_PROTOCOL_ERROR'))
    assert 'missing required' not in finding.why
    assert s.tools_by_name() == {}
