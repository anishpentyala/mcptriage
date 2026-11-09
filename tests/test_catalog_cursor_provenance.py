"""A continuation can supply schemas only through its observed cursor chain."""
import json

import pytest

from mcptriage.rules import diagnose
from mcptriage.transcript import parse_text


OLD = {'name': 'old', 'inputSchema': {'required': ['old_required']}}
PAGE = {'name': 'page', 'inputSchema': {'required': ['page_required']}}


def session(rows):
    return parse_text('\n'.join(map(json.dumps, rows)))


def listing(cursor='next'):
    return [{'id': 1, 'method': 'tools/list'},
            {'id': 1, 'result': {'tools': [OLD], 'nextCursor': cursor}}]


def page(cursor='next', next_cursor=None):
    result = {'tools': [PAGE]}
    if next_cursor is not None:
        result['nextCursor'] = next_cursor
    return [{'id': 2, 'method': 'tools/list', 'params': {'cursor': cursor}},
            {'id': 2, 'result': result}]


def call():
    return [{'id': 3, 'method': 'tools/call',
             'params': {'name': 'page', 'arguments': {}}},
            {'id': 3, 'error': {'code': -32602}}]


@pytest.mark.parametrize('rows', [
    page(),
    listing() + page('wrong'),
    listing()[:1] + page()[:1] + listing()[1:] + page()[1:],
    listing() + [{'id': 4, 'method': 'tools/list'},
                 {'id': 4, 'result': {'tools': []}}] + page(),
    listing() + [{'method': 'notifications/tools/list_changed'}] + page(),
    listing(17) + page('17'),
])
def test_unlinked_page_cannot_explain_call_failure(rows):
    s = session(rows + call())
    assert 'page' not in s.tools_by_name()
    finding = next(f for f in diagnose(s) if f.code in ('TOOL_CALL_ARG_MISMATCH', 'TOOL_CALL_PROTOCOL_ERROR'))
    assert 'page_required' not in finding.why


@pytest.mark.parametrize('cursor', ['next', '', 'opaque/+==?'])
def test_observed_cursor_chain_supplies_schemas(cursor):
    s = session(listing(cursor) + page(cursor) + call())
    assert set(s.tools_by_name()) == {'old', 'page'}
    finding = next(f for f in diagnose(s) if f.code in ('TOOL_CALL_ARG_MISMATCH', 'TOOL_CALL_PROTOCOL_ERROR'))
    assert 'page_required' in finding.why


def test_continuation_must_follow_latest_cursor_not_older_one():
    rows = listing() + page(next_cursor='last')
    rows += [{'id': 4, 'method': 'tools/list', 'params': {'cursor': 'next'}},
             {'id': 4, 'result': {'tools': [{'name': 'stale', 'inputSchema': {}}]}}]
    assert set(session(rows).tools_by_name()) == {'old', 'page'}


def test_final_page_exhausts_cursor_and_preserves_prior_tools():
    rows = listing() + page()
    rows += [{'id': 4, 'method': 'tools/list', 'params': {'cursor': 'next'}},
             {'id': 4, 'result': {'tools': [{'name': 'stale', 'inputSchema': {}}]}}]
    assert set(session(rows).tools_by_name()) == {'old', 'page'}


def test_past_call_cannot_use_later_advertisement():
    rows = page() + call() + listing()
    s = session(rows)
    finding = next(f for f in diagnose(s) if f.code in ('TOOL_CALL_ARG_MISMATCH', 'TOOL_CALL_PROTOCOL_ERROR'))
    assert 'page_required' not in finding.why


def test_three_page_chain_preserves_all_linked_schemas():
    rows = listing() + page(next_cursor='last')
    rows += [{'id': 4, 'method': 'tools/list', 'params': {'cursor': 'last'}},
             {'id': 4, 'result': {'tools': [{'name': 'last', 'inputSchema': {}}]}}]
    assert set(session(rows).tools_by_name()) == {'old', 'page', 'last'}


@pytest.mark.parametrize('failed', [{'error': {'code': -32603}},
                                    {'result': {'tools': None}}])
def test_failed_continuation_does_not_consume_advertised_cursor(failed):
    rows = listing()
    rows += [{'id': 4, 'method': 'tools/list', 'params': {'cursor': 'next'}},
             dict(id=4, **failed)]
    rows += page()
    assert set(session(rows).tools_by_name()) == {'old', 'page'}


def test_failed_unlinked_page_cannot_advertise_a_new_chain():
    rows = listing() + page('wrong', 'forged')
    rows += [{'id': 4, 'method': 'tools/list', 'params': {'cursor': 'forged'}},
             {'id': 4, 'result': {'tools': [{'name': 'forged', 'inputSchema': {}}]}}]
    assert set(session(rows).tools_by_name()) == {'old'}
