"""A new initialize attempt cannot inherit an earlier captured tool catalog."""
import json

import pytest

from mcptriage.rules import diagnose
from mcptriage.transcript import parse_text


TOOL = {'name': 'query', 'inputSchema': {'required': ['old_required']}}


def listing():
    return [{'id': 1, 'method': 'tools/list'},
            {'id': 1, 'result': {'tools': [TOOL], 'nextCursor': 'next'}}]


def call(identifier):
    return [{'id': identifier, 'method': 'tools/call', 'params': {'name': 'query', 'arguments': {}}},
            {'id': identifier, 'error': {'code': -32602}}]


def session(rows):
    return parse_text('\n'.join(map(json.dumps, rows)))


@pytest.mark.parametrize('reply', [None, {'result': {'capabilities': {'tools': {}}}},
                                  {'error': {'code': -32603}}])
def test_initialize_attempt_invalidates_old_schema_in_real_diagnosis(reply):
    rows = listing() + call(2) + [{'id': 3, 'method': 'initialize'}]
    if reply is not None:
        rows.append(dict(id=3, **reply))
    rows += call(4)
    s = session(rows)
    assert s.tools_by_name() == {}
    findings = [f for f in diagnose(s) if f.code == 'TOOL_CALL_ARG_MISMATCH']
    assert len(findings) == 2
    assert 'old_required' in findings[0].why
    assert 'old_required' not in findings[1].why


def test_delayed_old_list_response_after_initialize_cannot_restore_catalog():
    rows = listing()[:1] + [{'id': 3, 'method': 'initialize'}] + listing()[1:] + call(4)
    assert session(rows).tools_by_name() == {}
    finding = next(f for f in diagnose(session(rows)) if f.code == 'TOOL_CALL_ARG_MISMATCH')
    assert 'old_required' not in finding.why


def test_old_cursor_cannot_resume_catalog_after_new_initialize():
    rows = listing() + [{'id': 3, 'method': 'initialize'}]
    rows += [{'id': 5, 'method': 'tools/list', 'params': {'cursor': 'next'}},
             {'id': 5, 'result': {'tools': [TOOL]}}]
    assert session(rows).tools_by_name() == {}


def test_fresh_listing_after_initialize_provides_new_schema():
    rows = listing() + [{'id': 3, 'method': 'initialize'}]
    new_tool = dict(TOOL, inputSchema={'required': ['new_required']})
    rows += [{'id': 5, 'method': 'tools/list'}, {'id': 5, 'result': {'tools': [new_tool]}}] + call(4)
    s = session(rows)
    assert s.tools_by_name() == {'query': new_tool['inputSchema']}
    finding = next(f for f in diagnose(s) if f.code == 'TOOL_CALL_ARG_MISMATCH')
    assert 'new_required' in finding.why and 'old_required' not in finding.why


def test_unrelated_request_does_not_clear_catalog():
    rows = listing() + [{'id': 3, 'method': 'ping'}, {'id': 3, 'result': {}}] + call(4)
    assert session(rows).tools_by_name() == {'query': TOOL['inputSchema']}


def test_pre_boundary_cutoff_keeps_prior_evidence():
    s = session(listing() + [{'id': 3, 'method': 'initialize'}])
    assert s.tools_by_name(before_line=3) == {'query': TOOL['inputSchema']}
    assert s.tools_by_name(before_line=4) == {}
