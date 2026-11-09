"""An observed fresh listing cannot keep removed tool schemas current."""
import json
import pytest
from mcptriage.transcript import parse_text
from mcptriage.rules import diagnose

OLD={'name':'old','inputSchema':{'type':'object','required':['old_required']}}
NEW={'name':'new','inputSchema':{'type':'object','required':['new_required']}}
def session(result,params=None):
    request={'id':2,'method':'tools/list'}
    if params is not None:request['params']=params
    rows=[{'id':1,'method':'tools/list'},{'id':1,'result':{'tools':[OLD]}},request,{'id':2,'result':result},{'id':3,'method':'tools/call','params':{'name':'old','arguments':{}}},{'id':3,'error':{'code':-32602}}]
    return parse_text('\n'.join(map(json.dumps,rows)))


@pytest.mark.parametrize('params',[None,{}, {'other':'value'}])
@pytest.mark.parametrize('tools',[[],[NEW]])
def test_fresh_first_page_replaces_prior_schema_evidence(params,tools):
    s=session({'tools':tools},params)
    assert 'old' not in s.tools_by_name()
    f=next(f for f in diagnose(s)if f.code in ('TOOL_CALL_ARG_MISMATCH', 'TOOL_CALL_PROTOCOL_ERROR'))
    assert 'old_required' not in f.why
    assert ('new' in s.tools_by_name())==bool(tools)


def test_empty_refresh_does_not_explain_failure_with_removed_schema_control():
    f=next(f for f in diagnose(session({'tools':[]}))if f.code in ('TOOL_CALL_ARG_MISMATCH', 'TOOL_CALL_PROTOCOL_ERROR'))
    assert 'old_required' not in f.why, 'fresh empty listing must not supply a removed tool schema'


@pytest.mark.parametrize('cursor',['next',''])
def test_continuation_page_still_merges_observed_tools(cursor):
    s=session({'tools':[NEW]}, {'cursor':cursor})
    # Continuations are linked to a cursor advertised by the first page.
    s.messages[1].obj['result']['nextCursor'] = cursor
    assert set(s.tools_by_name())=={'old','new'}


def test_past_call_keeps_schema_before_later_refresh():
    s=session({'tools':[]})
    assert s.tools_by_name(before_line=3)=={'old':OLD['inputSchema']}
    assert s.tools_by_name(before_line=5)=={}


def test_fresh_paginated_listing_drops_old_then_adds_continuation():
    s=session({'tools':[NEW],'nextCursor':'next'})
    rows=[m.obj for m in s.messages[:4]]+[{'id':4,'method':'tools/list','params':{'cursor':'next'}},{'id':4,'result':{'tools':[{'name':'page2','inputSchema':{}}]}}]
    out=parse_text('\n'.join(map(json.dumps,rows)))
    assert set(out.tools_by_name())=={'new','page2'}


@pytest.mark.parametrize('params',[{'cursor':None},{'cursor':False},{'cursor':7},[],False])
def test_unusable_request_params_do_not_invent_first_page_refresh(params):
    # A malformed cursor/request cannot identify a fresh first-page listing.
    s=session({'tools':[]},params)
    assert s.tools_by_name().get('old')==OLD['inputSchema']


@pytest.mark.parametrize('result',[None,[],{}, {'tools':None}, {'tools':{}}])
def test_unusable_result_is_not_a_successful_empty_refresh(result):
    assert session(result).tools_by_name().get('old')==OLD['inputSchema']


def test_failed_refresh_is_not_an_observed_empty_catalog():
    s=session({'tools':[]})
    s.messages[3].obj={'id':2,'error':{'code':-32603}}
    assert s.tools_by_name().get('old')==OLD['inputSchema']


def test_successful_refresh_updates_same_named_schema():
    updated=dict(OLD,inputSchema={'type':'object','required':['current_required']})
    s=session({'tools':[updated]})
    f=next(f for f in diagnose(s)if f.code in ('TOOL_CALL_ARG_MISMATCH', 'TOOL_CALL_PROTOCOL_ERROR'))
    assert 'current_required' in f.why and 'old_required' not in f.why
