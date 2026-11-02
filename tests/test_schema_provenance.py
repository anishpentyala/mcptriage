"""Tool schemas must come from an unambiguous captured tools/list exchange."""
import json
import pytest
from mcptriage.transcript import parse_text
from mcptriage.rules import diagnose

SCHEMA={'tools':[{'name':'x','inputSchema':{'type':'object','required':['secret']}}]}
def dump(*rows):
    return '\n'.join(json.dumps(r) for r in rows)

@pytest.mark.parametrize('earlier',[
    [],
    [{'id':1,'method':'initialize'}],
    [{'id':1,'method':'resources/list'}],
    [{'id':'1','method':'tools/list'}],
    [{'id':1,'method':'tools/list'},{'id':1,'method':'resources/list'}],
    [{'id':1,'method':'tools/list'},{'id':1,'method':'tools/list'}],
])
def test_unproven_schema_does_not_explain_argument_error(earlier):
    s=parse_text(dump(*earlier,{'id':1,'result':SCHEMA},
                     {'id':2,'method':'tools/call','params':{'name':'x','arguments':{}}},
                     {'id':2,'error':{'code':-32602}}))
    assert s.tools_by_name(before_line=len(earlier)+2)=={}
    f=next(f for f in diagnose(s) if f.code=='TOOL_CALL_ARG_MISMATCH')
    assert 'missing required' not in f.why


def test_first_response_only_can_publish_schema():
    s=parse_text(dump({'id':1,'method':'tools/list'}, {'id':1,'result':{'tools':[]}},
                     {'id':1,'result':SCHEMA}))
    assert s.tools_by_name()=={}


def test_error_then_response_cannot_publish_schema():
    s=parse_text(dump({'id':1,'method':'tools/list'}, {'id':1,'error':{'code':-32603}},
                     {'id':1,'result':SCHEMA}))
    assert s.tools_by_name()=={}


def test_response_before_request_is_not_evidence():
    s=parse_text(dump({'id':1,'result':SCHEMA},{'id':1,'method':'tools/list'}))
    assert s.tools_by_name()=={}


@pytest.mark.parametrize('identifier',[0,'1',1.0])
def test_valid_captured_list_preserves_diagnostic(identifier):
    s=parse_text(dump({'id':identifier,'method':'tools/list'}, {'id':identifier,'result':SCHEMA},
                     {'id':2,'method':'tools/call','params':{'name':'x','arguments':{}}},
                     {'id':2,'error':{'code':-32602}}))
    assert s.tools_by_name(before_line=3)=={'x':SCHEMA['tools'][0]['inputSchema']}
    f=next(f for f in diagnose(s) if f.code=='TOOL_CALL_ARG_MISMATCH')
    assert "missing required argument 'secret'" in f.why


def test_future_id_reuse_cannot_rewrite_past_evidence():
    s=parse_text(dump({'id':1,'method':'tools/list'},{'id':1,'result':SCHEMA},
                     {'id':2,'method':'tools/call'}, {'id':1,'method':'resources/list'}))
    assert 'x' in s.tools_by_name(before_line=3)
    assert s.tools_by_name()=={}


def test_empty_list_does_not_invent_schemas():
    s=parse_text(dump({'id':1,'method':'tools/list'},{'id':1,'result':{'tools':[]}}))
    assert s.tools_by_name()=={}


def test_method_with_integer_id_cannot_claim_string_response():
    s=parse_text(dump({'id':1,'method':'tools/list'},{'id':'1','result':SCHEMA}))
    assert s.tools_by_name()=={}


def test_reused_id_omits_only_that_ids_schemas():
    s=parse_text(dump({'id':1,'method':'tools/list'},{'id':1,'result':SCHEMA},
                     {'id':1,'method':'resources/list'},
                     {'id':2,'method':'tools/list'},
                     {'id':2,'result':{'tools':[{'name':'safe','inputSchema':{}}]}}))
    assert s.tools_by_name()=={'safe':{}}


def test_later_unique_list_updates_existing_tool_schema():
    s=parse_text(dump({'id':1,'method':'tools/list'},{'id':1,'result':SCHEMA},
                     {'id':2,'method':'tools/list'},
                     {'id':2,'result':{'tools':[{'name':'x','inputSchema':{'type':'object'}}]}}))
    assert s.tools_by_name()=={'x':{'type':'object'}}


@pytest.mark.parametrize('mode',['text','json'])
def test_cli_does_not_present_unproven_schema_detail(tmp_path,capsys,mode):
    from mcptriage.cli import main
    path=tmp_path/'capture.jsonl'
    path.write_text(dump({'id':1,'result':SCHEMA},
                         {'id':2,'method':'tools/call','params':{'name':'x','arguments':{}}},
                         {'id':2,'error':{'code':-32602}}))
    assert main(['diagnose',str(path),'--format',mode])==1
    out=capsys.readouterr().out
    assert 'TOOL_CALL_ARG_MISMATCH' in out
    assert 'missing required' not in out


def test_unique_paginated_list_responses_merge_schema_evidence():
    s=parse_text(dump({'id':1,'method':'tools/list'},
                     {'id':1,'result':dict(SCHEMA,nextCursor='next')},
                     {'id':2,'method':'tools/list','params':{'cursor':'next'}},
                     {'id':2,'result':{'tools':[{'name':'y','inputSchema':{}}]}}))
    assert set(s.tools_by_name())=={'x','y'}
