"""Distinguish protocol rejection from isError execution failures."""
import json
import pytest
from mcptriage.rules import diagnose
from mcptriage.transcript import parse_text
from mcptriage.report import render_json,render_text


def inspect(response,request=None):
    if request is None:request={'id':3,'method':'tools/call','params':{'name':'x','arguments':{}}}
    return diagnose(parse_text('\n'.join(map(json.dumps,[request,dict(id=3,**response)]))))

@pytest.mark.parametrize('code',[-32700,-32600,-32601,-32603,-32000,-32022,0,41,-32603.0])
def test_integer_protocol_error_is_not_reported_as_healthy(code):
    fs=inspect({'error':{'code':code,'message':'backend unavailable'}})
    f=next((f for f in fs if f.code=='TOOL_CALL_PROTOCOL_ERROR'),None)
    assert f is not None
    assert f.severity=='high'
    assert 'JSON-RPC error' in f.title
    assert not any(f.code in ('TOOL_CALL_FAILED','TOOL_CALL_ARG_MISMATCH') for f in fs)

@pytest.mark.parametrize('code',[True,False,[],{},None,'-32603',-32603.5])
def test_malformed_code_is_not_reinterpreted(code):
    fs=inspect({'error':{'code':code}})
    assert any(f.code=='UNUSABLE_ERROR_CODE' for f in fs)
    assert not any(f.code=='TOOL_CALL_PROTOCOL_ERROR' for f in fs)

@pytest.mark.parametrize('result',[{},None,{'content':[]},{'isError':False},{'isError':'true'}])
def test_success_or_nonboolean_marker_does_not_invent_protocol_error(result):
    assert not any(f.code=='TOOL_CALL_PROTOCOL_ERROR' for f in inspect({'result':result}))

@pytest.mark.parametrize('response,expected',[
 ({'error':{'code':-32602,'message':'invalid params'}},'TOOL_CALL_ARG_MISMATCH'),
 ({'result':{'isError':True,'content':[{'text':'failed'}]}},'TOOL_CALL_FAILED')])
def test_existing_specific_paths_stay_separate(response,expected):
    fs=inspect(response)
    assert sum(f.code==expected for f in fs)==1
    assert not any(f.code=='TOOL_CALL_PROTOCOL_ERROR' for f in fs)

@pytest.mark.parametrize('name',[None,[],{},True,1])
def test_invalid_name_keeps_shape_diagnosis(name):
    fs=inspect({'error':{'code':-32603}},{'id':3,'method':'tools/call','params':{'name':name}})
    assert any(f.code=='UNUSABLE_TOOL_NAME' for f in fs)
    assert not any(f.code=='TOOL_CALL_PROTOCOL_ERROR' for f in fs)

@pytest.mark.parametrize('render',[render_text,render_json])
def test_protocol_error_evidence_is_redacted(render):
    fs=inspect({'error':{'code':-32603,'message':'backend unavailable','data':{'token':'PRIVATE_MARKER'}}})
    assert any(f.code=='TOOL_CALL_PROTOCOL_ERROR' for f in fs)
    assert 'PRIVATE_MARKER' not in render(fs,'synthetic')


def test_complete_capture_cannot_print_no_problems():
    rows=[{'id':1,'method':'initialize','params':{}},{'id':1,'result':{'capabilities':{'tools':{}}}},{'method':'notifications/initialized'},{'id':2,'method':'tools/list','params':{}},{'id':2,'result':{'tools':[{'name':'x','inputSchema':{'type':'object'}}]}},{'id':3,'method':'tools/call','params':{'name':'x','arguments':{}}},{'id':3,'error':{'code':-32603,'message':'database unavailable'}}]
    fs=diagnose(parse_text('\n'.join(map(json.dumps,rows))))
    assert [f.code for f in fs]==['TOOL_CALL_PROTOCOL_ERROR']
    assert 'no problems found' not in render_text(fs,'synthetic')

@pytest.mark.parametrize('prefix',[
 [{'id':3,'error':{'code':-32603}}, {'id':3,'method':'tools/call','params':{'name':'x'}}],
 [{'id':3,'method':'tools/call','params':{'name':'x'}},{'id':3,'method':'tools/call','params':{'name':'y'}},{'id':3,'error':{'code':-32603}}],
 [{'id':3,'method':'tools/call','params':{'name':'x'}},{'id':3,'result':{}},{'id':3,'error':{'code':-32603}}]
])
def test_unowned_or_already_consumed_response_does_not_attach_rejection(prefix):
    fs=diagnose(parse_text('\n'.join(map(json.dumps,prefix))))
    assert not any(f.code=='TOOL_CALL_PROTOCOL_ERROR' for f in fs)


def test_reused_id_after_completed_call_belongs_only_to_later_call():
    rows=[{'id':3,'method':'tools/call','params':{'name':'first'}},{'id':3,'result':{}},{'id':3,'method':'tools/call','params':{'name':'second'}},{'id':3,'error':{'code':-32603}}]
    fs=diagnose(parse_text('\n'.join(map(json.dumps,rows))))
    found=[f for f in fs if f.code=='TOOL_CALL_PROTOCOL_ERROR']
    assert len(found)==1 and "'second'" in found[0].title


@pytest.mark.parametrize('mode',['text','json'])
@pytest.mark.parametrize('source',['file','stdin'])
@pytest.mark.parametrize('override',[False,True])
def test_complete_capture_cli_exit_contract(mode,source,override,capsys,monkeypatch):
    import io
    import sys
    from pathlib import Path
    from mcptriage.cli import main
    path=Path(__file__).resolve().parents[1]/'examples'/'tool-call-protocol-error.jsonl'
    if source=='stdin':monkeypatch.setattr(sys,'stdin',io.StringIO(path.read_text()))
    args=['diagnose',str(path) if source=='file' else '-','--format',mode]
    if override:args+=['--exit-zero']
    assert main(args)==(0 if override else 1)
    out=capsys.readouterr().out
    assert 'TOOL_CALL_PROTOCOL_ERROR' in out and 'no problems found' not in out
    if mode=='json':
        data=json.loads(out)
        assert data['finding_count']==1
        assert data['findings'][0]['severity']=='high'


@pytest.mark.parametrize('code',[-32603,-32602,401])
@pytest.mark.parametrize('mode',['text','json'])
def test_conflicting_call_response_never_selects_error_or_execution_path(code,mode):
    rows=[{'id':1,'method':'tools/call','params':{'name':'x','arguments':{}}},
          {'id':1,'error':{'code':code,'message':'failed','data':{'token':'head"PRIVATE_SUFFIX'}},'result':{'isError':True}}]
    fs=diagnose(parse_text('\n'.join(map(json.dumps,rows))))
    codes={f.code for f in fs}
    assert 'UNUSABLE_RESPONSE' in codes
    assert not codes & {'TOOL_CALL_PROTOCOL_ERROR','TOOL_CALL_ARG_MISMATCH','TOOL_CALL_FAILED'}
    output=(render_json if mode=='json' else render_text)(fs,'synthetic')
    assert 'PRIVATE_SUFFIX' not in output
    if mode=='json':json.loads(output)

@pytest.mark.parametrize('mode',['text','json'])
def test_valid_call_protocol_error_remains_diagnosed_and_escaped_secret_masked(mode):
    rows=[{'id':1,'method':'tools/call','params':{'name':'x','arguments':{}}},
          {'id':1,'error':{'code':-32603,'message':'failed','data':{'token':'head"PRIVATE_SUFFIX'}}}]
    fs=diagnose(parse_text('\n'.join(map(json.dumps,rows))))
    assert any(f.code=='TOOL_CALL_PROTOCOL_ERROR' for f in fs)
    output=(render_json if mode=='json' else render_text)(fs,'synthetic')
    assert 'PRIVATE_SUFFIX' not in output
    if mode=='json':json.loads(output)
