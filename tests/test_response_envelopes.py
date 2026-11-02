"""An invalid result/error envelope cannot establish protocol success or failure."""
import json
import pytest
from mcptriage.rules import diagnose
from mcptriage.transcript import parse_text

MALFORMED = [
    {'result': {'tools': []}, 'error': {'code': -32603}},
    {'result': {'tools': []}, 'error': None},
    {'result': {'tools': []}, 'error': 'bad'},
    {'error': None}, {'error': []}, {'error': 'bad'}, {'error': False},
]

def capture(method, payload):
    params={'name': 'x', 'arguments': {}} if method=='tools/call' else {}
    return parse_text('\n'.join(json.dumps(row) for row in [
        {'id':1,'method':method,'params':params}, dict(id=1,**payload)]))

@pytest.mark.parametrize('method',['initialize','tools/list','tools/call'])
@pytest.mark.parametrize('payload',MALFORMED)
def test_invalid_response_is_explicit_and_not_a_protocol_outcome(method,payload):
    fs=diagnose(capture(method,payload))
    codes={f.code for f in fs}
    assert 'UNUSABLE_RESPONSE' in codes
    assert not codes & {'EMPTY_TOOLS_LIST','MISSING_TOOLS_CAPABILITY','MISSING_INITIALIZED',
                        'TOOLS_LIST_ERROR','AUTH_ON_LIST','TOOL_CALL_FAILED','TOOLS_LIST_HANG',
                        'UNUSABLE_TOOLS_CATALOG','PAGINATION_INCOMPLETE','SCHEMA_ISSUES'}

@pytest.mark.parametrize('payload',MALFORMED)
def test_invalid_envelope_cannot_publish_tool_schema(payload):
    payload=dict(payload)
    if 'result' in payload:
        payload['result']={'tools':[{'name':'x','inputSchema':{'required':['private']}}]}
    assert capture('tools/list',payload).tools_by_name()=={}

@pytest.mark.parametrize('payload',[
    {'result':{'tools':[]}}, {'error':{'code':-32603}},
    {'error':{'code':401,'message':'unauthorized'}},
])
def test_valid_envelope_keeps_method_diagnosis(payload):
    codes={f.code for f in diagnose(capture('tools/list',payload))}
    assert 'UNUSABLE_RESPONSE' not in codes
    assert codes & {'EMPTY_TOOLS_LIST','TOOLS_LIST_ERROR','AUTH_ON_LIST'}

@pytest.mark.parametrize('mode',['text','json'])
def test_cli_malformed_envelope_remains_high_severity(tmp_path,capsys,mode):
    from mcptriage.cli import main
    p=tmp_path/'capture.jsonl'
    p.write_text('{"id":1,"method":"tools/list"}\n{"id":1,"result":{"tools":[]},"error":null}')
    assert main(['diagnose',str(p),'--format',mode])==1
    out=capsys.readouterr().out
    assert 'UNUSABLE_RESPONSE' in out
    assert 'EMPTY_TOOLS_LIST' not in out

@pytest.mark.parametrize('method,expected',[
    ('initialize','MISSING_TOOLS_CAPABILITY'),('tools/list','EMPTY_TOOLS_LIST'),
    ('tools/call','TOOL_CALL_FAILED'),
])
@pytest.mark.parametrize('error',[None,False,[],{'code':-32603}])
def test_conflicting_envelope_does_not_claim_existing_success(method,expected,error):
    result={'tools':[], 'isError':True, 'content':[]}
    codes={f.code for f in diagnose(capture(method,{'result':result,'error':error}))}
    assert expected not in codes

@pytest.mark.parametrize('payload',[{'error':None},{'error':'bad'},{'result':{},'error':None}])
def test_invalid_response_consumes_pair_and_cannot_be_replaced_by_late_catalog(payload):
    s=capture('tools/list',payload)
    from mcptriage.transcript import parse_text
    late=parse_text('{"id":1,"result":{"tools":[{"name":"late","inputSchema":{}}]}}')
    late.messages[0].line_no=3
    s.messages.extend(late.messages)
    assert s.response_for(s.requests()[0]).line_no==2
    assert s.tools_by_name()=={}
    fs=diagnose(s)
    assert sum(f.code=='UNUSABLE_RESPONSE' for f in fs)==1
    assert not any(f.code=='TOOLS_LIST_HANG' for f in fs)


def test_unusable_envelope_is_reported_even_without_request():
    codes={f.code for f in diagnose(parse_text('{"id":9,"error":null}'))}
    assert 'UNUSABLE_RESPONSE' in codes and 'ORPHAN_RESPONSES' in codes

@pytest.mark.parametrize('mode',['text','json'])
@pytest.mark.parametrize('shape',['both','bad-error'])
def test_malformed_envelope_evidence_still_masks_secret(tmp_path,capsys,mode,shape):
    from mcptriage.cli import main
    response={'id':1,'error':{'token':'private-envelope-marker'}} if shape=='both' else {'id':1,'error':'Bearer private-envelope-marker'}
    if shape=='both':response['result']={'tools':[]}
    p=tmp_path/'capture.jsonl'
    p.write_text('{"id":1,"method":"tools/list"}\n'+json.dumps(response))
    assert main(['diagnose',str(p),'--format',mode])==1
    out=capsys.readouterr().out
    assert 'UNUSABLE_RESPONSE' in out
    assert 'private-envelope-marker' not in out

@pytest.mark.parametrize('result',[None,False,[],0,''])
def test_result_value_is_not_itself_a_malformed_envelope(result):
    fs=diagnose(capture('tools/list',{'result':result}))
    assert not any(f.code=='UNUSABLE_RESPONSE' for f in fs)
    assert any(f.code=='UNUSABLE_TOOLS_CATALOG' for f in fs)


@pytest.mark.parametrize('mode',['text','json'])
@pytest.mark.parametrize('source',['file','stdin'])
@pytest.mark.parametrize('exit_zero',[False,True])
def test_complete_synthetic_example_reports_envelope_not_false_empty_catalog(tmp_path,capsys,monkeypatch,mode,source,exit_zero):
    from pathlib import Path
    import io
    from mcptriage.cli import main
    text=(Path(__file__).parents[1]/'examples'/'conflicting-response.jsonl').read_text()
    p=tmp_path/'capture.jsonl';p.write_text(text)
    monkeypatch.setattr('sys.stdin',io.StringIO(text))
    args=['diagnose',str(p) if source=='file' else '-','--format',mode]
    if exit_zero:args.append('--exit-zero')
    assert main(args)==(0 if exit_zero else 1)
    out=capsys.readouterr().out
    assert 'UNUSABLE_RESPONSE' in out
    assert not any(code in out for code in ['EMPTY_TOOLS_LIST','TOOLS_LIST_ERROR','TOOLS_LIST_HANG'])
    if mode=='json':assert json.loads(out)['finding_count']==1
