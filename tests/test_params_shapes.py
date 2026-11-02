"""Malformed captured parameter values must diagnose rather than crash."""
import json
import pytest
from mcptriage.transcript import parse_text
from mcptriage.rules import diagnose

@pytest.mark.parametrize('method',['initialize','tools/call'])
@pytest.mark.parametrize('params',[[],[1],'bad','',True,False,1,0,None])
def test_unusable_params_are_preserved_with_explicit_diagnostic(method,params):
    rows=[{'id':1,'method':method,'params':params}, {'id':1,'error':{'code':-32602}}]
    s=parse_text('\n'.join(json.dumps(x) for x in rows))
    f=next(f for f in diagnose(s) if f.code=='UNUSABLE_PARAMS')
    assert f.severity=='high'
    assert s.messages[0].obj['params']==params
    assert 'line 1:' in f.evidence

@pytest.mark.parametrize('method',['initialize','tools/call'])
@pytest.mark.parametrize('params',[None,{}, {'arguments':{}}, {'protocolVersion':'2025-11-25'}])
def test_missing_or_object_params_keep_existing_rules(method,params):
    row={'id':1,'method':method}
    if params is not None:row['params']=params
    s=parse_text(json.dumps(row)+'\n'+json.dumps({'id':1,'result':{}}))
    assert 'UNUSABLE_PARAMS' not in {f.code for f in diagnose(s)}

@pytest.mark.parametrize('mode',['text','json'])
@pytest.mark.parametrize('method',['initialize','tools/call'])
def test_cli_unusable_params_has_diagnostic_without_traceback(tmp_path,capsys,mode,method):
    from mcptriage.cli import main
    p=tmp_path/'capture.jsonl'
    p.write_text(json.dumps({'id':1,'method':method,'params':["marker"]})+'\n'+json.dumps({'id':1,'result':{}}))
    assert main(['diagnose',str(p),'--format',mode])==1
    out=capsys.readouterr()
    assert 'UNUSABLE_PARAMS' in out.out
    assert 'Traceback' not in out.err


@pytest.mark.parametrize('method',['initialize','tools/call'])
def test_unanswered_unusable_params_still_diagnose(method):
    s=parse_text(json.dumps({'id':1,'method':method,'params':[{'token':'private-marker'}]}))
    f=next(f for f in diagnose(s) if f.code=='UNUSABLE_PARAMS')
    assert 'private-marker' not in f.evidence
    assert '***' in f.evidence


def test_valid_calls_still_report_real_schema_mismatch():
    s=parse_text('\n'.join(json.dumps(row) for row in [
        {'id':1,'method':'tools/list'},
        {'id':1,'result':{'tools':[{'name':'x','inputSchema':{'required':['needed']}}]}},
        {'id':2,'method':'tools/call','params':{'name':'x','arguments':{}}},
        {'id':2,'error':{'code':-32602}},
    ]))
    assert any(f.code=='TOOL_CALL_ARG_MISMATCH' and "missing required argument 'needed'" in f.why for f in diagnose(s))


def test_valid_version_downshift_still_diagnoses():
    s=parse_text('{"id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}\n'
                 '{"id":1,"result":{"protocolVersion":"2025-06-18"}}')
    assert 'VERSION_DOWNSHIFT' in {f.code for f in diagnose(s)}
