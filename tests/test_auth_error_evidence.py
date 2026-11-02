"""Outer request IDs and log prefixes are not authentication-error evidence."""
import json
import pytest
from mcptriage.transcript import parse_text
from mcptriage.rules import diagnose

def findings(identifier=1,message='handler failed',code=-32603,prefix='',extra=None):
    response={'id':identifier,'error':{'code':code,'message':message}}
    if extra:response.update(extra)
    rows=[{'id':0,'method':'initialize'},{'id':0,'result':{'capabilities':{'tools':{}}}},
          {'method':'notifications/initialized'}, {'id':identifier,'method':'tools/list'},response]
    return diagnose(parse_text('\n'.join(prefix+json.dumps(r) for r in rows)))

@pytest.mark.parametrize('identifier',[401,'401','trace-401','unauthorized-request','unauthenticated-id'])
def test_outer_id_does_not_turn_internal_error_into_auth(identifier):
    fs=findings(identifier=identifier)
    assert not any(f.code=='AUTH_ON_LIST' for f in fs)
    assert any(f.code=='TOOLS_LIST_ERROR' and 'internal error' in f.title for f in fs)

@pytest.mark.parametrize('prefix',['trace401 401: ','unauthorized-log-channel: ','unauthenticated-capture '])
def test_log_prefix_does_not_count_as_auth_error(prefix):
    fs=findings(prefix=prefix)
    assert not any(f.code=='AUTH_ON_LIST' for f in fs)
    assert any(f.code=='TOOLS_LIST_ERROR' for f in fs)

@pytest.mark.parametrize('extra',[{'trace':'401'},{'label':'unauthorized'},{'metadata':{'http':401}}])
def test_outer_metadata_not_auth_error(extra):
    assert not any(f.code=='AUTH_ON_LIST' for f in findings(extra=extra))

@pytest.mark.parametrize('message',['401 Unauthorized','unauthorized','unauthenticated'])
def test_auth_error_message_remains_detected(message):
    fs=findings(message=message)
    assert any(f.code=='AUTH_ON_LIST' for f in fs)
    assert not any(f.code=='TOOLS_LIST_ERROR' for f in fs)

def test_numeric_auth_code_remains_detected():
    assert any(f.code=='AUTH_ON_LIST' for f in findings(code=401))

@pytest.mark.parametrize('mode',['text','json'])
def test_cli_id401_keeps_protocol_error_diagnosis(tmp_path,capsys,mode):
    from mcptriage.cli import main
    p=tmp_path/'capture.jsonl'
    p.write_text('{"id":401,"method":"tools/list"}\n{"id":401,"error":{"code":-32603,"message":"handler failed"}}')
    assert main(['diagnose',str(p),'--format',mode])==1
    out=capsys.readouterr().out
    assert 'TOOLS_LIST_ERROR' in out
    assert 'AUTH_ON_LIST' not in out

@pytest.mark.parametrize('data',[{'status':401},{'reason':'unauthorized'}])
def test_nested_error_data_markers_remain_detected(data):
    rows=[{'id':1,'method':'tools/list'},
          {'id':1,'error':{'code':-32603,'message':'backend rejected','data':data}}]
    fs=diagnose(parse_text('\n'.join(json.dumps(r) for r in rows)))
    assert any(f.code=='AUTH_ON_LIST' for f in fs)
