"""Malformed traffic must diagnose, not crash or alias valid request IDs."""
import json
import pytest
from mcptriage.transcript import parse_text
from mcptriage.rules import diagnose
from mcptriage.cli import main


@pytest.mark.parametrize('value,shape',[(v,k) for v in [[],{},True,False,1.5,None] for k in ['request','result','error'] if not (v is None and k=='error')])
def test_invalid_id_is_preserved_and_excluded_from_pairing(value,shape):
    obj={'jsonrpc':'2.0','id':value}
    obj.update({'method':'tools/list'} if shape=='request' else {shape:{} if shape=='result' else {'code':-32600,'message':'invalid'}})
    session=parse_text(json.dumps(obj))
    findings=diagnose(session)
    assert any(f.code=='INVALID_RPC_ID' and f.severity=='high' for f in findings)
    assert session.messages[0].obj==obj
    assert session.requests()==[]
    assert session.orphan_responses()==[]


@pytest.mark.parametrize('bad',[True,1.5,[],{}])
def test_invalid_response_cannot_satisfy_integer_request(bad):
    req={'jsonrpc':'2.0','id':1,'method':'tools/list'}
    resp={'jsonrpc':'2.0','id':bad,'result':{'tools':[]}}
    session=parse_text(json.dumps(req)+'\n'+json.dumps(resp))
    assert session.response_for(session.requests()[0]) is None
    codes={f.code for f in diagnose(session)}
    assert 'INVALID_RPC_ID' in codes
    assert 'EMPTY_TOOLS_LIST' not in codes


@pytest.mark.parametrize('value',[0,-1,42,'1','',2**100,1.0])
def test_valid_ids_continue_to_pair(value):
    session=parse_text(json.dumps({'id':value,'method':'tools/list'})+'\n'+json.dumps({'id':value,'result':{'tools':[]}}))
    assert session.response_for(session.requests()[0]).line_no==2
    assert 'INVALID_RPC_ID' not in {f.code for f in diagnose(session)}


def test_valid_integer_and_string_stay_distinct():
    session=parse_text('{"id":1,"method":"tools/list"}\n{"id":"1","result":{"tools":[]}}')
    assert session.response_for(session.requests()[0]) is None


def test_null_error_does_not_become_an_invalid_request_diagnostic():
    session=parse_text('{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Parse error"}}')
    assert 'INVALID_RPC_ID' not in {f.code for f in diagnose(session)}
    assert session.requests()==[]


@pytest.mark.parametrize('mode',['text','json'])
def test_cli_invalid_id_returns_diagnostic_not_traceback(tmp_path,capsys,mode):
    path=tmp_path/'capture.jsonl'
    path.write_text('{"jsonrpc":"2.0","id":{},"method":"tools/list"}')
    assert main(['diagnose',str(path),'--format',mode])==1
    output=capsys.readouterr()
    assert 'INVALID_RPC_ID' in output.out
    assert 'Traceback' not in output.err


def test_invalid_tool_list_cannot_publish_schema_for_later_call():
    text='\n'.join(json.dumps(obj) for obj in [
        {'id':True,'result':{'tools':[{'name':'x','inputSchema':{'required':['secret']}}]}},
        {'id':2,'method':'tools/call','params':{'name':'x','arguments':{}}},
        {'id':2,'error':{'code':-32602,'message':'bad arguments'}},
    ])
    session=parse_text(text)
    assert session.tools_by_name()=={}
    assert 'INVALID_RPC_ID' in {f.code for f in diagnose(session)}


def test_invalid_id_evidence_is_redacted():
    text=json.dumps({'id':{'token':'private-marker'},'method':'tools/list'})
    finding=next(f for f in diagnose(parse_text(text)) if f.code=='INVALID_RPC_ID')
    assert 'private-marker' not in finding.evidence
    assert '***' in finding.evidence


@pytest.mark.parametrize('numeric',['1.0','1e0'])
def test_integral_json_number_pairs_integer_id(numeric):
    session=parse_text('{"id":1,"method":"tools/list"}\n'+ '{"id":'+numeric+',"result":{"tools":[]}}')
    assert session.response_for(session.requests()[0]).line_no==2


def test_large_integral_decimal_id_does_not_round_into_another_request():
    session=parse_text('{"id":9007199254740992,"method":"tools/list"}\n'
                       '{"id":9007199254740993.0,"result":{"tools":[]}}')
    assert session.response_for(session.requests()[0]) is None
    assert len(session.orphan_responses())==1


def test_huge_exponent_id_is_bounded_and_diagnosed():
    session=parse_text('{"id":1e999999999,"method":"tools/list"}')
    findings=diagnose(session)
    assert any(f.code=='INVALID_RPC_ID' and 'supported range' in f.why for f in findings)


@pytest.mark.parametrize('prefix',['','2026-11-02 [mcp] '])
def test_precise_decimal_id_with_optional_log_prefix(prefix):
    session=parse_text(prefix+'{"id":9007199254740993.0,"method":"tools/list"}\n'
                       +prefix+'{"id":9007199254740993,"result":{"tools":[]}}')
    assert session.response_for(session.requests()[0]).line_no==2
    assert session.requests()[0].msg_id==9007199254740993
