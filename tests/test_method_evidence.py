"""Malformed method fields are neither invocations nor response evidence."""
import json
import pytest
from mcptriage.transcript import parse_text
from mcptriage.rules import diagnose


@pytest.mark.parametrize('method',[None,False,True,0,1,1.5,[],{},['tools/list']])
@pytest.mark.parametrize('with_id',[False,True])
def test_nonstring_method_retained_but_not_usable_traffic(method,with_id):
    row={'method':method}
    if with_id:row['id']=1
    session=parse_text(json.dumps(row))
    assert len(session.messages)==1 and session.messages[0].obj==row
    assert session.requests()==[] and session.notifications()==[]
    assert session.parsed==[] and session.response_pairs()=={}
    assert any(f.code=='INVALID_RPC_METHOD' for f in diagnose(session))


@pytest.mark.parametrize('payload',[{'result':{'tools':[{'name':'x','inputSchema':{'required':['x']}}]}},
                                    {'error':{'code':-32602}}])
def test_null_method_cannot_be_borrowed_as_tools_list_reply(payload):
    rows=[{'id':1,'method':'tools/list'},dict(id=1,method=None,**payload),
          {'id':2,'method':'tools/call','params':{'name':'x','arguments':{}}},
          {'id':2,'error':{'code':-32602}}]
    session=parse_text('\n'.join(map(json.dumps,rows)))
    assert session.response_for(session.requests('tools/list')[0]) is None
    assert session.tools_by_name()=={}
    findings=diagnose(session)
    assert any(f.code=='INVALID_RPC_METHOD' for f in findings)
    assert not any('missing required' in f.why for f in findings)


@pytest.mark.parametrize('method',['tools/list','notifications/initialized','custom/method',''])
def test_string_method_classification_is_preserved(method):
    session=parse_text(json.dumps({'id':1,'method':method})+'\n'+json.dumps({'id':1,'result':{}}))
    assert len(session.requests())==1 and session.response_for(session.requests()[0]).line_no==2
    assert not any(f.code=='INVALID_RPC_METHOD' for f in diagnose(session))


@pytest.mark.parametrize('mode',['text','json'])
def test_cli_reports_bad_method_without_false_catalog_claim(tmp_path,capsys,mode):
    from mcptriage.cli import main
    rows=[{'id':1,'method':'tools/list'},
          {'id':1,'method':None,'result':{'tools':[]}}]
    path=tmp_path/'capture';path.write_text('\n'.join(map(json.dumps,rows)))
    assert main(['diagnose',str(path),'--format',mode])==1
    out=capsys.readouterr().out
    assert 'INVALID_RPC_METHOD' in out
    assert 'EMPTY_TOOLS_LIST' not in out


@pytest.mark.parametrize('prefix',['','2026-11-05 client: '])
def test_invalid_method_is_not_replaced_with_nested_protocol_shaped_value(prefix):
    row={'id':1,'method':{'method':'tools/list','id':2},'result':{'tools':[]}}
    session=parse_text(prefix+json.dumps(row))
    assert len(session.messages)==1 and session.requests()==[]
    assert session.messages[0].obj==row
    assert [f.code for f in diagnose(session)]==['INVALID_RPC_METHOD']


def test_real_response_after_invalid_method_still_pairs_chronologically():
    rows=[{'id':1,'method':'tools/list'},
          {'id':1,'method':None,'result':{'tools':[]}},
          {'id':1,'result':{'tools':[{'name':'x','inputSchema':{}}]}}]
    session=parse_text('\n'.join(map(json.dumps,rows)))
    assert session.response_for(session.requests()[0]).line_no==3
    assert session.tools_by_name()=={'x':{}}
