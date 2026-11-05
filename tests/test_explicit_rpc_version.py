"""Explicitly wrong RPC versions cannot establish catalog evidence."""
import json
import pytest
from mcptriage.transcript import parse_text
from mcptriage.rules import diagnose


@pytest.mark.parametrize('version',[None,False,True,2,2.0,'1.0','2.0 ',[],{}])
@pytest.mark.parametrize('payload',[{'id':1,'method':'tools/list'}, {'id':1,'result':{'tools':[]}}])
def test_explicit_wrong_version_retained_not_usable(version,payload):
    row=dict(payload,jsonrpc=version)
    session=parse_text(json.dumps(row))
    assert session.messages[0].obj==row
    assert session.parsed==[]
    assert session.response_pairs()=={}
    assert any(f.code=='INVALID_RPC_VERSION' for f in diagnose(session))


@pytest.mark.parametrize('version',['1.0',None,2.0])
def test_wrong_reply_cannot_publish_catalog(version):
    rows=[{'id':1,'method':'tools/list'},
          {'id':1,'jsonrpc':version,'result':{'tools':[{'name':'x','inputSchema':{}}]}}]
    session=parse_text('\n'.join(map(json.dumps,rows)))
    assert session.response_for(session.requests()[0]) is None
    assert session.tools_by_name()=={}


@pytest.mark.parametrize('version',['2.0','omitted'])
def test_valid_and_omitted_version_compatibility(version):
    rows=[{'id':1,'method':'tools/list'},{'id':1,'result':{'tools':[]}}]
    if version!='omitted':
        for row in rows:row['jsonrpc']=version
    session=parse_text('\n'.join(map(json.dumps,rows)))
    assert session.response_for(session.requests()[0]).line_no==2
    assert any(f.code=='EMPTY_TOOLS_LIST' for f in diagnose(session))
    assert not any(f.code=='INVALID_RPC_VERSION' for f in diagnose(session))


@pytest.mark.parametrize('mode',['text','json'])
def test_cli_wrong_version_high_without_false_empty_catalog(tmp_path,capsys,mode):
    from mcptriage.cli import main
    path=tmp_path/'capture'
    path.write_text('{"id":1,"method":"tools/list"}\n{"jsonrpc":"1.0","id":1,"result":{"tools":[]}}')
    assert main(['diagnose',str(path),'--format',mode])==1
    out=capsys.readouterr().out
    assert 'INVALID_RPC_VERSION' in out
    assert 'EMPTY_TOOLS_LIST' not in out
