"""Malformed tools/list catalog fields remain explicit, never a healthy catalog."""
import json
import pytest
from mcptriage.rules import diagnose
from mcptriage.transcript import parse_text


def run(result):
    rows=[{'id':1,'method':'tools/list'}, {'id':1,'result':result}]
    return diagnose(parse_text('\n'.join(json.dumps(r) for r in rows)))

@pytest.mark.parametrize('result',[None,[],False,0,'tools',{},
    {'tools':None},{'tools':{}},{'tools':'bad'},{'tools':0},{'tools':False}])
def test_catalog_must_be_object_with_tools_array(result):
    fs=run(result)
    assert any(f.code=='UNUSABLE_TOOLS_CATALOG' and f.severity=='high' for f in fs)
    assert not any(f.code=='EMPTY_TOOLS_LIST' for f in fs)

@pytest.mark.parametrize('tool',[None,[],True,7,'x',{},
    {'name':None},{'name':[]},{'name':False},{'name':7}])
def test_catalog_entries_require_objects_with_string_names(tool):
    fs=run({'tools':[tool]})
    assert any(f.code=='UNUSABLE_TOOLS_CATALOG' and f.severity=='high' for f in fs)

@pytest.mark.parametrize('tools',[[],[{'name':'x','inputSchema':{}}],
    [{'name':'x','inputSchema':{}},{'name':'y','inputSchema':{}}]])
def test_usable_catalog_does_not_get_shape_finding(tools):
    assert not any(f.code=='UNUSABLE_TOOLS_CATALOG' for f in run({'tools':tools}))

@pytest.mark.parametrize('method',['initialize','resources/list','tools/call'])
def test_unrelated_methods_not_treated_as_bad_catalog(method):
    rows=[{'id':1,'method':method},{'id':1,'result':{}}]
    assert not any(f.code=='UNUSABLE_TOOLS_CATALOG' for f in diagnose(parse_text(
        '\n'.join(json.dumps(r) for r in rows))))

@pytest.mark.parametrize('mode',['text','json'])
def test_cli_high_shape_failure(tmp_path,capsys,mode):
    from mcptriage.cli import main
    p=tmp_path/'capture.jsonl'
    p.write_text('{"id":1,"method":"tools/list"}\n{"id":1,"result":{"tools":{}}}')
    assert main(['diagnose',str(p),'--format',mode])==1
    out=capsys.readouterr().out
    assert 'UNUSABLE_TOOLS_CATALOG' in out

def test_known_good_and_malformed_entries_both_have_evidence():
    fs=run({'tools':[None,{'name':'x','inputSchema':{'type':'array'}}]})
    assert any(f.code=='UNUSABLE_TOOLS_CATALOG' for f in fs)
    assert any(f.code=='SCHEMA_ISSUES' for f in fs)

def test_jsonrpc_error_not_called_malformed_catalog():
    rows=[{'id':1,'method':'tools/list'},{'id':1,'error':{'code':-32603}}]
    assert not any(f.code=='UNUSABLE_TOOLS_CATALOG' for f in diagnose(parse_text(
        '\n'.join(json.dumps(r) for r in rows))))
