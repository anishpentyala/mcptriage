"""Schema diagnostics need a paired non-error tools/list response, not key resemblance."""
import json
import pytest
from mcptriage.transcript import parse_text
from mcptriage.rules import diagnose

BAD={'tools':[{'name':'bad','inputSchema':{'type':'array'}}]}

def capture(*rows):
    return '\n'.join(json.dumps(r) for r in rows)

def schemas(*rows):
    return [f for f in diagnose(parse_text(capture(*rows))) if f.code=='SCHEMA_ISSUES']

@pytest.mark.parametrize('rows',[
    [{'id':1,'result':BAD}],
    [{'id':1,'method':'initialize'},{'id':1,'result':BAD}],
    [{'id':1,'method':'resources/list'},{'id':1,'result':BAD}],
    [{'id':1,'method':'tools/call'},{'id':1,'result':BAD}],
    [{'id':1,'method':'tools/list'},{'id':'1','result':BAD}],
    [{'id':1,'result':BAD},{'id':1,'method':'tools/list'}],
    [{'id':1,'method':'tools/list'},{'id':1,'result':{'tools':[]}},{'id':1,'result':BAD}],
    [{'id':1,'method':'tools/list'},{'id':1,'error':{'code':-32603}},{'id':1,'result':BAD}],
    [{'id':1,'method':'tools/list'},{'id':1,'error':{'code':-32603},'result':BAD}],
    [{'id':1,'method':'tools/list'},{'id':1,'method':'resources/list'},{'id':1,'result':BAD}],
    [{'id':1,'method':'tools/list'},{'id':1,'method':'tools/list'},{'id':1,'result':BAD}],
])
def test_unproven_tools_shaped_payload_not_called_list_schema(rows):
    assert schemas(*rows)==[]

@pytest.mark.parametrize('identifier',[1,'1',1.0,0])
def test_paired_list_preserves_schema_diagnostic(identifier):
    fs=schemas({'id':identifier,'method':'tools/list'},{'id':identifier,'result':BAD})
    assert len(fs)==1
    assert "tool 'bad' inputSchema type is 'array'" in fs[0].evidence

@pytest.mark.parametrize('schema',[None,[],{'type':'array'},{'required':[{}]}])
def test_all_existing_schema_checks_keep_working(schema):
    assert schemas({'id':1,'method':'tools/list'},
                   {'id':1,'result':{'tools':[{'name':'bad','inputSchema':schema}]}})

def test_completed_first_exchange_survives_later_id_reuse():
    fs=schemas({'id':1,'method':'tools/list'},{'id':1,'result':BAD},
               {'id':1,'method':'resources/list'},{'id':1,'result':{'tools':[]}})
    assert len(fs)==1

def test_sequential_tools_list_reuse_checks_each_result():
    fs=schemas({'id':1,'method':'tools/list'},{'id':1,'result':BAD},
               {'id':1,'method':'tools/list'},{'id':1,'result':BAD})
    assert len(fs)==1
    assert fs[0].title.startswith('2 tool schema')

def test_unrelated_payload_does_not_pollute_real_diagnostic():
    fs=schemas({'id':1,'method':'resources/list'},{'id':1,'result':BAD},
               {'id':2,'method':'tools/list'},{'id':2,'result':BAD})
    assert len(fs)==1
    assert fs[0].title.startswith('1 tool schema')

@pytest.mark.parametrize('mode',['text','json'])
def test_cli_omits_unproven_schema_claim(tmp_path,capsys,mode):
    from mcptriage.cli import main
    path=tmp_path/'capture.jsonl'
    path.write_text(capture({'id':1,'result':BAD}))
    main(['diagnose',str(path),'--format',mode])
    out=capsys.readouterr().out
    assert 'SCHEMA_ISSUES' not in out
    assert 'ORPHAN_RESPONSES' in out
