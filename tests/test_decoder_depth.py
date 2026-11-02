"""Decoder recursion limits retain evidence instead of aborting a capture."""
import json
import pytest
from mcptriage.transcript import parse_text
from mcptriage.rules import diagnose

@pytest.mark.parametrize('prefix',['','log: '])
@pytest.mark.parametrize('shape',['array','object'])
def test_deep_input_retained_not_crash(prefix,shape):
    nested=('['*2000+'0'+']'*2000 if shape=='array' else
            '{"x":'*2000+'0'+'}'*2000)
    text=prefix+'{"id":1,"method":"tools/list","params":{"nested":'+nested+'}}'
    s=parse_text(text)
    assert len(s.messages)==1
    assert s.messages[0].raw==text
    assert s.messages[0].kind=='unparsed'
    assert any(f.code=='NO_PROTOCOL_MESSAGES' for f in diagnose(s))

@pytest.mark.parametrize('prefix',['','log: '])
def test_deep_rejected_object_not_replaced_by_nested_request(prefix):
    text=prefix+'{"nested":'+'['*2000+'0'+']'*2000+',"fake":{"id":7,"method":"tools/list"}}'
    s=parse_text(text)
    assert s.requests()==[]
    assert s.messages[0].raw==text

def test_other_message_survives_deep_failure():
    text='['*2000+'0'+']'*2000+'\n{"id":2,"method":"tools/list"}'
    fs=diagnose(parse_text(text))
    assert any(f.code=='TOOLS_LIST_HANG' for f in fs)

@pytest.mark.parametrize('prefix',['','log: '])
def test_ordinary_nested_params_still_pair(prefix):
    nested={'x':{'y':[1,2]}}
    s=parse_text(prefix+json.dumps({'id':1,'method':'tools/list','params':nested})+'\n'+
                 prefix+'{"id":1,"result":{"tools":[]}}')
    assert s.response_for(s.requests()[0]).line_no==2

@pytest.mark.parametrize('mode',['text','json'])
def test_deep_capture_cli_diagnostic(tmp_path,capsys,mode):
    from mcptriage.cli import main
    p=tmp_path/'capture.jsonl';p.write_text('['*2000+'0'+']'*2000)
    assert main(['diagnose',str(p),'--format',mode])==1
    assert 'NO_PROTOCOL_MESSAGES' in capsys.readouterr().out
