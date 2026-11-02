"""Interpreter integer conversion limits must not crash or fabricate nested traffic."""
import json
import pytest
from mcptriage.transcript import parse_text
from mcptriage.rules import diagnose

@pytest.fixture(autouse=True)
def bounded_integer_decoder(monkeypatch):
    # Exercise the runtime rejection path on every supported Python version,
    # including 3.9/3.10 builds that do not enable an integer-string limit.
    original = json.loads
    decoder = json.JSONDecoder
    def bounded(value):
        if len(value.lstrip('-')) > 4300:
            raise ValueError('integer conversion limit')
        return int(value)
    def loads(text, **kwargs):
        kwargs.setdefault('parse_int', bounded)
        return original(text, **kwargs)
    class BoundedDecoder(decoder):
        def __init__(self, *args, **kwargs):
            kwargs.setdefault('parse_int', bounded)
            super().__init__(*args, **kwargs)
    monkeypatch.setattr(json, 'loads', loads)
    monkeypatch.setattr(json, 'JSONDecoder', BoundedDecoder)


@pytest.mark.parametrize('prefix',['','2026-11-02 [mcp] '])
@pytest.mark.parametrize('field',['"id":%s,"method":"tools/list"',
    '"id":1,"method":"tools/list","params":{"x":%s}',
    '"id":1,"result":{"tools":[],"count":%s}'])
def test_oversized_integer_is_retained_without_crash(prefix,field):
    text=prefix+'{'+field % ('9'*5000)+'}'
    s=parse_text(text)
    assert len(s.messages)==1
    assert s.messages[0].raw==text
    assert s.messages[0].kind=='unparsed'
    assert any(f.code=='NO_PROTOCOL_MESSAGES' for f in diagnose(s))

@pytest.mark.parametrize('prefix',['','log: '])
def test_limit_failure_does_not_extract_nested_fake_request(prefix):
    text=prefix+'{"count":'+('9'*5000)+',"nested":{"id":7,"method":"tools/list"}}'
    s=parse_text(text)
    assert s.requests()==[]
    assert s.messages[0].kind=='unparsed'

def test_other_lines_still_diagnosed_after_limit_failure():
    text='{"id":'+('9'*5000)+',"method":"initialize"}\n{"id":2,"method":"tools/list"}'
    s=parse_text(text)
    assert len(s.messages)==2
    assert len(s.requests())==1
    assert any(f.code=='TOOLS_LIST_HANG' for f in diagnose(s))

@pytest.mark.parametrize('prefix',['','log: '])
def test_long_numeric_string_id_is_not_rejected(prefix):
    identifier='9'*5000
    s=parse_text(prefix+json.dumps({'id':identifier,'method':'tools/list'})+'\n'+
                 prefix+json.dumps({'id':identifier,'result':{'tools':[]}}))
    assert s.response_for(s.requests()[0]).line_no==2
    assert 'NO_PROTOCOL_MESSAGES' not in {f.code for f in diagnose(s)}

def test_near_limit_integer_still_pairs():
    identifier='9'*1000
    s=parse_text('{"id":'+identifier+',"method":"tools/list"}\n'+
                 '{"id":'+identifier+',"result":{"tools":[]}}')
    assert s.response_for(s.requests()[0]).line_no==2

@pytest.mark.parametrize('mode',['text','json'])
def test_cli_conversion_limit_returns_diagnostic_not_traceback(tmp_path,capsys,mode):
    from mcptriage.cli import main
    p=tmp_path/'capture.jsonl';p.write_text('{"id":'+('9'*5000)+',"method":"tools/list"}')
    assert main(['diagnose',str(p),'--format',mode])==1
    out=capsys.readouterr()
    assert 'NO_PROTOCOL_MESSAGES' in out.out
    assert 'Traceback' not in out.err
