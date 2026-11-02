"""Config decoder limits are explicit diagnostic failures, not tracebacks."""
import json
import pytest
from mcptriage.configcheck import check_config_text

@pytest.fixture(autouse=True)
def decoder_limits(monkeypatch):
    original=json.loads
    def bounded(value):
        if len(value.lstrip('-'))>4300:raise ValueError('integer conversion limit')
        return int(value)
    def loads(text,**kwargs):
        kwargs.setdefault('parse_int',bounded)
        return original(text,**kwargs)
    monkeypatch.setattr(json,'loads',loads)

@pytest.mark.parametrize('shape',['integer','array','object'])
def test_rejected_config_gets_explicit_high_finding(shape,rejected_nesting_depth):
    value = ('9'*5000 if shape=='integer' else
             '['*rejected_nesting_depth+'0'+']'*rejected_nesting_depth if shape=='array' else
             '{"x":'*rejected_nesting_depth+'0'+'}'*rejected_nesting_depth)
    text='{"mcpServers":{"s":{"command":"python","extra":'+value+'}}}'
    fs=check_config_text(text)
    assert len(fs)==1
    assert fs[0].code=='CFG_JSON_LIMIT'
    assert fs[0].severity=='high'
    assert '9'*20 not in fs[0].evidence
    assert 'runtime' in fs[0].why

@pytest.mark.parametrize('mode',['text','json'])
@pytest.mark.parametrize('command',['check-config','diagnose'])
def test_cli_limits_not_tracebacks(tmp_path,capsys,mode,command):
    from mcptriage.cli import main
    cfg=tmp_path/'mcp.json';cfg.write_text('{"mcpServers":{"x":'+('9'*5000)+'}}')
    args=['check-config',str(cfg)]
    if command=='diagnose':
        log=tmp_path/'log.jsonl';log.write_text('{"id":1,"method":"initialize"}')
        args=['diagnose',str(log),'--config',str(cfg)]
    assert main([*args,'--format',mode])==1
    out=capsys.readouterr()
    assert 'CFG_JSON_LIMIT' in out.out
    assert 'Traceback' not in out.err

def test_invalid_syntax_keeps_position():
    fs=check_config_text('{broken')
    assert fs[0].code=='CFG_JSON_ERROR'
    assert ':1:2' in fs[0].evidence

def test_ordinary_nested_config_still_checked():
    fs=check_config_text(json.dumps({'mcpServers':{'s':{'url':'https://example.invalid/mcp','extra':{'x':[1,2]}}}}))
    assert not any(f.code.startswith('CFG_JSON_') for f in fs)
