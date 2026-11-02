"""Static config checks reject unusable field types without printing values."""
import json
import pytest
from mcptriage.configcheck import check_config_text


def inspect(spec):
    return check_config_text(json.dumps({'mcpServers':{'x':spec}}))


@pytest.mark.parametrize('field,value',[
    ('command',True),('command',1),('command',[]),('command',{}),('command',None),
    ('url',True),('url',1),('url',[]),('url',{}),('url',None),
    ('args',[None]),('args',[1]),('args',[True]),('args',[{}]),('args',[[]]),
    ('env',[]),('env',True),('env',1),('env',None),
    ('env',{'SECRET':['private-marker']}),('env',{'SECRET':1}),('env',{'SECRET':None}),
    ('envFile',[]),('envFile',True),('envFile',1),('envFile',None),
])
def test_malformed_field_is_reported_without_value(field,value):
    spec={'command':'python'}
    spec[field]=value
    fs=inspect(spec)
    assert any(f.code=='CFG_SHAPE' and field in f.title for f in fs)
    assert not any('private-marker' in str(f) for f in fs)


@pytest.mark.parametrize('spec',[
    {'command':'python'}, {'url':'https://example.test/mcp'},
    {'command':'python','args':['-m','server']}, {'command':'python','env':{'X':'plain'}},
    {'command':'python','args':[],'env':{}},
])
def test_supported_field_shapes_keep_existing_checks(spec):
    assert not any(f.code=='CFG_SHAPE' for f in inspect(spec))


def test_invalid_url_does_not_invent_endpoint_conflict():
    fs=inspect({'command':'python','url':{'secret':'private-marker'}})
    assert not any('both' in f.title for f in fs)
    assert any(f.code=='CFG_SHAPE' and 'url' in f.title for f in fs)


def test_invalid_command_does_not_hide_missing_endpoint():
    fs=inspect({'command':True})
    assert any('neither' in f.title for f in fs)


def test_valid_environment_value_not_echoed():
    fs=inspect({'command':'python','env':{'SECRET':'private-marker'}})
    assert not any('private-marker' in str(f) for f in fs)


@pytest.mark.parametrize('mode',['text','json'])
@pytest.mark.parametrize('spec',[
    {'command':True}, {'command':'python','args':['-m',{'secret':'private-marker'}]},
    {'command':'python','env':{'SECRET':['private-marker']}},
])
def test_cli_reports_bad_config_without_echoing_value(tmp_path,capsys,mode,spec):
    from mcptriage.cli import main
    p=tmp_path/'config.json'
    p.write_text(json.dumps({'mcpServers':{'x':spec}}))
    result=main(['check-config',str(p),'--format',mode])
    out=capsys.readouterr()
    assert 'CFG_SHAPE' in out.out
    assert 'private-marker' not in out.out and 'Traceback' not in out.err
    assert result==(1 if spec.get('command') is True else 0)
