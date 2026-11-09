"""Supported nested enum equality must not recurse after successful decoding."""
import json
import pytest
from mcptriage.rules import validate_arguments,diagnose
from mcptriage.transcript import parse_text


def nested(value,depth,kind):
    for _ in range(depth):value=[value] if kind=='array' else {'x':value}
    return value

@pytest.mark.parametrize('kind',['array','object'])
@pytest.mark.parametrize('equal',[True,False])
@pytest.mark.parametrize('depth',[30,1200,2400])
def test_deep_enum_values_use_structural_json_equality(kind,equal,depth):
    value=nested(1,depth,kind)
    allowed=nested(1.0 if equal else 2,depth,kind)
    problems=validate_arguments({'properties':{'arg':{'enum':[allowed]}}},{'arg':value})
    assert bool(problems) is not equal

@pytest.mark.parametrize('depth',[30,1200,2400])
def test_accepted_deep_json_transcript_never_aborts_diagnosis(depth):
    # Real runtime decoder: accepted on newer builds, preserved unparsed on others.
    value='['*depth+'0'+']'*depth
    text='{"id":1,"method":"tools/list"}\n{"id":1,"result":{"tools":[{"name":"x","inputSchema":{"properties":{"arg":{"enum":['+value+']}}}}]}}\n{"id":2,"method":"tools/call","params":{"name":"x","arguments":{"arg":'+value+'}}}\n{"id":2,"error":{"code":-32602}}'
    s=parse_text(text)
    fs=diagnose(s)
    if len(s.parsed)==4:
        f=next(f for f in fs if f.code in ('TOOL_CALL_ARG_MISMATCH', 'TOOL_CALL_PROTOCOL_ERROR'))
        assert 'not one of' not in f.why
    else:
        assert s.unparsed
        assert any(f.code in ('STDIO_POLLUTION','NO_PROTOCOL_MESSAGES') for f in fs)

@pytest.mark.parametrize('left,right,equals',[
    (True,1,False),(False,0,False),(1,1.0,True),([True],[1],False),
    ({'x':1},{'x':1.0},True),({'x':1},{'y':1},False),([1],[1,2],False),
])
def test_shallow_equality_keeps_json_type_semantics(left,right,equals):
    problems=validate_arguments({'properties':{'arg':{'enum':[right]}}},{'arg':left})
    assert bool(problems) is not equals

@pytest.mark.parametrize('kind',['array','object'])
def test_deep_mismatch_has_bounded_safe_explanation(kind):
    problems=validate_arguments({'properties':{'arg':{'enum':[nested(2,2400,kind)]}}},{'arg':nested(1,2400,kind)})
    assert len(problems)==1 and len(problems[0])<220
    assert 'not one of' in problems[0]


def test_equality_does_not_mutate_schema_or_arguments():
    schema={'properties':{'arg':{'enum':[{'x':[1,True,None]}]}}}
    args={'arg':{'x':[1.0,True,None]}}
    before=json.dumps([schema,args],sort_keys=True)
    assert validate_arguments(schema,args)==[]
    assert json.dumps([schema,args],sort_keys=True)==before


def test_later_enum_alternative_can_match_after_deep_mismatch():
    assert validate_arguments({'properties':{'arg':{'enum':[nested(0,1800,'array'),nested(1,1800,'array')]}}},{'arg':nested(1.0,1800,'array')})==[]


def test_short_mismatch_explanation_stays_readable():
    assert validate_arguments({'properties':{'arg':{'enum':['a','b']}}},{'arg':'c'})==["argument 'arg' is not one of ['a', 'b']"]


@pytest.mark.parametrize('equal',[True,False])
@pytest.mark.parametrize('mode',['text','json'])
@pytest.mark.parametrize('source',['file','stdin'])
def test_cli_deep_enum_has_safe_exit_and_bounded_output(equal,mode,source,tmp_path):
    import subprocess
    import sys
    depth=2000
    value='['*depth+'1'+']'*depth
    allowed='['*depth+('1.0' if equal else '2')+']'*depth
    text='\n'.join([
        '{"id":0,"method":"initialize"}',
        '{"id":0,"result":{"capabilities":{"tools":{}}}}',
        '{"method":"notifications/initialized"}',
        '{"id":1,"method":"tools/list"}',
        '{"id":1,"result":{"tools":[{"name":"x","inputSchema":{"properties":{"arg":{"enum":['+allowed+']}}}}]}}',
        '{"id":2,"method":"tools/call","params":{"name":"x","arguments":{"arg":'+value+'}}}',
        '{"id":2,"error":{"code":-32602}}',
    ])
    path=tmp_path/'deep.jsonl'
    path.write_text(text)
    result=subprocess.run(
        [sys.executable,'-m','mcptriage','diagnose',str(path) if source=='file' else '-','--format',mode],
        input=text if source=='stdin' else None,text=True,capture_output=True,timeout=15,
    )
    assert not result.stderr, 'CLI must not emit a traceback for accepted deep enum values'
    assert result.returncode==1
    assert len(result.stdout)<3000
    accepted=len(parse_text(text).parsed)==7
    if accepted:
        assert ('TOOL_CALL_PROTOCOL_ERROR' if equal else 'TOOL_CALL_ARG_MISMATCH') in result.stdout
        assert ('not one of' in result.stdout) is (not equal)
    else:
        # Runtime decoder rejection stays capture-quality evidence, not schema evidence.
        assert 'TOOL_CALL_ARG_MISMATCH' not in result.stdout
        assert 'STDIO_POLLUTION' in result.stdout
    if mode=='json':
        report=json.loads(result.stdout)
        assert report['finding_count']>=1
        if accepted:
            assert report['finding_count']==1


@pytest.mark.parametrize('mode',['text','json'])
def test_enum_explanation_masks_known_secret_before_clipping(mode):
    from mcptriage.report import render_text,render_json
    secret='SYNTHETIC_PRIVATE_SUFFIX'*50
    allowed=json.dumps({'token':secret,'version':'next'})
    rows=[{'id':1,'method':'tools/list'},
          {'id':1,'result':{'tools':[{'name':'x','inputSchema':{'properties':{'arg':{'enum':[allowed]}}}}]}},
          {'id':2,'method':'tools/call','params':{'name':'x','arguments':{'arg':'wrong'}}},
          {'id':2,'error':{'code':-32602}}]
    fs=diagnose(parse_text('\n'.join(map(json.dumps,rows))))
    output=(render_json if mode=='json' else render_text)(fs,'synthetic')
    assert 'SYNTHETIC_PRIVATE_SUFFIX' not in output
    assert '***' in output


@pytest.mark.parametrize('key',['token','password','api_key','authorization'])
@pytest.mark.parametrize('escape',['quote"','backslash\\'])
@pytest.mark.parametrize('mode',['text','json'])
def test_long_escaped_enum_secret_is_not_partially_displayed(key,escape,mode):
    from mcptriage.report import render_text,render_json
    secret=escape+'SYNTHETIC_ENUM_CANARY'*50
    allowed=json.dumps({key:secret,'version':'next'})
    rows=[{'id':1,'method':'tools/list'},
          {'id':1,'result':{'tools':[{'name':'x','inputSchema':{'properties':{'arg':{'enum':[allowed]}}}}]}},
          {'id':2,'method':'tools/call','params':{'name':'x','arguments':{'arg':'wrong'}}},
          {'id':2,'error':{'code':-32602}}]
    fs=diagnose(parse_text('\n'.join(map(json.dumps,rows))))
    output=(render_json if mode=='json' else render_text)(fs,'synthetic')
    assert 'SYNTHETIC_ENUM_CANARY' not in output
    assert 'not one of' in output
