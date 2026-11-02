"""Escaped quotes inside known credential values must not expose suffixes."""
import json
import pytest
from mcptriage.rules import redact,diagnose
from mcptriage.transcript import parse_text
from mcptriage.report import render_text,render_json

@pytest.mark.parametrize('key',['token','password','api_key','authorization'])
@pytest.mark.parametrize('value',['prefix"PRIVATE_SUFFIX','prefix\\PRIVATE_SUFFIX','prefix\nPRIVATE_SUFFIX'])
@pytest.mark.parametrize('layers',[0,1])
def test_json_string_escapes_preserve_complete_mask(key,value,layers):
    text=json.dumps({key:value,'status':'keep'})
    if layers:text=json.dumps({'text':text})
    output=redact(text)
    assert 'PRIVATE_SUFFIX' not in output
    assert 'keep' in output

@pytest.mark.parametrize('render',[render_text,render_json])
@pytest.mark.parametrize('secret',['prefix"PRIVATE_SUFFIX','prefix\\PRIVATE_SUFFIX'])
def test_actual_call_error_raw_evidence_and_decoded_content_both_masked(render,secret):
    rows=[{'id':1,'method':'tools/call','params':{'name':'x'}},
          {'id':1,'result':{'isError':True,'content':[{'type':'text','text':json.dumps({'token':secret})}]}}]
    fs=diagnose(parse_text('\n'.join(json.dumps(r) for r in rows)))
    assert 'PRIVATE_SUFFIX' not in render(fs,'<stdin>')


def test_noncredential_quoted_text_is_not_rewritten():
    text=json.dumps({'status':'literal"keep\\everything'})
    assert redact(text)==text

@pytest.mark.parametrize('layers',[0,1])
@pytest.mark.parametrize('value',['a"PRIVATE_SUFFIX','a\\"PRIVATE_SUFFIX','a\\\\PRIVATE_SUFFIX','a\nPRIVATE_SUFFIX','a\tPRIVATE_SUFFIX'])
def test_json_structure_and_unrelated_metadata_preserved(layers,value):
    text=json.dumps({'token':value,'status':'keep','values':[1,True,None]})
    if layers:text=json.dumps({'text':text,'outer':'keep-outer'})
    decoded=json.loads(redact(text))
    if layers:
        assert decoded['outer']=='keep-outer'
        decoded=json.loads(decoded['text'])
    assert decoded=={'token':'***','status':'keep','values':[1,True,None]}

@pytest.mark.parametrize('mode',['text','json'])
def test_long_escaped_quote_secret_masks_before_evidence_clip(tmp_path,capsys,mode):
    from mcptriage.cli import main
    value='head"'+('PRIVATE_SUFFIX'*60)
    p=tmp_path/'log.jsonl'
    p.write_text('{"id":1,"method":"tools/call","params":{"name":"x"}}\n'+json.dumps({'id':1,'result':{'isError':True,'content':[{'text':json.dumps({'token':value})}]}}))
    assert main(['diagnose',str(p),'--format',mode])==0
    out=capsys.readouterr().out
    assert 'TOOL_CALL_FAILED' in out and 'PRIVATE_SUFFIX' not in out


@pytest.mark.parametrize('slashes',range(1,9))
@pytest.mark.parametrize('key',['token','password','api_key','authorization'])
def test_encoded_trailing_backslashes_cannot_consume_next_credential(key,slashes):
    inner={key:'head'+('\\'*slashes),'client_secret':'PRIVATE_SUFFIX','status':'keep'}
    output=redact(json.dumps({'text':json.dumps(inner),'outer':'preserve'}))
    assert 'PRIVATE_SUFFIX' not in output
    outer=json.loads(output)
    assert outer['outer']=='preserve'
    assert json.loads(outer['text'])=={key:'***','client_secret':'***','status':'keep'}


@pytest.mark.parametrize('slashes',range(1,9))
@pytest.mark.parametrize('suffix',['','"','\n','a'])
def test_encoded_escape_tokens_preserve_following_noncredential_metadata(slashes,suffix):
    text=json.dumps({'text':json.dumps({'token':'head'+('\\'*slashes)+suffix,
                                      'status':'keep','array':[1,True,None]})})
    assert json.loads(json.loads(redact(text))['text'])=={
        'token':'***','status':'keep','array':[1,True,None]}


@pytest.mark.parametrize('render',[render_text,render_json])
@pytest.mark.parametrize('slashes',[1,2,3])
def test_encoded_trailing_backslashes_in_actual_error_evidence(render,slashes):
    secret=json.dumps({'token':'head'+('\\'*slashes),'password':'PRIVATE_SUFFIX','status':'keep'})
    rows=[{'id':1,'method':'tools/call','params':{'name':'x'}},
          {'id':1,'result':{'isError':True,'content':[{'type':'text','text':secret}]}}]
    findings=diagnose(parse_text('\n'.join(json.dumps(r) for r in rows)))
    output=render(findings,'<stdin>')
    assert 'TOOL_CALL_FAILED' in output and 'PRIVATE_SUFFIX' not in output
