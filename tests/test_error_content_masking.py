"""Known credential prefixes must be masked before content clipping."""
import json
import pytest
from mcptriage.transcript import parse_text
from mcptriage.rules import diagnose
from mcptriage.report import render_text,render_json


@pytest.mark.parametrize('render',[render_text,render_json])
@pytest.mark.parametrize('text',[
    'Authorization: Bearer '+('private-marker'*30),
    '{"token":"'+('private-marker'*30)+'"}',
    'https://x.test/?token='+('private-marker'*30),
    'https://alice:'+('private-marker'*30)+'@x.test/',
])
def test_long_tool_error_content_masked_before_clip(render,text):
    rows=[{'id':1,'method':'tools/call','params':{'name':'x'}},
          {'id':1,'result':{'isError':True,'content':[{'type':'text','text':text}]}}]
    fs=diagnose(parse_text('\n'.join(map(json.dumps,rows))))
    f=next(f for f in fs if f.code=='TOOL_CALL_FAILED')
    assert 'private-marker' not in f.why
    assert 'private-marker' not in render(fs,'<stdin>')


@pytest.mark.parametrize('render',[render_text,render_json])
def test_plain_tool_error_content_remains_readable(render):
    rows=[{'id':1,'method':'tools/call','params':{'name':'x'}},
          {'id':1,'result':{'isError':True,'content':[{'type':'text','text':'database unavailable'}]}}]
    fs=diagnose(parse_text('\n'.join(map(json.dumps,rows))))
    assert 'database unavailable' in render(fs,'<stdin>')


@pytest.mark.parametrize('key',['token','api_key','access-token','refresh_token','password','client_secret','AUTHORIZATION'])
def test_one_layer_escaped_json_known_keys_masked_before_raw_evidence_clip(key):
    text=json.dumps({key:'private-marker'*30})
    rows=[{'id':1,'method':'tools/call','params':{'name':'x'}},
          {'id':1,'result':{'isError':True,'content':[{'type':'text','text':text}]}}]
    fs=diagnose(parse_text('\n'.join(map(json.dumps,rows))))
    assert 'private-marker' not in render_json(fs,'<stdin>')
    assert 'private-marker' not in render_text(fs,'<stdin>')


def test_escaped_clean_json_content_preserved():
    from mcptriage.rules import redact
    text=json.dumps({'text':json.dumps({'status':'database unavailable'})})
    assert redact(text)==text
