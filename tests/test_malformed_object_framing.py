"""A syntax-invalid first object cannot donate nested protocol evidence."""
import json
import pytest
from mcptriage.transcript import parse_text
from mcptriage.rules import diagnose

PAYLOADS=[{'id':7,'method':'tools/list'},
          {'id':7,'result':{'tools':[{'name':'invented','inputSchema':{'type':'object'}}]}}]

@pytest.mark.parametrize('prefix',['','2026-11-08 [mcp] '])
@pytest.mark.parametrize('payload',PAYLOADS)
@pytest.mark.parametrize('template',[
    '{{"broken": , "nested":{payload}}}',
    '{{"broken": invalid, "nested":{payload}}}',
    '{{"nested":{payload},}}',
    '{{"nested":{payload}',
])
def test_malformed_first_object_does_not_extract_nested_message(prefix,payload,template):
    text=prefix+template.format(payload=json.dumps(payload))
    session=parse_text(text)
    assert len(session.messages)==1
    assert session.messages[0].raw==text
    assert session.messages[0].kind=='unparsed'
    assert session.messages[0].obj is None
    assert session.requests()==[]
    assert session.parsed==[]
    assert 'NO_PROTOCOL_MESSAGES' in {f.code for f in diagnose(session)}

@pytest.mark.parametrize('prefix',['','[mcp] ','2026-11-08 INFO '])
def test_valid_first_object_and_log_suffix_remain_supported(prefix):
    row=json.dumps({'id':7,'method':'tools/list'})
    session=parse_text(prefix+row+' [client->server]')
    assert session.requests()[0].msg_id==7
    assert session.messages[0].extracted

def test_later_physical_records_still_pair_after_malformed_object():
    broken='{"broken": , "nested":{"id":7,"method":"tools/list"}}'
    session=parse_text(broken+'\n{"id":8,"method":"tools/list"}\n{"id":8,"result":{"tools":[]}}')
    assert [m.msg_id for m in session.requests()]==[8]
    assert session.response_for(session.requests()[0]).line_no==3
    assert session.messages[0].kind=='unparsed'

def test_malformed_list_response_cannot_supply_catalog():
    text='{"id":7,"method":"tools/list"}\n{"broken": , "nested":{"id":7,"result":{"tools":[{"name":"invented","inputSchema":{"type":"object"}}]}}}'
    session=parse_text(text)
    assert session.response_for(session.requests()[0]) is None
    assert session.tools_by_name()=={}
    assert 'TOOLS_LIST_HANG' in {f.code for f in diagnose(session)}

@pytest.mark.parametrize('mode',['text','json'])
def test_cli_malformed_record_retains_missing_reply(tmp_path,capsys,mode):
    from mcptriage.cli import main
    path=tmp_path/'capture.jsonl'
    path.write_text('{"id":7,"method":"tools/list"}\n{"nested":{"id":7,"result":{"tools":[]}},}')
    assert main(['diagnose',str(path),'--stdio','--format',mode])==1
    output=capsys.readouterr()
    assert 'TOOLS_LIST_HANG' in output.out
    assert 'EMPTY_TOOLS_LIST' not in output.out
    assert 'Traceback' not in output.err


def test_malformed_brace_in_log_prefix_does_not_skip_to_later_message():
    text='[context {not JSON}] {"id":7,"method":"tools/list"}'
    session=parse_text(text)
    assert session.messages[0].kind=='unparsed'
    assert session.messages[0].raw==text
    assert session.requests()==[]


def test_valid_nonprotocol_first_object_does_not_skip_to_later_message():
    session=parse_text('log: {"metadata":true} {"id":7,"method":"tools/list"}')
    assert session.messages[0].kind=='unparsed'
    assert session.requests()==[]


def test_valid_nonprotocol_nested_object_does_not_create_request():
    session=parse_text('log: {"nested":{"id":7,"method":"tools/list"}}')
    assert session.messages[0].kind=='unparsed'
    assert session.requests()==[]
