"""Repeated members are not unique evidence of a startup or schema result."""
import json
import pytest
from mcptriage.transcript import parse_text
from mcptriage.rules import diagnose
from mcptriage.report import render_json,render_text
from mcptriage.cli import main


ROWS = [
    '{"id":1,"id":2,"method":"tools/list"}',
    '{"id":1,"method":"ping","method":"initialize"}',
    '{"id":1,"result":null,"result":{"capabilities":{"tools":{}}}}',
    '{"id":1,"error":{"code":500,"code":401}}',
    '{"id":1,"result":{"tools":[],"tools":[{"name":"x"}]}}',
    '{"id":1,"result":{"tools":[{"name":"x","inputSchema":{"type":"string","type":"object"}}]}}',
    r'{"id":1,"method":"ping","\u006dethod":"tools/list"}',
    '{"id":1,"method":"tools/call","params":{"name":"a","name":"b"}}',
]


@pytest.mark.parametrize('prefix',['','2026-11-03 INFO: '])
@pytest.mark.parametrize('row',ROWS)
def test_full_and_embedded_ambiguous_object_excluded_with_no_nested_substitute(row,prefix):
    session=parse_text(prefix+row)
    assert len(session.messages)==1
    message=session.messages[0]
    assert message.kind=='duplicate_json_key' and message.obj is None
    assert message.raw==prefix+row
    assert session.parsed==[] and session.requests()==[]
    assert session.response_pairs()=={} and session.tools_by_name()=={}
    fs=diagnose(session)
    assert any(f.code=='DUPLICATE_JSON_KEY' and f.severity=='high' for f in fs)


def test_duplicate_initialize_result_cannot_establish_healthy_startup_regression_control():
    session=parse_text('{"id":1,"method":"initialize"}\n'+ROWS[2]+'\n{"method":"notifications/initialized"}')
    fs=diagnose(session)
    assert any(f.code=='DUPLICATE_JSON_KEY' and f.severity=='high' for f in fs), \
        'duplicate initialize result must not disappear into a clean startup report'
    assert not any(f.code=='MISSING_INITIALIZED' for f in fs)


@pytest.mark.parametrize('renderer',[render_json,render_text])
def test_no_raw_names_or_values_in_diagnostic(renderer):
    secret_key,secret_value='PRIVATE_MEMBER_7b48','PRIVATE_VALUE_2c91'
    raw='{"id":1,"result":{'+json.dumps(secret_key)+':'+json.dumps(secret_value)+','+json.dumps(secret_key)+':null}}'
    fs=diagnose(parse_text(raw))
    out=renderer(fs,'capture.jsonl')
    assert secret_key not in out and secret_value not in out
    assert 'line 1:' in out


def test_following_unambiguous_messages_continue_normally():
    s=parse_text(ROWS[0]+'\n{"id":3,"method":"tools/list"}\n{"id":3,"result":{"tools":[]}}')
    assert len(s.parsed)==2
    assert s.response_for(s.requests()[0]).result()=={'tools':[]}
    fs=diagnose(s)
    assert any(f.code=='EMPTY_TOOLS_LIST' for f in fs)


def test_distinct_objects_and_repeated_array_values_are_not_duplicate_members():
    s=parse_text('{"id":1,"method":"ping","params":{"a":{"x":1},"b":{"x":2},"v":[1,1]}}')
    assert len(s.parsed)==1 and s.messages[0].kind=='request'
    assert not any(f.code=='DUPLICATE_JSON_KEY' for f in diagnose(s))


@pytest.mark.parametrize('prefix',['','LOG '])
def test_precise_numeric_id_still_preserved(prefix):
    s=parse_text(prefix+'{"id":9007199254740993.0,"method":"ping"}')
    assert s.messages[0].msg_id==9007199254740993


@pytest.mark.parametrize('fmt',['text','json'])
def test_cli_fails_ambiguous_capture(tmp_path,capsys,fmt):
    p=tmp_path/'capture.jsonl';p.write_text(ROWS[2])
    assert main(['diagnose',str(p),'--format',fmt])==1
    assert 'DUPLICATE_JSON_KEY' in capsys.readouterr().out


def test_ambiguous_catalog_does_not_supply_argument_schema():
    text='\n'.join([
        '{"id":1,"method":"tools/list"}',
        '{"id":1,"result":{"tools":[{"name":"x","inputSchema":{"type":"object","properties":{"n":{"type":"integer","type":"string"}}}}]}}',
        '{"id":2,"method":"tools/call","params":{"name":"x","arguments":{"n":42}}}',
        '{"id":2,"error":{"code":-32602}}',
    ])
    s=parse_text(text)
    assert s.tools_by_name()=={}
    f=next(f for f in diagnose(s) if f.code=='TOOL_CALL_ARG_MISMATCH')
    assert 'violate' not in f.why


def test_ambiguous_request_is_not_recovered_as_its_nested_tools_call():
    raw='LOG {"meta":1,"meta":2,"nested":{"id":1,"method":"tools/call","params":{"name":"x"}}}'
    s=parse_text(raw)
    assert s.requests()==[] and len(s.messages)==1
    assert s.messages[0].kind=='duplicate_json_key'


def test_strict_mode_does_not_mislabel_ambiguous_json_as_logging_pollution():
    s=parse_text('{"id":1,"method":"initialize"}\n'+ROWS[2])
    fs=diagnose(s,strict_stdio=True)
    assert any(f.code=='DUPLICATE_JSON_KEY' for f in fs)
    assert not any(f.code=='STDIO_POLLUTION' for f in fs)
