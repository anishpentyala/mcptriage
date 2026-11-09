"""Wire schema checks must not compare rounded IEEE-754 substitutes."""
import pytest
from mcptriage.transcript import parse_text
from mcptriage.rules import diagnose


def explanation(allowed,value,declared=None,prefix=''):
    schema='"enum":['+allowed+']' if declared is None else '"type":"'+declared+'"'
    text='\n'.join(prefix+s for s in [
        '{"id":1,"method":"tools/list"}',
        '{"id":1,"result":{"tools":[{"name":"calc","inputSchema":{"properties":{"x":{'+schema+'}}}}]}}',
        '{"id":2,"method":"tools/call","params":{"name":"calc","arguments":{"x":'+value+'}}}',
        '{"id":2,"error":{"code":-32602,"message":"Invalid params"}}',
    ])
    return next(f.why for f in diagnose(parse_text(text)) if f.code in ('TOOL_CALL_ARG_MISMATCH', 'TOOL_CALL_PROTOCOL_ERROR'))


@pytest.mark.parametrize('prefix',['','2026-11-05 INFO '])
@pytest.mark.parametrize('allowed,value,match',[
    ('1','1.00000000000000001',False),
    ('9007199254740993','9007199254740993.0',True),
    ('1e400','2e400',False),
    ('1e-400','2e-400',False),
    ('0.12345678901234567891','0.12345678901234567892',False),
    ('1e400','10e399',True),
    ('-1e400','-2e400',False),
    ('{"n":[9007199254740993]}','{"n":[9007199254740993.0]}',True),
    ('true','1.0',False),
])
def test_wire_enum_mathematical_equality(allowed,value,match,prefix):
    why=explanation(allowed,value,prefix=prefix)
    assert ('not one of' not in why) is match


@pytest.mark.parametrize('value,integer',[
    ('1.00000000000000001',False),('9007199254740993.0',True),
    ('1e400',True),('1e-400',False),('0e-400',True),('-1e-400',False),
])
def test_wire_integer_uses_actual_fractional_part(value,integer):
    why=explanation('null',value,declared='integer')
    assert ('should be integer' not in why) is integer


@pytest.mark.parametrize('value',['1e9999999999999999999','1e-9999999999999999999'])
def test_beyond_decimal_exponent_range_is_not_schema_proof(value):
    assert 'not one of' not in explanation('1',value)
    assert 'should be integer' not in explanation('null',value,declared='integer')


@pytest.mark.parametrize('code',['-32602.00000000000000001','401.00000000000000001',
                                  '-32022.00000000000000001'])
def test_rounded_error_code_does_not_borrow_integer_meaning(code):
    text='{"id":1,"method":"tools/call","params":{"name":"x"}}\n'+ '{"id":1,"error":{"code":'+code+'}}'
    findings=diagnose(parse_text(text))
    assert any(f.code=='UNUSABLE_ERROR_CODE' for f in findings)
    assert not any(f.code in {'TOOL_CALL_ARG_MISMATCH','AUTH_FAILURE'} for f in findings)


@pytest.mark.parametrize('fmt',['text','json'])
def test_cli_exact_wire_mismatch_has_readable_evidence(tmp_path,capsys,fmt):
    import json
    from mcptriage.cli import main
    text='\n'.join([
        '{"id":1,"method":"tools/list"}',
        '{"id":1,"result":{"tools":[{"name":"calc","inputSchema":{"properties":{"x":{"enum":[1e400]}}}}]}}',
        '{"id":2,"method":"tools/call","params":{"name":"calc","arguments":{"x":2e400}}}',
        '{"id":2,"error":{"code":-32602}}'])
    path=tmp_path/'capture.jsonl';path.write_text(text)
    assert main(['diagnose',str(path),'--format',fmt])==1
    output=capsys.readouterr().out
    assert 'not one of [1e400]' in output
    if fmt=='json':
        assert json.loads(output)['finding_count']>0


def test_existing_float_api_and_wire_metadata_are_both_preserved():
    import json
    message=parse_text('{"id":1.0,"method":"x","params":{"n":9007199254740993.0}}').messages[0]
    number=message.obj['params']['n']
    assert isinstance(number,float)
    assert str(number.exact)=='9007199254740993.0'
    assert message.msg_id==1 and type(message.msg_id) is int
    assert json.loads(json.dumps(message.obj))['params']['n']==float(number)



def test_fractional_401_code_is_not_authentication_evidence_on_list():
    text='{"id":1,"method":"tools/list"}\n'+ '{"id":1,"error":{"code":401.00000000000000001}}'
    findings=diagnose(parse_text(text))
    assert any(f.code=='UNUSABLE_ERROR_CODE' for f in findings)
    assert not any(f.code=='AUTH_ON_LIST' for f in findings)
