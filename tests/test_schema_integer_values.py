"""JSON Schema integer checks use mathematical numeric value, excluding bool."""
import json
import pytest
from mcptriage.rules import validate_arguments,diagnose
from mcptriage.transcript import parse_text


@pytest.mark.parametrize('value',[0.0,1.0,-1.0,10000000000.0,0,1,-1])
def test_integral_numbers_satisfy_integer_type(value):
    assert validate_arguments({'properties':{'x':{'type':'integer'}}},{'x':value})==[]


@pytest.mark.parametrize('value',[True,False,1.5,-0.25,'1',None,[],{}])
def test_nonintegers_still_rejected(value):
    assert validate_arguments({'properties':{'x':{'type':'integer'}}},{'x':value})


@pytest.mark.parametrize('wire',['1.0','1e0','-2.0','0.0'])
def test_wire_integral_values_do_not_invent_argument_violation(wire):
    text=(' {"id":1,"method":"tools/list"}\n'
          '{"id":1,"result":{"tools":[{"name":"x","inputSchema":{"type":"object",'
          '"properties":{"n":{"type":"integer"}}}}]}}\n'
          '{"id":2,"method":"tools/call","params":{"name":"x","arguments":{"n":'+wire+'}}}\n'
          '{"id":2,"error":{"code":-32602}}')
    fs=diagnose(parse_text(text))
    f=next(f for f in fs if f.code=='TOOL_CALL_PROTOCOL_ERROR')
    assert 'should be integer' not in f.why
