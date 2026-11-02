"""Malformed schema evidence cannot crash or invent argument explanations."""
import json
import pytest
from mcptriage.transcript import parse_text
from mcptriage.rules import diagnose,validate_arguments

@pytest.mark.parametrize('required',[[{}],[[]],[True],[1],[None],['x','x'],['x',{}]])
def test_invalid_required_is_not_used_as_argument_evidence(required):
    schema={'type':'object','required':required}
    assert validate_arguments(schema,{})==[]
    rows=[{'id':1,'method':'tools/list'},
          {'id':1,'result':{'tools':[{'name':'x','inputSchema':schema}]}},
          {'id':2,'method':'tools/call','params':{'name':'x','arguments':{}}},
          {'id':2,'error':{'code':-32602}}]
    fs=diagnose(parse_text('\n'.join(json.dumps(x) for x in rows)))
    assert any(f.code=='SCHEMA_ISSUES' for f in fs)
    assert not any(f.code=='TOOL_CALL_ARG_MISMATCH' and 'missing required' in f.why for f in fs)


@pytest.mark.parametrize('value',[True,False,1,0,1.0,None,'1',[],{}])
def test_enum_compares_json_types_instead_of_python_bool_number_alias(value):
    problems=validate_arguments({'properties':{'x':{'enum':[True]}}},{'x':value})
    assert bool(problems)==(value is not True)


def test_numeric_integer_float_equality_stays_valid():
    assert validate_arguments({'properties':{'x':{'enum':[1]}}},{'x':1.0})==[]


def test_nested_enum_boolean_alias_does_not_pass():
    assert validate_arguments({'properties':{'x':{'enum':[{'enabled':True}]}}},
                              {'x':{'enabled':1}})


def test_valid_required_still_explains_missing_argument():
    assert validate_arguments({'required':['x']},{})==["missing required argument 'x'"]


@pytest.mark.parametrize('left,right,match',[
    ([True],[1],False),([False],[0],False),
    ({'x':[True]},{'x':[1]},False),
    ({'x':1},{'x':1.0},True),([1],[1.0],True),
    ({'a':1,'b':True},{'b':True,'a':1.0},True),
    ([1,2],[2,1],False),([],{},False),
    (None,None,True),('1',1,False),
])
def test_enum_json_equality_nested_and_preservation(left,right,match):
    p=validate_arguments({'properties':{'x':{'enum':[left]}}},{'x':right})
    assert bool(p) is not match


@pytest.mark.parametrize('mode',['text','json'])
def test_cli_malformed_required_diagnoses_not_traceback(tmp_path,capsys,mode):
    from mcptriage.cli import main
    rows=[{'id':1,'method':'tools/list'},
          {'id':1,'result':{'tools':[{'name':'x','inputSchema':{'required':[{}]}}]}},
          {'id':2,'method':'tools/call','params':{'name':'x','arguments':{}}},
          {'id':2,'error':{'code':-32602}}]
    p=tmp_path/'capture.jsonl'
    p.write_text('\n'.join(json.dumps(r) for r in rows))
    assert main(['diagnose',str(p),'--format',mode])==1
    o=capsys.readouterr()
    assert 'SCHEMA_ISSUES' in o.out
    assert 'missing required' not in o.out
    assert 'Traceback' not in o.err


def test_absent_and_empty_required_stay_valid():
    assert validate_arguments({}, {})==[]
    assert validate_arguments({'required':[]}, {})==[]
