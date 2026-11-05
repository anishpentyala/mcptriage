"""const uses existing JSON equality, including an explicitly null constant."""
import copy
import json
import pytest
from mcptriage.rules import diagnose,validate_arguments
from mcptriage.transcript import WireNumber,parse_text


def check(value,const):
    return validate_arguments({'properties':{'x':{'const':const}}},{'x':value})

@pytest.mark.parametrize('value,const,equal',[
    (None,None,True),(None,'null',False),('null',None,False),
    (True,1,False),(False,0,False),(1,True,False),(0,False,False),
    (True,True,True),(False,False,True),(1,1.,True),('1',1,False),
    ('x','x',True),('x','y',False),([],[],True),({},[],False),
    ([1],[1.],True),([True],[1],False),([1,2],[2,1],False),
    ({'a':1,'b':True},{'b':True,'a':1.},True),
    ({'x':True},{'x':1},False),({'x':1},{'y':1},False),
])
def test_const_json_equality(value,const,equal):
    assert bool(check(value,const)) is (not equal)

@pytest.mark.parametrize('value,const,equal',[
    ('9007199254740993.0','9007199254740992.0',False),
    ('9007199254740993.0','9007199254740993',True),
    ('1e400','10e399',True),('1e-400','0',False),
    ('0.1','0.10000000000000000001',False),('-0.0','0.0',True),
])
def test_exact_wire_numeric_identity(value,const,equal):
    assert bool(check(WireNumber(value),WireNumber(const))) is (not equal)

@pytest.mark.parametrize('equal',[True,False])
def test_deep_const_values_do_not_recurse(equal):
    left,right=1,1. if equal else 2
    for _ in range(1500):left,right=[left],[right]
    assert bool(check(left,right)) is (not equal)


def test_missing_property_not_invented_as_const_null_mismatch():
    assert validate_arguments({'properties':{'x':{'const':None}}},{})==[]
    assert validate_arguments({'required':['x'],'properties':{'x':{'const':None}}},{})==["missing required argument 'x'"]


def test_const_and_enum_type_bounds_are_independent():
    schema={'properties':{'x':{'const':1,'enum':[2],'type':'integer','minimum':4}}}
    problems=validate_arguments(schema,{'x':3.5})
    assert len(problems)==4
    assert any('const' in p for p in problems)
    assert any('not one of' in p for p in problems)


def test_absent_const_unchanged_and_no_mutation():
    schema={'properties':{'x':{'const':{'a':[1,True]}}}}
    args={'x':{'a':[1.,True]}};before=copy.deepcopy((schema,args))
    assert validate_arguments(schema,args)==[]
    assert (schema,args)==before
    assert validate_arguments({'properties':{'x':{}}},{'x':None})==[]


def capture(value,const,rejected=True):
    return '\n'.join(map(json.dumps,[
        {'id':1,'method':'tools/list'},
        {'id':1,'result':{'tools':[{'name':'x','inputSchema':{'properties':{'x':{'const':const}}}}]}},
        {'id':2,'method':'tools/call','params':{'name':'x','arguments':{'x':value}}},
        {'id':2,'error':{'code':-32602}} if rejected else {'id':2,'result':{'content':[]}},
    ]))

@pytest.mark.parametrize('rejected',[True,False])
def test_only_observed_rejected_call_is_explained(rejected):
    fs=diagnose(parse_text(capture('actual','expected',rejected)))
    findings=[f for f in fs if f.code=='TOOL_CALL_ARG_MISMATCH']
    assert bool(findings) is rejected
    if rejected:assert 'differs from const (values omitted)' in findings[0].why

@pytest.mark.parametrize('mode',['text','json'])
def test_cli_new_explanation_omits_captured_const_value(tmp_path,capsys,mode):
    from mcptriage.cli import main
    marker='SYNTHETIC_CONST_VALUE'
    p=tmp_path/'log.jsonl';p.write_text(capture('wrong',marker))
    assert main(['diagnose',str(p),'--format',mode])==1
    out=capsys.readouterr()
    assert not out.err
    assert 'differs from const (values omitted)' in out.out
    fs=diagnose(parse_text(p.read_text()))
    assert marker not in next(f.why for f in fs if f.code=='TOOL_CALL_ARG_MISMATCH')
    if mode=='json':assert json.loads(out.out)['finding_count']>0
