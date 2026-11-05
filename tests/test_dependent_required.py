"""Dependent presence is not truthiness, recursion or a partial malformed map."""
import copy
import itertools
import json
import pytest
from mcptriage.rules import validate_arguments,diagnose
from mcptriage.transcript import parse_text

@pytest.mark.parametrize('value',[None,False,0,'',[],{},'SYNTHETIC_ARGUMENT_VALUE'])
@pytest.mark.parametrize('trigger',['card',''])
def test_present_even_falsey_trigger_explains_missing_dependency(trigger,value):
    problems=validate_arguments({'dependentRequired':{trigger:['billing']}},{trigger:value})
    assert len(problems)==1
    assert 'dependentRequired' in problems[0]
    assert 'SYNTHETIC_ARGUMENT_VALUE' not in problems[0]

@pytest.mark.parametrize('args',[{}, {'billing':None},{'card':False,'billing':None}])
def test_inactive_or_satisfied_dependency_has_no_opinion(args):
    assert validate_arguments({'dependentRequired':{'card':['billing']}},args)==[]

@pytest.mark.parametrize('deps',[None,True,False,0,'card',[],['card'],{'card':None},{'card':True},
    {'card':'billing'},{'card':[None]},{'card':[{}]},{'card':[1]},{'card':['billing','billing']},
    {'card':['billing'],'broken':{}},{1:['billing']}])
def test_whole_malformed_keyword_ignored_but_independent_required_retained(deps):
    schema={'dependentRequired':deps,'required':['other']}
    assert validate_arguments(schema,{'card':1})==["missing required argument 'other'"]

@pytest.mark.parametrize('deps',[{}, {'card':[]}, {'card':['card']}, {'absent':['billing']}])
def test_empty_self_or_inactive_dependencies_unchanged(deps):
    assert validate_arguments({'dependentRequired':deps},{'card':1})==[]


def test_dependencies_are_directional_not_recursive_inference():
    schema={'dependentRequired':{'a':['b'],'b':['c']}}
    assert len(validate_arguments(schema,{'a':None}))==1
    assert len(validate_arguments(schema,{'a':None,'b':None}))==1
    assert validate_arguments(schema,{'a':None,'b':None,'c':None})==[]
    assert validate_arguments(schema,{'c':None})==[]


def test_nested_and_legacy_dependencies_not_claimed_supported():
    assert validate_arguments({'properties':{'x':{'dependentRequired':{'a':['b']}}}}, {'x':{'a':1}})==[]
    assert validate_arguments({'dependencies':{'a':['b']}},{'a':1})==[]
    assert validate_arguments({'dependentSchemas':{'a':{'required':['b']}}},{'a':1})==[]


def test_schema_and_args_not_mutated_and_independent_type_checks_preserved():
    schema={'dependentRequired':{'a':['b','c']},'properties':{'a':{'type':'string'}}}
    args={'a':False};before=copy.deepcopy((schema,args))
    assert len(validate_arguments(schema,args))==3
    assert (schema,args)==before


def test_exhaustive_three_name_presence_oracle():
    names=['a','b','c']
    subsets=[list(c) for k in range(4) for c in itertools.combinations(names,k)]
    for required in itertools.product(subsets,repeat=3):
        deps=dict(zip(names,required))
        for present in subsets:
            args=dict.fromkeys(present,None)
            expected=sum(len(set(deps[key])-set(present)) for key in present)
            assert len(validate_arguments({'dependentRequired':deps},args))==expected


def capture(rejected=True,earlier=True):
    schema={'dependentRequired':{'card':['billing']}}
    listing=[{'id':1,'method':'tools/list'},{'id':1,'result':{'tools':[{'name':'x','inputSchema':schema}]}}]
    call=[{'id':2,'method':'tools/call','params':{'name':'x','arguments':{'card':'SYNTHETIC_ARGUMENT_VALUE'}}},
          {'id':2,'error':{'code':-32602}} if rejected else {'id':2,'result':{'content':[]}}]
    return '\n'.join(map(json.dumps,listing+call if earlier else call+listing))

@pytest.mark.parametrize('rejected,earlier',[(True,True),(True,False),(False,True)])
def test_only_observed_rejected_call_with_earlier_schema_gets_explanation(rejected,earlier):
    fs=diagnose(parse_text(capture(rejected,earlier)))
    assert any('via dependentRequired' in f.why for f in fs)==(rejected and earlier)

@pytest.mark.parametrize('mode',['text','json'])
def test_cli_explanation_omits_argument_values_not_all_raw_capture(tmp_path,capsys,mode):
    from mcptriage.cli import main
    p=tmp_path/'capture.jsonl';p.write_text(capture())
    assert main(['diagnose',str(p),'--format',mode])==1
    output=capsys.readouterr();assert not output.err
    assert 'via dependentRequired' in output.out
    finding=next(f for f in diagnose(parse_text(p.read_text())) if f.code=='TOOL_CALL_ARG_MISMATCH')
    assert 'SYNTHETIC_ARGUMENT_VALUE' not in finding.why
    if mode=='json':assert json.loads(output.out)['finding_count']>0
