"""The complete argument object has property-count constraints of its own."""
import copy
import json
import pytest
from mcptriage.rules import validate_arguments,diagnose
from mcptriage.transcript import WireNumber,parse_text

@pytest.mark.parametrize('keyword,bound,size,bad',[
    ('minProperties',1,0,True),('minProperties',2,1,True),('minProperties',2,2,False),
    ('minProperties',2,3,False),('minProperties',0,0,False),
    ('maxProperties',0,1,True),('maxProperties',2,3,True),('maxProperties',2,2,False),
    ('maxProperties',2,1,False),('maxProperties',0,0,False),
])
def test_root_object_counts_all_member_names(keyword,bound,size,bad):
    args={str(i):None for i in range(size)}
    problems=validate_arguments({keyword:bound},args)
    assert bool(problems) is bad
    if bad:assert problems==[f'arguments object violates {keyword} (content and bound omitted)']

@pytest.mark.parametrize('keyword',['minProperties','maxProperties'])
@pytest.mark.parametrize('bound',[None,True,False,'1',[],{},-1,1.5,float('inf'),float('nan')])
def test_malformed_root_bound_not_used_as_evidence(keyword,bound):
    assert validate_arguments({keyword:bound},{'a':1})==[]

@pytest.mark.parametrize('bound',[2,2.,WireNumber('2.0'),WireNumber('2e0')])
def test_nonnegative_integral_numeric_bounds_work(bound):
    assert validate_arguments({'minProperties':bound},{'a':1})
    assert validate_arguments({'maxProperties':bound},{'a':1,'b':2,'c':3})

@pytest.mark.parametrize('bound',[10**200,WireNumber('1e400')])
def test_large_exact_bounds_do_not_render_or_round(bound):
    assert validate_arguments({'minProperties':bound},{})==['arguments object violates minProperties (content and bound omitted)']
    assert validate_arguments({'maxProperties':bound},{'a':None})==[]


def test_root_and_property_constraints_are_independent_without_mutation():
    schema={'minProperties':3,'properties':{'x':{'type':'object','maxProperties':0}}}
    args={'x':{'child':1}};before=copy.deepcopy((schema,args))
    problems=validate_arguments(schema,args)
    assert len(problems)==2
    assert problems[0].startswith('arguments object')
    assert problems[1].startswith("argument 'x'")
    assert (schema,args)==before


def test_root_counts_unknown_names_and_falsey_values_not_required_members():
    assert validate_arguments({'minProperties':2,'properties':{'known':{}}},{'unknown':False,'other':None})==[]
    assert len(validate_arguments({'minProperties':2,'required':['known']},{'unknown':None}))==2

@pytest.mark.parametrize('schema,args',[(None,{}),({},[]),({'minProperties':2},None),({'minProperties':2},['a'])])
def test_non_object_inputs_keep_no_opinion(schema,args):
    assert validate_arguments(schema,args)==[]


def capture(rejected=True,earlier=True):
    schema={'maxProperties':1}
    listing=[{'id':1,'method':'tools/list'},{'id':1,'result':{'tools':[{'name':'x','inputSchema':schema}]}}]
    call=[{'id':2,'method':'tools/call','params':{'name':'x','arguments':{'a':'SYNTHETIC_ROOT_VALUE','b':False}}},
          {'id':2,'error':{'code':-32602}} if rejected else {'id':2,'result':{'content':[]}}]
    return '\n'.join(map(json.dumps,listing+call if earlier else call+listing))

@pytest.mark.parametrize('rejected,earlier',[(True,True),(True,False),(False,True)])
def test_explanation_requires_observed_rejection_and_prior_schema(rejected,earlier):
    fs=diagnose(parse_text(capture(rejected,earlier)))
    assert any('arguments object violates maxProperties' in f.why for f in fs)==(rejected and earlier)

@pytest.mark.parametrize('mode',['text','json'])
def test_cli_root_explanation_without_content_or_bound_echo(tmp_path,capsys,mode):
    from mcptriage.cli import main
    p=tmp_path/'capture.jsonl';p.write_text(capture())
    assert main(['diagnose',str(p),'--format',mode])==1
    out=capsys.readouterr();assert not out.err
    assert 'arguments object violates maxProperties' in out.out
    finding=next(f for f in diagnose(parse_text(p.read_text())) if f.code=='TOOL_CALL_ARG_MISMATCH')
    assert 'SYNTHETIC_ROOT_VALUE' not in finding.why
    if mode=='json':assert json.loads(out.out)['finding_count']>0
