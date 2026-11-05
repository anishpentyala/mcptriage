"""Top-level property size checks explain observed invalid-params rejection."""
import copy
import json
import pytest
from mcptriage.rules import validate_arguments,diagnose
from mcptriage.transcript import WireNumber,parse_text

KINDS=[('minLength','maxLength','ab'),('minItems','maxItems',[0,1]),
       ('minProperties','maxProperties',{'a':0,'b':1})]

def check(keyword,bound,value):
    return validate_arguments({'properties':{'x':{keyword:bound}}},{'x':value})

@pytest.mark.parametrize('minimum,maximum,value',KINDS)
@pytest.mark.parametrize('bound',[0,1,2,3])
def test_supported_boundaries(minimum,maximum,value,bound):
    assert bool(check(minimum,bound,value)) is (len(value)<bound)
    assert bool(check(maximum,bound,value)) is (len(value)>bound)

@pytest.mark.parametrize('minimum,maximum,value',KINDS)
@pytest.mark.parametrize('bound',[True,False,None,'2',[],{},-1,.5,float('inf'),float('nan')])
def test_malformed_bounds_supply_no_evidence(minimum,maximum,value,bound):
    assert check(minimum,bound,value)==[]
    assert check(maximum,bound,value)==[]

@pytest.mark.parametrize('minimum,maximum,value',KINDS)
@pytest.mark.parametrize('bound',[2.,WireNumber('2.0'),WireNumber('2e0')])
def test_mathematical_integer_bound_values_are_valid(minimum,maximum,value,bound):
    assert check(minimum,bound,value)==[]
    assert check(maximum,bound,value)==[]

@pytest.mark.parametrize('keyword',['minLength','maxLength','minItems','maxItems','minProperties','maxProperties'])
@pytest.mark.parametrize('value',[None,True,42,1.5])
def test_non_container_instance_is_not_size_evidence(keyword,value):
    assert check(keyword,2,value)==[]

@pytest.mark.parametrize('value',['\U0001f680','e\u0301','\U0001f1fa\U0001f1f8','\u2028\u2029'])
def test_unicode_length_counts_codepoints_not_bytes_or_graphemes(value):
    assert check('maxLength',len(value),value)==[]
    assert check('minLength',len(value)+1,value)
    assert check('maxLength',len(value)-1,value)


def test_wrong_keyword_for_container_kind_stays_outside_scope():
    for keyword,value in [('minItems','x'),('minProperties',[]),('minLength',{}),
                          ('maxItems','xx'),('maxProperties',[1,2]),('maxLength',{'a':1})]:
        assert check(keyword,1,value)==[]


def capture(keyword,bound,value,rejected=True):
    return '\n'.join(map(json.dumps,[
        {'id':1,'method':'tools/list'},
        {'id':1,'result':{'tools':[{'name':'x','inputSchema':{'properties':{'x':{keyword:bound}}}}]}},
        {'id':2,'method':'tools/call','params':{'name':'x','arguments':{'x':value}}},
        {'id':2,'error':{'code':-32602}} if rejected else {'id':2,'result':{'content':[]}},
    ]))

@pytest.mark.parametrize('minimum,maximum,value',KINDS)
@pytest.mark.parametrize('rejected',[True,False])
def test_only_observed_rejection_uses_size_explanation(minimum,maximum,value,rejected):
    fs=diagnose(parse_text(capture(maximum,1,value,rejected)))
    mismatch=[f for f in fs if f.code=='TOOL_CALL_ARG_MISMATCH']
    assert bool(mismatch) is rejected
    if rejected:assert maximum in mismatch[0].why

@pytest.mark.parametrize('mode',['text','json'])
def test_cli_omits_payload_and_bound_from_new_explanation(tmp_path,capsys,mode):
    from mcptriage.cli import main
    marker='SYNTHETIC_CONTENT_MARKER'
    path=tmp_path/'capture.jsonl';path.write_text(capture('maxLength',1,marker))
    assert main(['diagnose',str(path),'--format',mode])==1
    output=capsys.readouterr()
    assert not output.err
    assert 'violates maxLength (content and bound omitted)' in output.out
    # Existing raw evidence is best-effort-redacted and may show content.
    # The new why text must not become a separate content echo.
    fs=diagnose(parse_text(path.read_text()))
    finding=next(f for f in fs if f.code=='TOOL_CALL_ARG_MISMATCH')
    assert marker not in finding.why
    if mode=='json':assert json.loads(output.out)['finding_count']>0


def test_required_enum_and_size_are_independent_without_mutation():
    schema={'required':['missing'],'properties':{'x':{'enum':['allowed'],'maxLength':1}}}
    args={'x':'bad'};before=copy.deepcopy((schema,args))
    problems=validate_arguments(schema,args)
    assert len(problems)==3
    assert (schema,args)==before
    assert any('missing required' in p for p in problems)
    assert any('not one of' in p for p in problems)
    assert any('maxLength' in p for p in problems)


def test_absent_size_keywords_and_nested_contents_unchanged():
    assert validate_arguments({'properties':{'x':{'type':'array'}}},{'x':[]})==[]
    assert check('maxItems',1,[{'very_long':'value'*1000}])==[]
    assert check('maxProperties',1,{'a':[1,2,3]})==[]

@pytest.mark.parametrize('minimum,maximum,value',KINDS)
@pytest.mark.parametrize('bound',[3.,WireNumber('3.0'),WireNumber('3e0')])
def test_integral_float_bounds_can_establish_a_violation(minimum,maximum,value,bound):
    assert check(minimum,bound,value)
    assert check(maximum,bound,value)==[]


def test_extreme_bound_is_compared_without_integer_materialization():
    assert check('minLength',WireNumber('1e100000000'),'x')
    assert check('maxLength',WireNumber('1e100000000'),'x')==[]
    assert check('maxLength',WireNumber('0.0000000000000000001'),'xx')==[]
