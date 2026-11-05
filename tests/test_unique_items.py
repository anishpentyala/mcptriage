"""Bounded duplicate-array evidence uses JSON equality, not Python aliases."""
import copy
import json
import pytest
from mcptriage.rules import diagnose,validate_arguments
from mcptriage.transcript import parse_text,WireNumber


def check(value,flag=True):
    return validate_arguments({'properties':{'x':{'uniqueItems':flag}}},{'x':value})

@pytest.mark.parametrize('value',[
    [1,1],[1,1.0],[True,True],[False,False],[None,None],['x','x'],
    [[],[]],[{},{}],[[1],[1.0]],[{'a':1},{'a':1.0}],
    [{'a':1,'b':2},{'b':2,'a':1}],
    [[True,{'x':False}],[True,{'x':False}]],
])
def test_duplicate_json_values_are_explained(value):
    assert check(value)==["argument 'x' violates uniqueItems (duplicate values omitted)"]

@pytest.mark.parametrize('value',[
    [],[1],[True,1],[False,0],[None,'null'],[1,'1'],[[],{}],
    [[True],[1]],[{'x':True},{'x':1}],[{'a':1},{'b':1}],
    [[1,2],[2,1]],[{},[],'',None,False,0],
])
def test_json_distinct_values_do_not_invent_duplicate(value):
    assert check(value)==[]

@pytest.mark.parametrize('flag',[False,None,0,1,'true',[],{},[True]])
def test_only_literal_true_enables_constraint(flag):
    assert check([1,1],flag)==[]

@pytest.mark.parametrize('value',[None,True,1,1.5,'aa',{'x':1,'y':1}])
def test_nonarrays_supply_no_uniqueness_evidence(value):
    assert check(value)==[]

@pytest.mark.parametrize('a,b,duplicate',[
    ('9007199254740992.0','9007199254740993.0',False),
    ('9007199254740993.0','9007199254740993',True),
    ('1e400','10e399',True),('1e-400','0',False),
    ('0.1','0.10000000000000000001',False),('-0.0','0.0',True),
])
def test_wire_numeric_identity_is_exact(a,b,duplicate):
    assert bool(check([WireNumber(a),WireNumber(b)])) is duplicate


def test_budget_exhaustion_is_not_false_evidence_and_other_checks_continue():
    schema={'required':['y'],'properties':{'x':{'uniqueItems':True,'maxItems':1}}}
    values=list(range(100))+[99]
    problems=validate_arguments(schema,{'x':values})
    assert len(problems)==2
    assert any('required' in p for p in problems) and any('maxItems' in p for p in problems)
    assert not any('uniqueItems' in p for p in problems)


def test_early_duplicate_still_has_evidence_with_long_tail():
    assert check([0,0]+list(range(10000)))


def test_structural_deep_equality_and_no_mutation():
    a,b=1,1.0
    for i in range(1500):a,b=[a],[b]
    assert check([a,b])
    value=[{'x':[1,True,None]},{'x':[2,False,None]}]
    before=copy.deepcopy(value)
    assert check(value)==[]
    assert value==before


def capture(value,rejected=True):
    return '\n'.join(map(json.dumps,[
        {'id':1,'method':'tools/list'},
        {'id':1,'result':{'tools':[{'name':'x','inputSchema':{'properties':{'x':{'uniqueItems':True}}}}]}},
        {'id':2,'method':'tools/call','params':{'name':'x','arguments':{'x':value}}},
        {'id':2,'error':{'code':-32602}} if rejected else {'id':2,'result':{'content':[]}},
    ]))

@pytest.mark.parametrize('rejected',[True,False])
def test_only_observed_rejected_call_is_explained(rejected):
    fs=diagnose(parse_text(capture([1,1],rejected)))
    findings=[f for f in fs if f.code=='TOOL_CALL_ARG_MISMATCH']
    assert bool(findings) is rejected
    if rejected:assert 'uniqueItems' in findings[0].why

@pytest.mark.parametrize('mode',['text','json'])
def test_cli_new_explanation_omits_duplicate_values(tmp_path,capsys,mode):
    from mcptriage.cli import main
    marker='SYNTHETIC_DUPLICATE_VALUE'
    p=tmp_path/'log.jsonl';p.write_text(capture([marker,marker]))
    assert main(['diagnose',str(p),'--format',mode])==1
    out=capsys.readouterr()
    assert not out.err
    assert 'violates uniqueItems (duplicate values omitted)' in out.out
    fs=diagnose(parse_text(p.read_text()))
    assert marker not in next(f.why for f in fs if f.code=='TOOL_CALL_ARG_MISMATCH')
    if mode=='json':assert json.loads(out.out)['finding_count']>0


def test_pair_attempt_budget_is_deterministic(monkeypatch):
    import mcptriage.rules as rules
    original=rules._json_equal
    calls=[]
    def measured(a,b):
        calls.append(1)
        return original(a,b)
    monkeypatch.setattr(rules,'_json_equal',measured)
    assert check(list(range(1000)))==[]
    assert len(calls)==4096
