"""Exact supported multipleOf explanations without giant exponent expansion."""
import json
from decimal import localcontext
from fractions import Fraction
import pytest
from mcptriage.rules import validate_arguments,diagnose
from mcptriage.transcript import WireNumber,parse_text


def check(value,divisor):
    return validate_arguments({'properties':{'x':{'multipleOf':divisor}}},{'x':value})

@pytest.mark.parametrize('value,divisor,multiple',[
    ('0','0.1',True),('0.3','0.1',True),('0.31','0.1',False),
    ('-0.3','0.1',True),('-0.31','0.1',False),
    ('1.2','0.03',True),('1.2','0.07',False),
    ('9007199254740993.0','2',False),('9007199254740994.0','2',True),
    ('1e400','1e399',True),('1e-400','1e-399',False),
    ('3e-400','1e-400',True),('3e400','2e399',True),
    ('1e100000000','3',False),('1e100000000','2',True),
    ('1','1e100000000',False),('1e-100000000','1e-100000000',True),
])
def test_exact_wire_multiples(value,divisor,multiple):
    with localcontext() as ctx:
        ctx.prec=2
        assert bool(check(WireNumber(value),WireNumber(divisor))) is (not multiple)

@pytest.mark.parametrize('divisor',[True,False,None,'0.1',[],{},0,-1,.0,float('inf'),float('nan')])
def test_unusable_divisors_supply_no_violation(divisor):
    assert check(.3,divisor)==[]

@pytest.mark.parametrize('value',[True,False,None,'0.3',[],{},float('inf'),float('nan')])
def test_nonnumeric_instances_supply_no_violation(value):
    assert check(value,.1)==[]

@pytest.mark.parametrize('value,divisor',[(.3,.1),(1.2,.03),(1.,.25),(0.,.1),(3,2),(4,2)])
def test_direct_python_inputs_use_represented_binary_value(value,divisor):
    ratio=Fraction(value)/Fraction(divisor)
    assert bool(check(value,divisor)) is (ratio.denominator!=1)


def capture(value,divisor,rejected=True):
    return '\n'.join([
        '{"id":1,"method":"tools/list"}',
        '{"id":1,"result":{"tools":[{"name":"x","inputSchema":{"properties":{"x":{"multipleOf":'+divisor+'}}}}]}}',
        '{"id":2,"method":"tools/call","params":{"name":"x","arguments":{"x":'+value+'}}}',
        '{"id":2,"error":{"code":-32602}}' if rejected else '{"id":2,"result":{"content":[]}}',
    ])

@pytest.mark.parametrize('rejected',[True,False])
def test_only_observed_rejection_explained(rejected):
    fs=diagnose(parse_text(capture('0.31','0.1',rejected)))
    findings=[f for f in fs if f.code=='TOOL_CALL_ARG_MISMATCH']
    assert bool(findings) is rejected
    if rejected:assert 'violates multipleOf (values omitted)' in findings[0].why

@pytest.mark.parametrize('mode',['text','json'])
def test_cli_exact_decimal_explanation(tmp_path,capsys,mode):
    from mcptriage.cli import main
    p=tmp_path/'log.jsonl';p.write_text(capture('9007199254740993.0','2'))
    assert main(['diagnose',str(p),'--format',mode])==1
    out=capsys.readouterr()
    assert not out.err
    assert 'violates multipleOf (values omitted)' in out.out
    if mode=='json':assert json.loads(out.out)['finding_count']>0


def test_coefficient_work_limit_is_not_false_violation():
    enormous=WireNumber('1.'+'1'*4400)
    assert check(enormous,2)==[]
    assert check(2,enormous)==[]


def test_existing_constraints_still_run_and_absent_keyword_unchanged():
    schema={'required':['y'],'properties':{'x':{'type':'integer','minimum':4,'multipleOf':2}}}
    assert len(validate_arguments(schema,{'x':3.5}))==4
    assert validate_arguments({'properties':{'x':{'type':'number'}}},{'x':.31})==[]
