"""Top-level numeric bounds are exact, opt-in rejection explanations."""
import json
from decimal import localcontext

import pytest

from mcptriage.rules import diagnose, validate_arguments
from mcptriage.transcript import parse_text


CASES = [
    ('minimum', 3, 2, True), ('minimum', 3, 3, False), ('minimum', 3, 4, False),
    ('maximum', 3, 2, False), ('maximum', 3, 3, False), ('maximum', 3, 4, True),
    ('exclusiveMinimum', 3, 2, True), ('exclusiveMinimum', 3, 3, True),
    ('exclusiveMinimum', 3, 4, False),
    ('exclusiveMaximum', 3, 2, False), ('exclusiveMaximum', 3, 3, True),
    ('exclusiveMaximum', 3, 4, True),
]


def check(keyword, bound, value):
    return validate_arguments({'properties': {'x': {keyword: bound}}}, {'x': value})


@pytest.mark.parametrize('keyword,bound,value,violates', CASES)
def test_inclusive_and_exclusive_boundaries(keyword, bound, value, violates):
    problems = check(keyword, bound, value)
    assert bool(problems) is violates
    if violates:
        assert keyword in problems[0] and 'values omitted' in problems[0]


@pytest.mark.parametrize('keyword', ['minimum', 'maximum', 'exclusiveMinimum', 'exclusiveMaximum'])
@pytest.mark.parametrize('value', [True, False, None, '2', [], {}, float('inf'), float('nan')])
def test_non_numeric_or_nonfinite_instance_is_not_bound_evidence(keyword, value):
    assert check(keyword, 3, value) == []


@pytest.mark.parametrize('keyword', ['minimum', 'maximum', 'exclusiveMinimum', 'exclusiveMaximum'])
@pytest.mark.parametrize('bound', [True, False, None, '3', [], {}, float('inf'), float('nan')])
def test_malformed_bound_is_not_coerced(keyword, bound):
    assert check(keyword, bound, 3) == []


def capture(keyword, bound, value, error=True):
    return '\n'.join([
        '{"id":1,"method":"tools/list"}',
        '{"id":1,"result":{"tools":[{"name":"x","inputSchema":{"type":"object",'
        '"properties":{"x":{"' + keyword + '":' + bound + '}}}}]}}',
        '{"id":2,"method":"tools/call","params":{"name":"x","arguments":{"x":' + value + '}}}',
        '{"id":2,"error":{"code":-32602}}' if error else '{"id":2,"result":{"content":[]}}',
    ])


@pytest.mark.parametrize('keyword,bound,value,violates', [
    ('minimum','9007199254740993','9007199254740992.0',True),
    ('maximum','9007199254740992','9007199254740993.0',True),
    ('minimum','0.10000000000000000001','0.1',True),
    ('maximum','-0.10000000000000000001','-0.1',True),
    ('exclusiveMinimum','1e400','10e399',True),
    ('exclusiveMaximum','-1e400','-10e399',True),
    ('minimum','1e-400','0',True),
    ('maximum','-1e-400','0',True),
    ('minimum','1e400','1e401',False),
    ('maximum','-1e400','-1e401',False),
    ('minimum','0','-0.0',False),
    ('exclusiveMaximum','0','-0.0',True),
])
def test_wire_bounds_use_exact_decimal_not_float_or_context(keyword,bound,value,violates):
    with localcontext() as ctx:
        ctx.prec = 2
        fs = diagnose(parse_text(capture(keyword,bound,value)))
    finding = next(f for f in fs if f.code in ('TOOL_CALL_ARG_MISMATCH', 'TOOL_CALL_PROTOCOL_ERROR'))
    assert ('violates numeric' in finding.why) is violates


@pytest.mark.parametrize('error', [True, False])
def test_success_is_not_new_validation_scan(error):
    fs = diagnose(parse_text(capture('minimum','10','1',error)))
    matches = [f for f in fs if f.code in ('TOOL_CALL_ARG_MISMATCH', 'TOOL_CALL_PROTOCOL_ERROR')]
    assert bool(matches) is error
    if error:
        assert 'violates numeric minimum' in matches[0].why


def test_independent_required_type_enum_and_bounds_continue():
    schema = {'required':['y'],'properties':{'x':{'type':'integer','enum':[5],'minimum':4}}}
    problems = validate_arguments(schema, {'x':2.5})
    assert len(problems) == 4
    assert any('missing required' in p for p in problems)
    assert any('should be integer' in p for p in problems)
    assert any('not one of' in p for p in problems)
    assert any('numeric minimum' in p for p in problems)


@pytest.mark.parametrize('mode', ['text','json'])
def test_cli_reports_bounded_values_omitted_explanation(tmp_path,capsys,mode):
    from mcptriage.cli import main
    p = tmp_path/'capture.jsonl'
    p.write_text(capture('maximum','1e100000000','2e100000000'))
    assert main(['diagnose',str(p),'--format',mode]) == 1
    output = capsys.readouterr()
    assert not output.err
    assert 'violates numeric maximum (values omitted)' in output.out
    assert len(output.out) < 4000
    if mode == 'json':
        assert json.loads(output.out)['finding_count'] > 0


def test_no_mutation_and_absent_bound_compatibility():
    schema = {'properties':{'x':{'minimum':1,'maximum':3}}}
    args = {'x':2}
    before = json.dumps([schema,args])
    assert validate_arguments(schema,args) == []
    assert json.dumps([schema,args]) == before
    assert validate_arguments({'properties':{'x':{'type':'number'}}},args) == []
