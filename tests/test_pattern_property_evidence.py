"""Unsupported pattern maps cannot prove an argument is additional."""
import json
import pytest
from mcptriage.rules import validate_arguments, diagnose
from mcptriage.transcript import parse_text


@pytest.mark.parametrize('patterns', [
    {'^S_':{'type':'string'}}, {'p':True}, {'.*':True},
    {'[':True}, {'(?<=prefix)x':True}, {'^(a+)+$':True},
    [], None, True, '.*',
])
def test_unknown_pattern_coverage_never_proves_unexpected_argument(patterns):
    schema = {'patternProperties':patterns, 'additionalProperties':False}
    assert validate_arguments(schema, {'S_name':'value'}) == []


@pytest.mark.parametrize('properties', [None, [], True, 'not a map'])
def test_malformed_properties_are_not_evidence_of_absent_property(properties):
    assert validate_arguments({'properties':properties,'additionalProperties':False}, {'x':1}) == []


@pytest.mark.parametrize('patterns', [None, {}, 'absent'])
def test_absent_or_empty_pattern_map_retains_supported_exclusion(patterns):
    schema = {'properties':{'known':True},'additionalProperties':False}
    if patterns != 'absent':
        schema['patternProperties'] = patterns
    problems = validate_arguments(schema, {'known':1,'extra':2})
    assert bool(problems) is (patterns is not None)


def test_independent_property_and_required_evidence_survive_pattern_uncertainty():
    schema = {'patternProperties':{'.*':True}, 'additionalProperties':False,
              'required':['needed'], 'properties':{'x':{'type':'string'},'never':False}}
    problems = validate_arguments(schema, {'x':42,'never':1,'extra':True})
    assert len(problems) == 3
    assert any('missing required' in p for p in problems)
    assert any('should be string' in p for p in problems)
    assert any('not allowed' in p for p in problems)
    assert not any('unexpected' in p for p in problems)


@pytest.mark.parametrize('mode', ['direct','text','json'])
def test_real_call_rejection_preserved_without_invented_pattern_explanation(tmp_path,capsys,mode):
    from mcptriage.cli import main
    schema = {'type':'object','patternProperties':{'^S_':{'type':'string'}},'additionalProperties':False}
    rows = [{'id':1,'method':'tools/list'},
            {'id':1,'result':{'tools':[{'name':'lookup','inputSchema':schema}]}},
            {'id':2,'method':'tools/call','params':{'name':'lookup','arguments':{'S_name':'value'}}},
            {'id':2,'error':{'code':-32602,'message':'invalid params'}}]
    text = '\n'.join(map(json.dumps, rows))
    if mode == 'direct':
        f = next(f for f in diagnose(parse_text(text)) if f.code=='TOOL_CALL_ARG_MISMATCH')
        assert 'Arguments violate' not in f.why
        assert 'server rejected' in f.why
    else:
        path = tmp_path/'capture.jsonl';path.write_text(text)
        assert main(['diagnose',str(path),'--format',mode]) == 1
        output = capsys.readouterr().out
        assert 'TOOL_CALL_ARG_MISMATCH' in output
        assert 'unexpected argument' not in output


@pytest.mark.parametrize('patterns', [{'.*':False}, {'^other$':True}])
def test_unsupported_patterns_are_not_evaluated_even_when_violation_seems_likely(patterns):
    # This is deliberately conservative: do not claim a full regex validator.
    assert validate_arguments({'patternProperties':patterns,'additionalProperties':False}, {'x':1}) == []


def test_pattern_source_is_not_executed(monkeypatch):
    import re
    def forbidden(*args, **kwargs):
        raise RuntimeError('captured regex source must not be executed')
    # Restore the shared module before pytest formats assertion failures.
    # Otherwise the negative control can break pytest's own regex machinery.
    with monkeypatch.context() as scoped:
        scoped.setattr(re, 'search', forbidden)
        scoped.setattr(re, 'compile', forbidden)
        problems = validate_arguments({'patternProperties':{'^(a+)+$':True},
                                       'additionalProperties':False}, {'a'*10000+'!':1})
    assert problems == []
