"""Malformed captured fields must not crash or become trusted semantics."""
import json
import pytest
from mcptriage.transcript import parse_text
from mcptriage.rules import diagnose


def inspect(*rows):
    return diagnose(parse_text('\n'.join(json.dumps(r) for r in rows)))


@pytest.mark.parametrize('code',[[],{},True,False,None,'-32601',-32601.5])
def test_malformed_list_error_code_is_diagnosed_without_guessed_detail(code):
    fs=inspect({'id':1,'method':'tools/list'}, {'id':1,'error':{'code':code,'message':'failure'}})
    assert any(f.code=='UNUSABLE_ERROR_CODE' for f in fs)
    assert not any(f.code=='TOOLS_LIST_ERROR' and 'no tools/list handler' in f.title for f in fs)


@pytest.mark.parametrize('name',[[],{},True,False,None,1,1.5])
def test_malformed_call_name_does_not_lookup_schema_or_crash(name):
    fs=inspect({'id':1,'method':'tools/call','params':{'name':name,'arguments':{}}},
               {'id':1,'error':{'code':-32602}})
    assert any(f.code=='UNUSABLE_TOOL_NAME' for f in fs)
    assert not any(f.code=='TOOL_CALL_ARG_MISMATCH' for f in fs)


@pytest.mark.parametrize('code',[-32601,-32602,-32603,-32022])
def test_valid_integer_list_error_keeps_detail(code):
    fs=inspect({'id':1,'method':'tools/list'}, {'id':1,'error':{'code':code}})
    assert any(f.code=='TOOLS_LIST_ERROR' for f in fs)
    assert not any(f.code=='UNUSABLE_ERROR_CODE' for f in fs)


@pytest.mark.parametrize('code',[[],{},True,None,'-32602',-32602.5])
def test_noninteger_call_error_cannot_claim_invalid_params(code):
    fs=inspect({'id':1,'method':'tools/call','params':{'name':'x','arguments':{}}},
               {'id':1,'error':{'code':code}})
    assert any(f.code=='UNUSABLE_ERROR_CODE' for f in fs)
    assert not any(f.code=='TOOL_CALL_ARG_MISMATCH' for f in fs)


def test_string_tool_name_keeps_call_diagnosis():
    fs=inspect({'id':1,'method':'tools/call','params':{'name':'x','arguments':{}}},
               {'id':1,'error':{'code':-32602}})
    assert any(f.code=='TOOL_CALL_ARG_MISMATCH' for f in fs)
    assert not any(f.code=='UNUSABLE_TOOL_NAME' for f in fs)


def test_missing_error_code_diagnosed():
    assert any(f.code=='UNUSABLE_ERROR_CODE' for f in inspect({'id':1,'method':'tools/list'},
                    {'id':1,'error':{'message':'no code'}}))


def test_missing_tool_name_diagnosed():
    assert any(f.code=='UNUSABLE_TOOL_NAME' for f in inspect({'id':1,'method':'tools/call','params':{}},
                    {'id':1,'error':{'code':-32602}}))


def test_integral_number_error_code_retains_mathematical_integer_semantics():
    fs=inspect({'id':1,'method':'tools/call','params':{'name':'x','arguments':{}}},
               {'id':1,'error':{'code':-32602.0}})
    assert any(f.code=='TOOL_CALL_ARG_MISMATCH' for f in fs)
    assert not any(f.code=='UNUSABLE_ERROR_CODE' for f in fs)


@pytest.mark.parametrize('response',[{'error':{'code':-32602}}, {'result':{'isError':True}}, None])
def test_absent_call_params_still_diagnoses_missing_name(response):
    rows=[{'id':1,'method':'tools/call'}]
    if response is not None:
        rows.append(dict(id=1,**response))
    fs=inspect(*rows)
    assert any(f.code=='UNUSABLE_TOOL_NAME' for f in fs)
    assert not any(f.code=='UNUSABLE_PARAMS' for f in fs)


@pytest.mark.parametrize('params',[None,[],True,1,'bad'])
def test_explicit_nonobject_params_keeps_only_its_own_shape_diagnosis(params):
    fs=inspect({'id':1,'method':'tools/call','params':params}, {'id':1,'error':{'code':-32602}})
    assert any(f.code=='UNUSABLE_PARAMS' for f in fs)
    assert not any(f.code=='UNUSABLE_TOOL_NAME' for f in fs)
