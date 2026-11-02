"""Authentication evidence scanning must not re-encode accepted nested data."""
import pytest
from mcptriage.rules import diagnose,rule_auth_on_list,rule_tools_list_error
from mcptriage.transcript import parse_text,Session,Message

@pytest.mark.parametrize('depth',[30,992,2000])
@pytest.mark.parametrize('leaf',['failure','unauthorized','unauthenticated',401])
def test_nested_error_data_does_not_need_encoder_recursion(depth,leaf):
    data=leaf
    for _ in range(depth):data=[data]
    request=Message(1,'{"id":1,"method":"tools/list"}',{'id':1,'method':'tools/list'},'request','tools/list',1)
    response=Message(2,'synthetic deeply nested error',{'id':1,'error':{'code':-32603,'message':'failure','data':data}},'response',msg_id=1)
    fs=diagnose(Session([request,response]))
    codes={f.code for f in fs}
    assert ('AUTH_ON_LIST' in codes)==(leaf!='failure')
    assert ('TOOLS_LIST_ERROR' in codes)==(leaf=='failure')

@pytest.mark.parametrize('depth',[30,992,2000])
@pytest.mark.parametrize('leaf',['"failure"','"unauthorized"'])
def test_real_decoder_acceptance_or_preserved_unparsed_both_safe(depth,leaf):
    nested='['*depth+leaf+']'*depth
    text='{"id":1,"method":"tools/list"}\n{"id":1,"error":{"code":-32603,"message":"failure","data":'+nested+'}}'
    s=parse_text(text)
    fs=diagnose(s)
    if len(s.parsed)==2:
        codes={f.code for f in fs}
        assert ('AUTH_ON_LIST' in codes)==(leaf=='"unauthorized"')
        assert ('TOOLS_LIST_ERROR' in codes)==(leaf=='"failure"')
    else:
        assert s.unparsed

@pytest.mark.parametrize('data',[{'reason':'unauthorized'},{'status':401},['unauthenticated'],{'nested':{'unauthorized':False}}])
def test_shallow_data_auth_markers_kept(data):
    from mcptriage.rules import _looks_auth
    assert _looks_auth({'code':-32603,'data':data})

@pytest.mark.parametrize('data',[{'status':1401},{'trace':'x401x'},False,None,[],{'message':'backend failure'}])
def test_unrelated_data_not_auth(data):
    from mcptriage.rules import _looks_auth
    assert not _looks_auth({'code':-32603,'data':data})

@pytest.mark.parametrize('marker',['failure','unauthorized'])
def test_diagnosis_does_not_require_error_reserialization(monkeypatch,marker):
    import json
    s=parse_text('{"id":1,"method":"tools/list"}\n{"id":1,"error":{"code":-32603,"message":"'+marker+'"}}')
    def rejected_encoder(*args,**kwargs):
        raise RecursionError('synthetic accepted-decoder/rejected-encoder boundary')
    monkeypatch.setattr(json,'dumps',rejected_encoder)
    codes={f.code for f in diagnose(s)}
    assert ('AUTH_ON_LIST' in codes)==(marker=='unauthorized')
    assert ('TOOLS_LIST_ERROR' in codes)==(marker=='failure')
