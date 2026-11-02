"""An error or malformed initialize result is not evidence of successful startup."""
import json
import pytest
from mcptriage.transcript import parse_text
from mcptriage.rules import diagnose


def inspect(*rows):
    return diagnose(parse_text('\n'.join(json.dumps(r) for r in rows)))


@pytest.mark.parametrize('response',[
    {'error':{'code':-32603}}, {'error':{'code':401,'message':'unauthorized'}},
    {'result':None}, {'result':[]}, {'result':True}, {'result':'bad'},
])
def test_failed_or_nonobject_initialize_not_called_successful(response):
    fs=inspect({'id':1,'method':'initialize'},dict(id=1,**response))
    assert not any(f.code=='MISSING_INITIALIZED' for f in fs)


@pytest.mark.parametrize('later',[
    {'id':2,'method':'initialize'},
    {'id':2,'method':'initialize','params':{}},
])
def test_later_success_not_hidden_by_earlier_error(later):
    fs=inspect({'id':1,'method':'initialize'},{'id':1,'error':{'code':-32603}},
               later,{'id':2,'result':{'capabilities':{'tools':{}}}})
    f=next(f for f in fs if f.code=='MISSING_INITIALIZED')
    assert 'line 4:' in f.evidence


def test_notification_before_success_does_not_complete_later_initialize():
    fs=inspect({'method':'notifications/initialized'}, {'id':1,'method':'initialize'},
               {'id':1,'result':{'capabilities':{'tools':{}}}})
    assert any(f.code=='MISSING_INITIALIZED' for f in fs)


def test_notification_after_success_keeps_clean_result():
    fs=inspect({'id':1,'method':'initialize'}, {'id':1,'result':{'capabilities':{'tools':{}}}},
               {'method':'notifications/initialized'})
    assert not any(f.code=='MISSING_INITIALIZED' for f in fs)


def test_ordinary_success_still_requests_notification():
    assert any(f.code=='MISSING_INITIALIZED' for f in inspect({'id':1,'method':'initialize'},
        {'id':1,'result':{'capabilities':{'tools':{}}}}))
