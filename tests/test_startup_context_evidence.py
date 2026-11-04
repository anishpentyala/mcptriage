"""A method failure does not prove an earlier successful initialize."""
import json
import pytest
from mcptriage.rules import diagnose
from mcptriage.transcript import parse_text


def inspect(rows):
    return diagnose(parse_text('\n'.join(json.dumps(r) for r in rows)))


@pytest.mark.parametrize('error',[{'code':401,'message':'unauthorized'},{'code':-32603,'message':'failed'}])
@pytest.mark.parametrize('opening',[
    [],
    [{'id':0,'method':'initialize'},{'id':0,'error':{'code':-32603}}],
    [{'id':0,'method':'initialize'},{'id':0,'result':None}],
    [{'id':0,'method':'initialize'},{'id':0,'result':{'capabilities':{}},'error':{}}],
])
def test_failure_does_not_invent_successful_startup(error,opening):
    rows=opening+[{'id':1,'method':'tools/list'},{'id':1,'error':error}]
    f=next(f for f in inspect(rows) if f.code in ('AUTH_ON_LIST','TOOLS_LIST_ERROR'))
    rendered=f.title+' '+f.why
    assert 'initialize succeeded' not in rendered, 'unobserved initialize success must not be asserted'
    assert 'after a successful initialize' not in rendered
    assert 'not established' in rendered


def test_success_after_failed_list_cannot_explain_earlier_failure():
    rows=[{'id':1,'method':'tools/list'},{'id':1,'error':{'code':401}},
          {'id':0,'method':'initialize'},{'id':0,'result':{}}]
    f=next(f for f in inspect(rows) if f.code=='AUTH_ON_LIST')
    assert 'initialize succeeded' not in f.title
    assert 'not established' in f.why


@pytest.mark.parametrize('error',[{'code':401},{'code':-32603}])
def test_actual_prior_success_is_cited(error):
    rows=[{'id':0,'method':'initialize'},{'id':0,'result':{'capabilities':{'tools':{}}}},
          {'id':1,'method':'tools/list'},{'id':1,'error':error}]
    f=next(f for f in inspect(rows) if f.code in ('AUTH_ON_LIST','TOOLS_LIST_ERROR'))
    assert 'line 2:' in f.evidence
    assert 'earlier initialize returned an object result' in f.why


def test_pending_initialize_cannot_count_as_success():
    rows=[{'id':0,'method':'initialize'},{'id':1,'method':'tools/list'},{'id':1,'error':{'code':401}}]
    f=next(f for f in inspect(rows) if f.code=='AUTH_ON_LIST')
    assert 'not established' in f.why


@pytest.mark.parametrize('latest',[
    [{'id':2,'method':'initialize'}],
    [{'id':2,'method':'initialize'},{'id':2,'error':{'code':-32603}}],
    [{'id':2,'method':'initialize'},{'id':2,'result':None}],
])
def test_latest_initialize_attempt_prevents_stale_success_claim(latest):
    rows=[{'id':0,'method':'initialize'},{'id':0,'result':{}}]+latest+[
        {'id':3,'method':'tools/list'},{'id':3,'error':{'code':401}}]
    f=next(f for f in inspect(rows) if f.code=='AUTH_ON_LIST')
    assert 'not established' in f.why
    assert 'earlier initialize:' not in f.evidence


def test_initialize_reply_after_list_request_does_not_establish_prior_success():
    rows=[{'id':0,'method':'initialize'},{'id':1,'method':'tools/list'},
          {'id':0,'result':{}},{'id':1,'error':{'code':401}}]
    assert 'not established' in next(f for f in inspect(rows) if f.code=='AUTH_ON_LIST').why


def test_ambiguous_initialize_id_does_not_establish_success():
    rows=[{'id':0,'method':'initialize'},{'id':0,'method':'initialize'},
          {'id':0,'result':{}},{'id':1,'method':'tools/list'},{'id':1,'error':{'code':401}}]
    assert 'not established' in next(f for f in inspect(rows) if f.code=='AUTH_ON_LIST').why


@pytest.mark.parametrize('identifier',[0,'0',1.0])
def test_supported_prior_identifier_types_preserve_evidence(identifier):
    rows=[{'id':identifier,'method':'initialize'},{'id':identifier,'result':{}},
          {'id':'list','method':'tools/list'},{'id':'list','error':{'code':401}}]
    f=next(f for f in inspect(rows) if f.code=='AUTH_ON_LIST')
    assert 'earlier initialize returned an object result' in f.why


@pytest.mark.parametrize('mode',['text','json'])
def test_cli_bare_list_failure_reports_missing_startup_evidence(tmp_path,capsys,mode):
    from mcptriage.cli import main
    path=tmp_path/'capture.jsonl'
    path.write_text('{"id":1,"method":"tools/list"}\n{"id":1,"error":{"code":401}}')
    assert main(['diagnose',str(path),'--format',mode])==1
    text=capsys.readouterr().out
    assert 'not established' in text
    assert 'initialize succeeded' not in text


def test_prior_initialize_evidence_keeps_credential_masking():
    rows=[{'id':0,'method':'initialize'},{'id':0,'result':{'token':'synthetic-marker'}},
          {'id':1,'method':'tools/list'},{'id':1,'error':{'code':401}}]
    f=next(f for f in inspect(rows) if f.code=='AUTH_ON_LIST')
    assert 'synthetic-marker' not in f.evidence and '***' in f.evidence
