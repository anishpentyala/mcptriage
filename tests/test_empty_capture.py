"""An unreadable or empty capture cannot be described as a healthy session."""
import json
import pytest
from mcptriage.transcript import parse_text
from mcptriage.rules import diagnose

@pytest.mark.parametrize('text',['',' \n\t','booting server','{"broken":',
    'null','[]','true','42','{"status":"connected"}',
    'HTTP/1.1 200 OK\ncontent-type: application/json'])
def test_no_protocol_evidence_is_explicit_high_finding(text):
    fs=diagnose(parse_text(text))
    assert any(f.code=='NO_PROTOCOL_MESSAGES' and f.severity=='high' for f in fs)

@pytest.mark.parametrize('mode',['text','json'])
@pytest.mark.parametrize('text',['','just a banner','{"broken":'])
def test_cli_invalid_capture_is_not_success(tmp_path,capsys,text,mode):
    from mcptriage.cli import main
    p=tmp_path/'capture.txt';p.write_text(text)
    assert main(['diagnose',str(p),'--format',mode])==1
    out=capsys.readouterr().out
    assert 'NO_PROTOCOL_MESSAGES' in out
    assert 'no problems found' not in out

@pytest.mark.parametrize('mode',['text','json'])
def test_cli_stdin_and_exit_zero_keep_finding(monkeypatch,capsys,mode):
    from io import StringIO
    from mcptriage.cli import main
    monkeypatch.setattr('sys.stdin',StringIO(''))
    assert main(['diagnose','-','--format',mode,'--exit-zero'])==0
    assert 'NO_PROTOCOL_MESSAGES' in capsys.readouterr().out

def test_valid_notification_is_protocol_evidence_not_healthy_claim():
    fs=diagnose(parse_text('{"method":"notifications/initialized"}'))
    assert not any(f.code=='NO_PROTOCOL_MESSAGES' for f in fs)
    assert any(f.code=='CAPTURE_INCOMPLETE' for f in fs)

def test_invalid_ids_not_reported_as_empty_capture():
    fs=diagnose(parse_text('{"id":true,"method":"tools/list"}'))
    assert any(f.code=='INVALID_RPC_ID' for f in fs)
    assert not any(f.code=='NO_PROTOCOL_MESSAGES' for f in fs)

def test_unparsed_evidence_has_line_number_and_masking():
    fs=diagnose(parse_text('Authorization: Bearer SYNTHETIC_SENTINEL'))
    f=next(f for f in fs if f.code=='NO_PROTOCOL_MESSAGES')
    assert 'line 1:' in f.evidence
    assert 'SYNTHETIC_SENTINEL' not in f.evidence
