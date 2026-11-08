"""Malformed bytes must not collapse distinct protocol identities into evidence."""
import io
import json
import os
import subprocess
import sys

import pytest

from mcptriage.cli import main
from mcptriage.transcript import parse_file, parse_text


def capture(first, second):
    return (b'{"jsonrpc":"2.0","id":"' + first + b'","method":"tools/list"}\n'
            b'{"jsonrpc":"2.0","id":"' + second + b'","result":{"tools":'
            b'[{"name":"synthetic-private-name","inputSchema":{"type":"object"}}]}}\n')


@pytest.mark.parametrize('bad', [b'\xff', b'\xc3(', b'\xe2\x82', b'\xed\xa0\x80'])
def test_file_rejects_invalid_utf8_before_catalog_projection(tmp_path, bad):
    path = tmp_path / 'capture.jsonl'
    path.write_bytes(capture(bad, b'\xfe'))
    with pytest.raises(UnicodeDecodeError):
        parse_file(str(path))


@pytest.mark.parametrize('source', ['file', 'stdin'])
@pytest.mark.parametrize('output', ['text', 'json'])
@pytest.mark.parametrize('exit_zero', [False, True])
def test_cli_invalid_bytes_publish_no_partial_diagnosis(tmp_path, source, output, exit_zero):
    data = capture(b'\xff', b'\xfe')
    path = tmp_path / 'capture.jsonl'
    path.write_bytes(data)
    run = subprocess.run(
        [sys.executable, '-m', 'mcptriage', 'diagnose',
         str(path) if source == 'file' else '-', '--format', output]
        + (['--exit-zero'] if exit_zero else []),
        input=data if source == 'stdin' else None, capture_output=True,
        env=dict(os.environ, PYTHONIOENCODING='utf-8:replace'),
    )
    assert run.returncode == 2
    assert run.stdout == b''
    assert b'UTF-8' in run.stderr
    assert b'Traceback' not in run.stderr
    assert b'synthetic-private-name' not in run.stderr


@pytest.mark.parametrize('ident', ['café', '日本語', '\ufffd'])
@pytest.mark.parametrize('source', ['file', 'stdin'])
def test_valid_utf8_ids_and_catalog_are_preserved(tmp_path, ident, source):
    data = capture(ident.encode('utf-8'), ident.encode('utf-8'))
    path = tmp_path / 'capture.jsonl'
    path.write_bytes(data)
    session = parse_file(str(path))
    assert session.messages[0].msg_id == ident
    assert session.response_for(session.messages[0]) is session.messages[1]
    assert 'synthetic-private-name' in session.tools_by_name()
    run = subprocess.run(
        [sys.executable, '-m', 'mcptriage', 'diagnose',
         str(path) if source == 'file' else '-', '--format', 'json'],
        input=data if source == 'stdin' else None, capture_output=True,
        # stdin bytes are UTF-8 independently of the process text wrapper.
        env=dict(os.environ, PYTHONIOENCODING='ascii:replace'),
    )
    assert run.returncode == 0
    assert run.stderr == b''
    assert json.loads(run.stdout)['finding_count'] == 1


def test_text_api_does_not_reject_legitimate_replacement_characters():
    session = parse_text(capture(b'\xef\xbf\xbd', b'\xef\xbf\xbd').decode('utf-8'))
    assert session.response_for(session.messages[0]) is session.messages[1]


def test_text_only_stdin_remains_supported(monkeypatch, capsys):
    monkeypatch.setattr(sys, 'stdin', io.StringIO(capture(b'ok', b'ok').decode()))
    assert main(['diagnose', '-', '--format', 'json']) == 0
    assert json.loads(capsys.readouterr().out)['finding_count'] == 1
