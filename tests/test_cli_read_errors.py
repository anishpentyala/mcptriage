"""Input failures must be concise errors, not tracebacks or partial success."""
import json
import subprocess
import sys

import pytest

from mcptriage.cli import main


def assert_input_error(arguments):
    try:
        main(arguments)
    except (SystemExit, OSError) as exc:
        assert isinstance(exc, SystemExit), "input failure escaped CLI boundary: %s" % type(exc).__name__
        assert exc.code == 2
    else:
        pytest.fail("input failure did not stop the CLI")


@pytest.mark.parametrize('command', ['diagnose', 'check-config'])
@pytest.mark.parametrize('kind', ['missing', 'directory'])
@pytest.mark.parametrize('output', ['text', 'json'])
@pytest.mark.parametrize('exit_zero', [False, True])
def test_unreadable_primary_input(tmp_path, command, kind, output, exit_zero):
    path = tmp_path / 'input'
    if kind == 'directory':
        path.mkdir()
    run = subprocess.run(
        [sys.executable, '-m', 'mcptriage', command, str(path), '--format', output]
        + (['--exit-zero'] if exit_zero else []),
        text=True, capture_output=True,
    )
    assert run.returncode == 2
    assert run.stdout == ''
    assert 'Traceback' not in run.stderr
    assert 'cannot read' in run.stderr


@pytest.mark.parametrize('source', ['file', 'stdin'])
@pytest.mark.parametrize('output', ['text', 'json'])
@pytest.mark.parametrize('exit_zero', [False, True])
def test_config_failure_does_not_publish_partial_diagnosis(tmp_path, source, output, exit_zero):
    path = tmp_path / 'capture.jsonl'
    path.write_text('{}\n')
    run = subprocess.run(
        [sys.executable, '-m', 'mcptriage', 'diagnose', str(path) if source == 'file' else '-',
         '--config', str(tmp_path / 'missing'), '--format', output]
        + (['--exit-zero'] if exit_zero else []),
        input='{}\n' if source == 'stdin' else None, text=True, capture_output=True,
    )
    assert run.returncode == 2
    assert run.stdout == ''
    assert 'Traceback' not in run.stderr
    assert 'cannot read config' in run.stderr


@pytest.mark.parametrize('command', ['diagnose', 'check-config'])
def test_error_does_not_echo_oserror_secret(monkeypatch, capsys, command):
    def denied(*args, **kwargs):
        raise PermissionError('token=synthetic_failure_secret')
    monkeypatch.setattr('mcptriage.cli.parse_file' if command == 'diagnose'
                        else 'mcptriage.cli.check_config_file', denied)
    assert_input_error([command, 'input'])
    captured = capsys.readouterr()
    assert captured.out == ''
    assert 'synthetic_failure_secret' not in captured.err
    assert 'PermissionError' in captured.err


@pytest.mark.parametrize('command', ['diagnose', 'check-config'])
def test_readable_empty_input_retains_diagnostic(tmp_path, capsys, command):
    path = tmp_path / 'empty'
    path.write_text('' if command == 'diagnose' else '{}')
    assert main([command, str(path), '--format', 'json']) == 1
    captured = capsys.readouterr()
    assert captured.err == ''
    assert json.loads(captured.out)['finding_count'] > 0


def test_stdin_read_failure(monkeypatch, capsys):
    class BrokenInput:
        def read(self):
            raise OSError('token=synthetic_stdin_secret')
    monkeypatch.setattr('sys.stdin', BrokenInput())
    assert_input_error(['diagnose', '-'])
    captured = capsys.readouterr()
    assert captured.out == ''
    assert 'cannot read transcript' in captured.err
    assert 'synthetic_stdin_secret' not in captured.err


@pytest.mark.parametrize('command', ['diagnose', 'check-config'])
@pytest.mark.parametrize('secret_path', ['token=synthetic_path_secret', 'Bearer synthetic_path_secret'])
def test_unreadable_input_does_not_echo_raw_path(tmp_path, capsys, command, secret_path):
    assert_input_error([command, str(tmp_path / secret_path)])
    captured = capsys.readouterr()
    assert captured.out == ''
    assert 'synthetic_path_secret' not in captured.err


@pytest.mark.parametrize('command', ['diagnose', 'check-config'])
def test_internal_exception_is_not_misreported_as_read_failure(monkeypatch, command):
    def defect(*args, **kwargs):
        raise RuntimeError('synthetic internal defect')
    monkeypatch.setattr('mcptriage.cli.parse_file' if command == 'diagnose'
                        else 'mcptriage.cli.check_config_file', defect)
    with pytest.raises(RuntimeError, match='internal defect'):
        main([command, 'input'])
