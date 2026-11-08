"""VS Code's servers format has a wider env value contract than mcpServers."""
import json
import sys

import pytest

from mcptriage.configcheck import check_config_text


VALID_VSCODE = [None, 0, 1, -5, 0.5, -2.75, 1e100, '', 'plain', '${env:PATH}']
BAD_VSCODE = [False, True, [], {}, ['SYNTHETIC_ENV_SECRET'], {'x': 'SYNTHETIC_ENV_SECRET'}]


def inspect(value, key='servers'):
    return check_config_text(json.dumps({key: {'local': {
        'type': 'stdio', 'command': sys.executable, 'env': {'VALUE': value}
    }}}))


@pytest.mark.parametrize('value', VALID_VSCODE)
def test_vscode_documented_env_values_do_not_invent_shape_problem(value):
    assert not any(f.code == 'CFG_SHAPE' for f in inspect(value))


@pytest.mark.parametrize('value', BAD_VSCODE)
def test_vscode_rejects_bool_and_container_env_values_without_echo(value):
    fs = inspect(value)
    assert any(f.code == 'CFG_SHAPE' and 'env' in f.title for f in fs)
    assert all('SYNTHETIC_ENV_SECRET' not in str(f) for f in fs)


@pytest.mark.parametrize('value', [None, 0, 1, -5, 0.5, False, True, [], {}])
def test_mcpservers_keeps_existing_string_only_contract(value):
    assert any(f.code == 'CFG_SHAPE' and 'env' in f.title
               for f in inspect(value, key='mcpServers'))


@pytest.mark.parametrize('key', ['mcpServers', 'servers'])
def test_valid_string_values_and_missing_or_empty_env_still_work(key):
    assert not any(f.code == 'CFG_SHAPE' for f in inspect('SYNTHETIC_ENV_SECRET', key))
    for spec in ({'command': sys.executable}, {'command': sys.executable, 'env': {}}):
        assert not any(f.code == 'CFG_SHAPE' for f in
                       check_config_text(json.dumps({key: {'local': spec}})))


@pytest.mark.parametrize('env', [None, False, 0, 'SYNTHETIC_ENV_SECRET', []])
def test_wider_value_contract_does_not_allow_nonobject_env(env):
    fs = check_config_text(json.dumps({'servers': {'local': {
        'command': sys.executable, 'env': env
    }}}))
    assert any(f.code == 'CFG_SHAPE' and 'env' in f.title for f in fs)
    assert all('SYNTHETIC_ENV_SECRET' not in str(f) for f in fs)


@pytest.mark.parametrize('literal', ['1e999', '-1e999'])
def test_overflowed_json_numbers_are_not_usable_vscode_environment_values(literal):
    text = '{"servers":{"local":{"url":"https://example.test/mcp","env":{"X":' + literal + '}}}}'
    assert any(f.code == 'CFG_SHAPE' and 'env' in f.title
               for f in check_config_text(text))


def test_selected_map_not_presence_of_servers_controls_contract():
    obj = {'mcpServers': {'strict': {'command': sys.executable, 'env': {'X': None}}},
           'servers': {'vscode': {'command': sys.executable, 'env': {'X': None}}}}
    fs = check_config_text(json.dumps(obj))
    assert any(f.code == 'CFG_SHAPE' and "'strict'" in f.title for f in fs)
    assert all('vscode' not in f.title for f in fs)


@pytest.mark.parametrize('command', ['check-config', 'diagnose'])
@pytest.mark.parametrize('mode', ['text', 'json'])
@pytest.mark.parametrize('value', [None, 3, 0.25])
def test_cli_paths_preserve_valid_vscode_env_without_false_diagnostic(tmp_path, capsys, command, mode, value):
    from mcptriage.cli import main
    config = tmp_path / 'mcp.json'
    config.write_text(json.dumps({'servers': {'local': {
        'command': sys.executable, 'type': 'stdio',
        'env': {'VALUE': value, 'API_KEY': 'SYNTHETIC_ENV_SECRET'}
    }}}))
    if command == 'check-config':
        args = [command, str(config), '--format', mode]
    else:
        capture = tmp_path / 'capture.jsonl'
        capture.write_text('{}\n')
        args = [command, str(capture), '--config', str(config), '--format', mode]
    status = main(args)
    output = capsys.readouterr()
    assert 'CFG_SHAPE' not in output.out
    assert 'SYNTHETIC_ENV_SECRET' not in output.out
    assert not output.err
    if command == 'check-config':
        assert status == 0


def test_string_environment_reference_still_checked_beside_number_and_null(monkeypatch):
    monkeypatch.delenv('MCPTRIAGE_SYNTHETIC_UNSET', raising=False)
    obj = {'servers': {'local': {'command': sys.executable, 'env': {
        'TEXT': '${env:MCPTRIAGE_SYNTHETIC_UNSET}', 'NUMBER': 3, 'NULL': None
    }}}}
    fs = check_config_text(json.dumps(obj))
    assert not any(f.code == 'CFG_SHAPE' for f in fs)
    assert sum(f.code == 'CFG_ENV_UNSET' for f in fs) == 1


def test_existing_fallback_selects_vscode_contract_when_mcpservers_not_map():
    obj = {'mcpServers': None, 'servers': {'local': {
        'command': sys.executable, 'env': {'X': None}
    }}}
    assert not any(f.code == 'CFG_SHAPE' for f in check_config_text(json.dumps(obj)))
