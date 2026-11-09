"""VS Code transport selection must not borrow the other transport's endpoint."""

import json
import sys

import pytest

from mcptriage.configcheck import check_config_text

URL = 'https://example.invalid/mcp?SYNTHETIC_ENDPOINT_SECRET'


def check(spec, root='servers'):
    return check_config_text(json.dumps({root: {'sample': spec}}))


def required_findings(findings):
    return [finding for finding in findings if finding.code == 'CFG_TRANSPORT_REQUIRED']


@pytest.mark.parametrize('transport,required,other', [
    ('stdio', 'command', {'url': URL}),
    ('http', 'url', {'command': sys.executable}),
    ('sse', 'url', {'command': sys.executable}),
])
@pytest.mark.parametrize('missing', ['absent', '', ' ', '\t\n', None, False, [], {}])
def test_vscode_declared_transport_requires_its_own_field(transport, required, other, missing):
    spec = {'type': transport, **other}
    if missing != 'absent':
        spec[required] = missing
    findings = check(spec)
    failures = required_findings(findings)
    assert len(failures) == 1
    assert failures[0].severity == 'high'
    assert required in failures[0].title
    assert 'SYNTHETIC_ENDPOINT_SECRET' not in str(failures[0])


@pytest.mark.parametrize('spec', [
    {'type': 'stdio', 'command': sys.executable},
    {'type': 'http', 'url': URL},
    {'type': 'sse', 'url': URL},
    {'command': sys.executable},
    {'url': URL},
    {'type': 'future-transport', 'url': URL},
    {'type': None, 'url': URL},
    {'type': 'streamable-http', 'url': URL},
])
def test_valid_or_unresolved_transport_keeps_existing_diagnostics(spec):
    assert not required_findings(check(spec))


@pytest.mark.parametrize('transport', ['stdio', 'http', 'sse'])
def test_portable_map_does_not_inherit_vscode_specific_contract(transport):
    assert not required_findings(check({'type': transport, 'url': URL}, 'mcpServers'))


def test_selected_portable_map_is_not_overridden_by_ignored_vscode_map():
    text = json.dumps({'mcpServers': {'portable': {'url': URL}},
                       'servers': {'vscode': {'type': 'stdio', 'url': URL}}})
    assert not required_findings(check_config_text(text))


@pytest.mark.parametrize('mode', ['text', 'json'])
@pytest.mark.parametrize('transport', ['stdio', 'http', 'sse'])
def test_cli_fails_for_mismatched_endpoint_without_echoing_value(tmp_path, capsys, mode, transport):
    from mcptriage.cli import main

    spec = {'type': transport}
    spec.update({'url': URL} if transport == 'stdio' else {'command': sys.executable})
    path = tmp_path / 'mcp.json'
    path.write_text(json.dumps({'servers': {'sample': spec}}), encoding='utf-8')
    assert main(['check-config', str(path), '--format', mode]) == 1
    captured = capsys.readouterr()
    assert 'CFG_TRANSPORT_REQUIRED' in captured.out
    assert 'SYNTHETIC_ENDPOINT_SECRET' not in captured.out
    assert not captured.err
