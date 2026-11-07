"""Invalid file encoding must not turn into a clean config verdict."""
import json

import pytest

from mcptriage.cli import main
from mcptriage.configcheck import check_config_file


@pytest.mark.parametrize('bad', [b'\xff', b'\xc3(', b'\xe2\x82', b'\xed\xa0\x80'])
def test_invalid_utf8_is_high_without_echoing_config(tmp_path, bad):
    path = tmp_path / 'config.json'
    path.write_bytes(b'{"mcpServers":{"private-marker":{"url":"https://example.invalid/'
                     + bad + b'"}}}')
    findings = check_config_file(str(path))
    assert len(findings) == 1
    finding = findings[0]
    assert finding.code == 'CFG_UTF8_ERROR'
    assert finding.severity == 'high'
    assert finding.evidence == str(path)
    assert 'private-marker' not in repr(finding)
    assert 'example.invalid' not in repr(finding)


@pytest.mark.parametrize('mode', ['text', 'json'])
@pytest.mark.parametrize('command', ['check-config', 'diagnose'])
def test_cli_invalid_utf8_blocks_in_both_config_routes(tmp_path, capsys, mode, command):
    path = tmp_path / 'config.json'
    path.write_bytes(b'{"mcpServers":{"private-marker":{"url":"https://example.invalid/\xff"}}}')
    args = ['check-config', str(path)]
    if command == 'diagnose':
        log = tmp_path / 'log.jsonl'
        log.write_text('{"jsonrpc":"2.0","id":1,"method":"initialize"}\n', encoding='utf-8')
        args = ['diagnose', str(log), '--config', str(path)]
    assert main([*args, '--format', mode]) == 1
    output = capsys.readouterr()
    assert 'CFG_UTF8_ERROR' in output.out
    assert 'private-marker' not in output.out
    assert 'example.invalid' not in output.out
    assert 'Traceback' not in output.err
    if mode == 'json':
        assert any(f['code'] == 'CFG_UTF8_ERROR' for f in json.loads(output.out)['findings'])


@pytest.mark.parametrize('suffix', ['café', '\ufffd', '日本語'])
def test_valid_utf8_including_literal_replacement_character_stays_clean(tmp_path, suffix):
    path = tmp_path / 'config.json'
    path.write_text(json.dumps({'mcpServers': {'server': {'url': 'https://example.invalid/' + suffix}}},
                               ensure_ascii=False), encoding='utf-8')
    assert check_config_file(str(path)) == []


def test_unreadable_file_still_raises_oserror(tmp_path):
    with pytest.raises(OSError):
        check_config_file(str(tmp_path / 'missing.json'))
