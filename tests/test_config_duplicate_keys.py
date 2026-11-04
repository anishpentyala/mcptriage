"""Ambiguous config objects must not become a clean last-value-wins report."""
import json
import pytest
from mcptriage.cli import main
from mcptriage.configcheck import check_config_text, check_config_file
from mcptriage.report import render_json, render_text


DUPLICATES = [
    '{"mcpServers":{},"mcpServers":{"s":{"command":"python"}}}',
    '{"mcpServers":{"s":null,"s":{"command":"python"}}}',
    '{"mcpServers":{"s":{"command":"/definitely/missing","command":"python"}}}',
    '{"mcpServers":{"s":{"url":null,"url":"https://example.invalid"}}}',
    '{"mcpServers":{"s":{"type":"broken","type":"stdio","command":"python"}}}',
    '{"mcpServers":{"s":{"args":"bad","args":[],"command":"python"}}}',
    '{"mcpServers":{"s":{"command":"python","env":{"KEY":"a","KEY":"b"}}}}',
    '{"mcpServers":{"s":{"command":"python","envFile":"a","envFile":"b"}}}',
    '{"servers":{"s":{"url":"https://example.invalid","url":null}}}',
    '{"meta":{"x":1,"x":2},"servers":{"s":{"command":"python"}}}',
    r'{"mcpServers":{"s":{"comm\u0061nd":"bad","command":"python"}}}',
    '{"mcpServers":{"s":{"command":"python","args":[{"x":1,"x":2}]}}}',
]


@pytest.mark.parametrize('text', DUPLICATES)
def test_ambiguous_document_is_one_high_finding_without_partial_checks(text):
    findings = check_config_text(text, 'client.json')
    assert [(f.code, f.severity) for f in findings] == [('CFG_JSON_DUPLICATE_KEY','high')]
    assert findings[0].evidence == 'client.json'
    assert 'no server entries were checked' in findings[0].why


def test_duplicate_launch_setting_cannot_report_clean_regression_control():
    text = '{"mcpServers":{"s":{"command":"/definitely/missing","command":"python"}}}'
    fs = check_config_text(text)
    assert any(f.code == 'CFG_JSON_DUPLICATE_KEY' and f.severity == 'high' for f in fs), \
        'duplicate launch command must not disappear into a clean last-value report'


@pytest.mark.parametrize('renderer', [render_json, render_text])
def test_no_duplicate_name_or_value_leaks(renderer):
    key, value = 'PRIVATE_KEY_SENTINEL_6d49', 'PRIVATE_VALUE_SENTINEL_4e82'
    text = '{"mcpServers":{"s":{"command":"python","env":{' + json.dumps(key)+':'+json.dumps(value)+','+json.dumps(key)+':"safe"}}}}'
    findings = check_config_text(text)
    out = renderer(findings, 'client.json')
    assert 'CFG_JSON_DUPLICATE_KEY' in out
    assert key not in out and value not in out


@pytest.mark.parametrize('obj', [
    {'mcpServers':{'s':{'command':'python'}}},
    {'servers':{'s':{'url':'https://example.invalid'}}},
    {'mcpServers':{'a':{'command':'python'},'b':{'command':'python'}}},
    {'mcpServers':{'s':{'command':'python','env':{'K':'a','k':'b'}}}},
    {'mcpServers':{'s':{'command':'python','args':['same','same']}}},
])
def test_distinct_objects_case_distinct_names_and_repeated_array_values_valid(obj):
    assert check_config_text(json.dumps(obj)) == []


@pytest.mark.parametrize('fmt', ['text','json'])
def test_cli_and_file_duplicate_failure(tmp_path, capsys, fmt):
    p = tmp_path/'client.json';p.write_text(DUPLICATES[2])
    assert check_config_file(str(p))[0].code == 'CFG_JSON_DUPLICATE_KEY'
    assert main(['check-config',str(p),'--format',fmt]) == 1
    assert 'CFG_JSON_DUPLICATE_KEY' in capsys.readouterr().out
    assert main(['check-config',str(p),'--format',fmt,'--exit-zero']) == 0


def test_combined_diagnose_keeps_duplicate_finding(tmp_path,capsys):
    cfg=tmp_path/'client.json';cfg.write_text(DUPLICATES[2])
    log=tmp_path/'capture.jsonl';log.write_text('{"id":1,"method":"ping"}\n{"id":1,"result":{}}\n')
    assert main(['diagnose',str(log),'--config',str(cfg),'--format','json']) == 1
    assert any(f['code']=='CFG_JSON_DUPLICATE_KEY' for f in json.loads(capsys.readouterr().out)['findings'])


def test_ordinary_syntax_error_stays_distinct():
    assert check_config_text('{"mcpServers":{,}')[0].code == 'CFG_JSON_ERROR'
