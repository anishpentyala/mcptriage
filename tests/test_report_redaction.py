"""Every report field uses the existing best-effort credential masker."""
import pytest
from mcptriage.rules import Finding,diagnose
from mcptriage.transcript import parse_text
from mcptriage.report import render_json,render_text

@pytest.mark.parametrize('render',[render_text,render_json])
@pytest.mark.parametrize('strict',[False,True])
@pytest.mark.parametrize('secret',[
    'Authorization: Bearer private-marker',
    '{"token":"private-marker"}',
    'https://x.test/?token=private-marker',
    'https://alice:private-marker@x.test/',
])
def test_stdio_noise_evidence_masks_known_credential_forms(render,strict,secret):
    s=parse_text('{"id":1,"method":"tools/list"}\n'+secret+'\n{"id":1,"result":{"tools":[]}}')
    fs=diagnose(s,strict_stdio=strict)
    assert any(f.code=='STDIO_POLLUTION' for f in fs)
    assert 'private-marker' not in render(fs,'<stdin>')


@pytest.mark.parametrize('render',[render_text,render_json])
@pytest.mark.parametrize('field',['title','evidence','why','fix'])
def test_report_boundary_masks_each_free_text_field_without_mutation(render,field):
    data=dict(code='EXAMPLE',severity='high',title='title',evidence='evidence',why='why',fix='fix')
    data[field]='Bearer private-marker'
    f=Finding(**data)
    assert 'private-marker' not in render([f],'<stdin>')
    assert getattr(f,field)=='Bearer private-marker'


@pytest.mark.parametrize('render',[render_text,render_json])
def test_clean_report_text_is_preserved(render):
    f=Finding('EXAMPLE','low','plain title','line 1: clean','plain reason','plain fix')
    out=render([f],'<stdin>')
    assert all(x in out for x in ['EXAMPLE','plain title','line 1: clean','plain reason','plain fix'])


@pytest.mark.parametrize('render',[render_text,render_json])
@pytest.mark.parametrize('empty',[False,True])
def test_source_masking_with_or_without_findings(render,empty):
    fs=[] if empty else [Finding('X','low','title','evidence','why','fix')]
    assert 'private-marker' not in render(fs,'https://x.test/?token=private-marker')


@pytest.mark.parametrize('mode',['text','json'])
def test_cli_pollution_output_does_not_echo_known_token(tmp_path,capsys,mode):
    from mcptriage.cli import main
    p=tmp_path/'capture.log'
    p.write_text('{"id":1,"method":"tools/list"}\nAuthorization: Bearer private-marker\n'
                 '{"id":1,"result":{"tools":[]}}')
    assert main(['diagnose',str(p),'--format',mode])==1
    out=capsys.readouterr()
    assert 'STDIO_POLLUTION' in out.out
    assert 'private-marker' not in out.out
    assert 'Traceback' not in out.err


def test_pollution_masking_runs_before_evidence_clip():
    raw='Authorization: Bearer '+('private-marker'*20)
    fs=diagnose(parse_text('{"id":1,"method":"tools/list"}\n'+raw+'\n{"id":1,"result":{}}'))
    f=next(f for f in fs if f.code=='STDIO_POLLUTION')
    assert 'private-marker' not in f.evidence
    assert len(f.evidence)<100


def test_best_effort_limit_does_not_claim_unknown_secret_formats_masked():
    from mcptriage.rules import redact
    assert redact('custom opaque marker')=='custom opaque marker'
