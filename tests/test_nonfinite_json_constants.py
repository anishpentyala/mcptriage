"""Reject Python JSON extensions without inventing nested protocol traffic."""
import json
import pytest
from mcptriage.transcript import parse_text
from mcptriage.rules import diagnose
from mcptriage.configcheck import check_config_text


@pytest.mark.parametrize('constant',['NaN','Infinity','-Infinity'])
@pytest.mark.parametrize('prefix',['','INFO client: '])
@pytest.mark.parametrize('field',['params','result'])
def test_nonjson_literal_cannot_establish_traffic(constant,prefix,field):
    line='{"id":1,"method":"tools/list","%s":{"bad":%s,"nested":{"id":2,"method":"initialize"}}}'%(field,constant)
    session=parse_text(prefix+line)
    assert len(session.messages)==1
    assert session.messages[0].raw==prefix+line
    assert session.parsed==[] and session.requests()==[]
    assert session.response_pairs()=={} and session.tools_by_name()=={}
    assert [f.code for f in diagnose(session)]==['NONFINITE_JSON_CONSTANT']


@pytest.mark.parametrize('constant',['NaN','Infinity','-Infinity'])
def test_bad_catalog_cannot_supply_schema(constant):
    text='{"id":1,"method":"tools/list"}\n{"id":1,"result":{"tools":[{"name":"x","inputSchema":{"enum":[%s]}}]}}'%constant
    session=parse_text(text)
    assert session.tools_by_name()=={}
    assert session.response_for(session.requests()[0]) is None


@pytest.mark.parametrize('constant',['NaN','Infinity','-Infinity'])
def test_config_excludes_entire_ambiguous_document_without_secret_echo(constant):
    text='{"mcpServers":{"private-name":{"command":"/private/secret","bad":%s}}}'%constant
    findings=check_config_text(text)
    assert [f.code for f in findings]==['CFG_NONFINITE_JSON_CONSTANT']
    assert 'private-name' not in str(findings) and '/private/secret' not in str(findings)


@pytest.mark.parametrize('value',['NaN','Infinity','-Infinity'])
def test_quoted_strings_still_usable(value):
    session=parse_text(json.dumps({'id':value,'method':'tools/list'}))
    assert session.requests()[0].msg_id==value


@pytest.mark.parametrize('number',['1e400','-1e400','1e-400'])
def test_valid_exponent_literals_not_nonjson_constants(number):
    session=parse_text('{"id":1,"method":"tools/call","params":{"name":"x","arguments":{"x":%s}}}'%number)
    assert len(session.requests())==1
    assert not any(f.code=='NONFINITE_JSON_CONSTANT' for f in diagnose(session))


@pytest.mark.parametrize('mode',['text','json'])
def test_cli_nonfinite_high_severity(tmp_path,capsys,mode):
    from mcptriage.cli import main
    path=tmp_path/'capture';path.write_text('{"id":1,"result":{"tools":[],"secret":"not-for-output","bad":NaN}}')
    assert main(['diagnose',str(path),'--format',mode])==1
    out=capsys.readouterr().out
    assert 'NONFINITE_JSON_CONSTANT' in out and 'not-for-output' not in out
