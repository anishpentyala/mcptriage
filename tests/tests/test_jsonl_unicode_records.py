"""Unicode string data is not a JSON Lines record terminator."""
import json
import pytest
from mcptriage.transcript import parse_text
from mcptriage.rules import diagnose

SEPARATORS=['\x85','\u2028','\u2029']

def capture(separator,ending='\n',prefix=''):
    rows=[{'id':1,'method':'tools/list'},
          {'id':1,'result':{'tools':[{'name':'x','description':'first'+separator+'second',
                                    'inputSchema':{'required':['q']}}]}},
          {'id':2,'method':'tools/call','params':{'name':'x','arguments':{}}},
          {'id':2,'error':{'code':-32602}}]
    return ending.join(prefix+json.dumps(r,ensure_ascii=False) for r in rows)

@pytest.mark.parametrize('separator',SEPARATORS)
@pytest.mark.parametrize('ending',['\n','\r\n'])
@pytest.mark.parametrize('prefix',['','[mcp] '])
def test_unicode_description_preserves_catalog_and_physical_line_numbers(separator,ending,prefix):
    session=parse_text(capture(separator,ending,prefix))
    assert [m.line_no for m in session.messages]==[1,2,3,4]
    assert session.tools_by_name()=={'x':{'required':['q']}}
    assert session.response_for(session.requests('tools/list')[0]).line_no==2
    findings=diagnose(session)
    assert any(f.code=='TOOL_CALL_ARG_MISMATCH' and "missing required argument 'q'" in f.why for f in findings)
    assert not any(f.code in ['TOOLS_LIST_HANG','STDIO_POLLUTION'] for f in findings)

def test_unicode_description_does_not_erase_observed_schema_control():
    session=parse_text(capture('\u2028'))
    assert session.tools_by_name()=={'x':{'required':['q']}}, 'Unicode description must not erase an observed schema'

@pytest.mark.parametrize('separator',SEPARATORS)
def test_unicode_string_id_stays_one_exact_identifier(separator):
    identifier='request'+separator+'tail'
    text='\n'.join(json.dumps(r,ensure_ascii=False) for r in [
        {'id':identifier,'method':'tools/list'}, {'id':identifier,'result':{'tools':[]}}])
    s=parse_text(text)
    assert len(s.messages)==2
    assert s.requests()[0].msg_id==identifier
    assert s.response_for(s.requests()[0]).line_no==2
    assert any(f.code=='EMPTY_TOOLS_LIST' for f in diagnose(s))

@pytest.mark.parametrize('separator',SEPARATORS)
def test_unicode_argument_keeps_literal_value(separator):
    value='left'+separator+'right'
    s=parse_text(json.dumps({'id':1,'method':'tools/call','params':{'name':'x','arguments':{'q':value}}},ensure_ascii=False))
    assert len(s.messages)==1
    assert s.requests()[0].obj['params']['arguments']['q']==value

@pytest.mark.parametrize('mode',['text','json'])
@pytest.mark.parametrize('separator',SEPARATORS)
def test_cli_preserves_diagnosis_from_unicode_catalog(tmp_path,capsys,mode,separator):
    from mcptriage.cli import main
    p=tmp_path/'capture.jsonl';p.write_text(capture(separator),encoding='utf-8')
    assert main(['diagnose',str(p),'--format',mode])==1
    out=capsys.readouterr().out
    assert 'TOOL_CALL_ARG_MISMATCH' in out
    assert "missing required argument 'q'" in out
    assert 'TOOLS_LIST_HANG' not in out

@pytest.mark.parametrize('character',['\v','\f','\x1c','\x1d','\x1e'])
def test_forbidden_control_character_is_not_a_new_record(character):
    # Unlike NEL/LS/PS these are not valid literal JSON string content. Keep
    # one damaged physical record, not two independently invented records.
    text='{"id":1,"method":"tools/call","params":{"q":"a'+character+'b"}}'
    s=parse_text(text)
    assert len(s.messages)==1 and s.messages[0].kind=='unparsed'
    assert s.messages[0].raw==text

@pytest.mark.parametrize('separator',SEPARATORS)
def test_escaped_and_literal_unicode_have_identical_protocol_outcomes(separator):
    literal=capture(separator)
    escaped=literal.replace(separator,'\\u%04x'%ord(separator))
    a,b=parse_text(literal),parse_text(escaped)
    assert [(m.kind,m.obj,m.line_no) for m in a.messages]==[(m.kind,m.obj,m.line_no) for m in b.messages]
    assert [(f.code,f.title,f.why) for f in diagnose(a)]==[(f.code,f.title,f.why) for f in diagnose(b)]

def test_unicode_identifier_remains_pairable_control():
    rows=[{'id':'first\u2029last','method':'tools/list'},
          {'id':'first\u2029last','result':{'tools':[]}}]
    s=parse_text('\n'.join(json.dumps(r,ensure_ascii=False) for r in rows))
    assert len(s.requests())==1, 'Unicode request identifier must remain a single request'
    assert s.response_for(s.requests()[0]) is not None
