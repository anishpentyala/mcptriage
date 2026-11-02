"""Pagination completion needs a later, correctly typed cursor request."""
import json
import pytest
from mcptriage.transcript import parse_text
from mcptriage.rules import diagnose

def codes(rows):
    return {f.code for f in diagnose(parse_text('\n'.join(json.dumps(r) for r in rows)))}


def test_earlier_cursor_request_cannot_complete_a_later_page():
    rows=[{'id':1,'method':'tools/list','params':{'cursor':'next'}},
          {'id':1,'result':{'tools':[]}},
          {'id':2,'method':'tools/list'},
          {'id':2,'result':{'tools':[],'nextCursor':'next'}}]
    assert 'PAGINATION_INCOMPLETE' in codes(rows)


@pytest.mark.parametrize('bad',[[],{},True,1,['next']])
def test_bad_request_cursor_does_not_crash_or_satisfy_page(bad):
    rows=[{'id':1,'method':'tools/list'},
          {'id':1,'result':{'tools':[],'nextCursor':'next'}},
          {'id':2,'method':'tools/list','params':{'cursor':bad}}]
    assert 'UNUSABLE_CURSOR' in codes(rows)
    assert 'PAGINATION_INCOMPLETE' in codes(rows)


@pytest.mark.parametrize('bad',[[],{},True,1,['next']])
def test_bad_response_cursor_is_explicit_not_pagination_guess(bad):
    rows=[{'id':1,'method':'tools/list'},
          {'id':1,'result':{'tools':[],'nextCursor':bad}}]
    c=codes(rows)
    assert 'UNUSABLE_CURSOR' in c
    assert 'PAGINATION_INCOMPLETE' not in c


@pytest.mark.parametrize('cursor',['next',''])
def test_later_same_string_cursor_completes_page(cursor):
    rows=[{'id':1,'method':'tools/list'},
          {'id':1,'result':{'tools':[],'nextCursor':cursor}},
          {'id':2,'method':'tools/list','params':{'cursor':cursor}}]
    assert 'PAGINATION_INCOMPLETE' not in codes(rows)
    assert 'UNUSABLE_CURSOR' not in codes(rows)


def test_empty_string_cursor_not_silently_ignored():
    assert 'PAGINATION_INCOMPLETE' in codes([
        {'id':1,'method':'tools/list'},
        {'id':1,'result':{'tools':[],'nextCursor':''}}])


def test_cursor_request_before_response_does_not_prove_followthrough():
    assert 'PAGINATION_INCOMPLETE' in codes([
        {'id':1,'method':'tools/list'},
        {'id':2,'method':'tools/list','params':{'cursor':'next'}},
        {'id':1,'result':{'tools':[],'nextCursor':'next'}}])


def test_unrelated_method_cannot_complete_tool_page():
    assert 'PAGINATION_INCOMPLETE' in codes([
        {'id':1,'method':'tools/list'},
        {'id':1,'result':{'tools':[],'nextCursor':'next'}},
        {'id':2,'method':'resources/list','params':{'cursor':'next'}}])


def test_absent_cursor_still_marks_final_page():
    c=codes([{'id':1,'method':'tools/list'},{'id':1,'result':{'tools':[]}}])
    assert not c & {'UNUSABLE_CURSOR','PAGINATION_INCOMPLETE'}


@pytest.mark.parametrize('tools',[1,True,'bad',{}])
def test_malformed_tools_page_cannot_crash_cursor_analysis(tools):
    assert 'PAGINATION_INCOMPLETE' in codes([
        {'id':1,'method':'tools/list'},
        {'id':1,'result':{'tools':tools,'nextCursor':'next'}}])


@pytest.mark.parametrize('mode',['text','json'])
def test_cli_bad_cursor_retains_redacted_evidence(tmp_path,capsys,mode):
    from mcptriage.cli import main
    p=tmp_path/'capture.jsonl'
    p.write_text(json.dumps({'id':1,'method':'tools/list','params':{'cursor':{'token':'private-marker'}}}))
    assert main(['diagnose',str(p),'--format',mode])==1
    out=capsys.readouterr()
    assert 'UNUSABLE_CURSOR' in out.out
    assert 'private-marker' not in out.out
    assert 'Traceback' not in out.err
