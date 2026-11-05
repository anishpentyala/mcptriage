"""A linked catalog cannot choose duplicate definitions by page order."""
import copy
import json
import pytest
from mcptriage.rules import diagnose
from mcptriage.transcript import parse_text


def tool(name, required):
    return {'name': name, 'inputSchema': {'required': [required]}}


def page(identifier, tools, cursor=None, next_cursor=None):
    req = {'id': identifier, 'method': 'tools/list'}
    if cursor is not None:
        req['params'] = {'cursor': cursor}
    result = {'tools': tools}
    if next_cursor is not None:
        result['nextCursor'] = next_cursor
    return [req, {'id': identifier, 'result': result}]


def call(identifier=90, name='x'):
    return [{'id': identifier, 'method': 'tools/call', 'params': {'name': name, 'arguments': {}}},
            {'id': identifier, 'error': {'code': -32602}}]


def session(rows):
    return parse_text('\n'.join(map(json.dumps, rows)))


def chain(first='first', second='second'):
    return (page(1, [tool('x', first), tool('safe', 'ok')], next_cursor='next')
            + page(2, [tool('x', second), tool('other', 'other')], cursor='next', next_cursor='last'))


@pytest.mark.parametrize('first,second', [('first', 'second'), ('second', 'first'), ('same', 'same')])
def test_linked_duplicate_cannot_choose_a_schema(first, second):
    s = session(chain(first, second) + call() + call(91, 'safe'))
    old = copy.deepcopy(s.messages)
    assert set(s.tools_by_name()) == {'safe', 'other'}
    findings = diagnose(s)
    duplicate = [f for f in findings if f.code == 'DUPLICATE_CATALOG_PAGE_NAMES']
    assert len(duplicate) == 1 and duplicate[0].evidence.startswith('line 4:')
    x = next(f for f in findings if f.code == 'TOOL_CALL_ARG_MISMATCH' and "'x'" in f.title)
    safe = next(f for f in findings if f.code == 'TOOL_CALL_ARG_MISMATCH' and "'safe'" in f.title)
    assert 'missing required' not in x.why
    assert "missing required argument 'ok'" in safe.why
    assert s.messages == old


def test_third_page_cannot_resurrect_ambiguous_name():
    s = session(chain() + page(3, [tool('x', 'third')], cursor='last') + call())
    assert 'x' not in s.tools_by_name()
    assert len([f for f in diagnose(s) if f.code == 'DUPLICATE_CATALOG_PAGE_NAMES']) == 2


def test_same_page_duplicate_stays_unusable_on_later_page():
    rows = page(1, [tool('x', 'a'), tool('x', 'b')], next_cursor='next')
    rows += page(2, [tool('x', 'c')], cursor='next')
    assert 'x' not in session(rows).tools_by_name()


@pytest.mark.parametrize('boundary', [page(3, [tool('x', 'new')]),
                                    [{'method': 'notifications/tools/list_changed'}] + page(3, [tool('x', 'new')]),
                                    [{'id': 4, 'method': 'initialize'}] + page(3, [tool('x', 'new')])])
def test_new_catalog_recovers_after_ambiguity(boundary):
    s = session(chain() + boundary + call())
    assert s.tools_by_name() == {'x': {'required': ['new']}}
    finding = next(f for f in diagnose(s) if f.code == 'TOOL_CALL_ARG_MISMATCH')
    assert "missing required argument 'new'" in finding.why


def test_future_collision_does_not_rewrite_earlier_call():
    rows = page(1, [tool('x', 'first')], next_cursor='next') + call()
    rows += page(2, [tool('x', 'second')], cursor='next') + call(91)
    findings = [f for f in diagnose(session(rows)) if f.code == 'TOOL_CALL_ARG_MISMATCH']
    assert "missing required argument 'first'" in findings[0].why
    assert 'missing required' not in findings[1].why


@pytest.mark.parametrize('rows', [
    page(1, [tool('x', 'a')]) + page(2, [tool('x', 'b')]),
    page(1, [tool('x', 'a')], next_cursor='next') + page(2, [tool('x', 'b')], cursor='wrong'),
    page(1, [tool('x', 'a')], next_cursor='next') + [{'method': 'notifications/tools/list_changed'}] + page(2, [tool('x', 'b')], cursor='next'),
    page(1, [tool('x', 'a')], next_cursor='next') + page(2, [tool('X', 'b')], cursor='next'),
])
def test_separate_unlinked_or_case_distinct_pages_not_called_collision(rows):
    assert not any(f.code == 'DUPLICATE_CATALOG_PAGE_NAMES' for f in diagnose(session(rows)))


def test_collision_count_is_names_not_number_of_extra_entries():
    rows = page(1, [tool('x', 'a')], next_cursor='next')
    rows += page(2, [tool('x', 'b'), tool('x', 'c')], cursor='next')
    findings = [f for f in diagnose(session(rows)) if f.code == 'DUPLICATE_CATALOG_PAGE_NAMES']
    assert len(findings) == 1
    assert 'repeats 1 earlier tool name(s)' in findings[0].title


@pytest.mark.parametrize('fmt', ['text', 'json'])
def test_cli_reports_observed_collision_without_schema_guess(tmp_path, capsys, fmt):
    from mcptriage.cli import main
    path = tmp_path / 'capture.jsonl'; path.write_text('\n'.join(map(json.dumps, chain() + call())))
    assert main(['diagnose', str(path), '--format', fmt]) == 1
    out = capsys.readouterr()
    assert 'DUPLICATE_CATALOG_PAGE_NAMES' in out.out and 'missing required' not in out.out
    assert not out.err


@pytest.mark.parametrize('bad_reply', [
    {'error': {'code': -32603}}, {'result': {'tools': None}},
    {'result': {'tools': [tool('x', 'bad')]}, 'error': {'code': -32603}},
])
def test_failed_page_does_not_create_collision_or_consume_cursor(bad_reply):
    rows = page(1, [tool('x', 'first')], next_cursor='next')
    rows += [{'id': 2, 'method': 'tools/list', 'params': {'cursor': 'next'}}, dict(id=2, **bad_reply)]
    rows += page(3, [tool('safe', 'ok')], cursor='next')
    s = session(rows)
    assert set(s.tools_by_name()) == {'x', 'safe'}
    assert not any(f.code == 'DUPLICATE_CATALOG_PAGE_NAMES' for f in diagnose(s))


def test_empty_string_cursor_still_links_duplicate_evidence():
    rows = page(1, [tool('x', 'first')], next_cursor='')
    rows += page(2, [tool('x', 'second')], cursor='')
    assert 'x' not in session(rows).tools_by_name()
    assert any(f.code == 'DUPLICATE_CATALOG_PAGE_NAMES' for f in diagnose(session(rows)))


def test_speculative_page_before_advertisement_is_not_collision_evidence():
    first = page(1, [tool('x', 'first')], next_cursor='next')
    second = page(2, [tool('x', 'second')], cursor='next')
    rows = [first[0], second[0], first[1], second[1]]
    s = session(rows)
    assert s.tools_by_name() == {'x': {'required': ['first']}}
    assert not any(f.code == 'DUPLICATE_CATALOG_PAGE_NAMES' for f in diagnose(s))


def test_catalog_cache_boundary_keeps_call_before_and_after_collision_separate():
    rows = page(1, [tool('x', 'first')], next_cursor='next')
    rows += call(90) + call(91)
    rows += page(2, [tool('x', 'second')], cursor='next')
    rows += call(92) + call(93)
    findings = [f for f in diagnose(session(rows)) if f.code == 'TOOL_CALL_ARG_MISMATCH']
    assert len(findings) == 4
    assert all('first' in f.why for f in findings[:2])
    assert all('missing required' not in f.why for f in findings[2:])
