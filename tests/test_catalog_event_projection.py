"""Catalog lookup work should depend on catalog traffic, not unrelated calls."""
import json
import random

import pytest

from mcptriage.rules import _DiagnosisSession, diagnose
from mcptriage.transcript import Session, parse_text


def parsed(rows):
    return parse_text('\n'.join(map(json.dumps, rows)))


class Counted(list):
    def __init__(self, values):
        super().__init__(values)
        self.visited = 0

    def __iter__(self):
        for value in super().__iter__():
            self.visited += 1
            yield value


def traffic(calls):
    rows = []
    for epoch in range(12):
        rows += [{'id': f'list{epoch}', 'method':'tools/list'},
                 {'id': f'list{epoch}', 'result':{'tools':[{'name':'x','inputSchema':{'required':['value']}}]}}]
        for i in range(calls):
            rid = f'call{epoch}-{i}'
            rows += [{'id':rid,'method':'tools/call','params':{'name':'x','arguments':{}}},
                     {'id':rid,'error':{'code':-32602}}]
    return parsed(rows)


def test_catalog_snapshots_do_not_rescan_unrelated_call_traffic():
    session = traffic(30)
    session.messages = Counted(session.messages)
    view = _DiagnosisSession(session)
    session.messages.visited = 0
    calls = session.requests('tools/call')
    session.messages.visited = 0
    for call in calls:
        assert view.tools_by_name(call.line_no) == {'x':{'required':['value']}}
    assert session.messages.visited == 0


@pytest.mark.parametrize('seed',range(5))
def test_projection_matches_original_catalog_at_every_cutoff(seed):
    rng = random.Random(seed)
    rows = []
    for i in range(80):
        identifier = rng.choice([1,2,'1','list','call'])
        kind = rng.randrange(7)
        if kind == 0:
            rows.append({'id':identifier,'method':'tools/list','params':rng.choice([{}, {'cursor':'next'}])})
        elif kind == 1:
            rows.append({'id':identifier,'result':{'tools':[{'name':rng.choice(['x','y']),'inputSchema':{'required':[str(i)]}}], 'nextCursor':'next'}})
        elif kind == 2:
            rows.append({'method':'notifications/tools/list_changed'})
        elif kind == 3:
            rows.append({'id':identifier,'method':'initialize'})
        elif kind == 4:
            rows.append({'id':identifier,'method':'tools/call','params':{'name':'x','arguments':{}}})
        elif kind == 5:
            rows.append({'id':identifier,'error':{'code':-32602}})
        else:
            rows.append({'id':identifier,'result':{'content':[]}})
    session = parsed(rows)
    view = _DiagnosisSession(session)
    # Nonmonotonic lookups must not reuse a snapshot from the wrong epoch.
    cutoffs = list(range(1,len(rows)+2)) + [None]
    rng.shuffle(cutoffs)
    for cutoff in cutoffs:
        assert view.tools_by_name(cutoff) == session.tools_by_name(cutoff)


def test_valid_pages_refresh_and_collision_keep_each_historical_snapshot():
    rows = [
        {'id':1,'method':'tools/list'},
        {'id':1,'result':{'tools':[{'name':'x','inputSchema':{'required':['old']}}], 'nextCursor':'next'}},
        {'id':90,'method':'tools/call','params':{'name':'x','arguments':{}}},
        {'id':90,'error':{'code':-32602}},
        {'id':2,'method':'tools/list','params':{'cursor':'next'}},
        {'id':2,'result':{'tools':[{'name':'x','inputSchema':{'required':['collision']}}]}},
        {'id':91,'method':'tools/call','params':{'name':'x','arguments':{}}},
        {'id':91,'error':{'code':-32602}},
        {'method':'notifications/tools/list_changed'},
        {'id':3,'method':'tools/list'},
        {'id':3,'result':{'tools':[{'name':'x','inputSchema':{'required':['new']}}]}},
        {'id':92,'method':'tools/call','params':{'name':'x','arguments':{}}},
        {'id':92,'error':{'code':-32602}},
    ]
    session = parsed(rows)
    view = _DiagnosisSession(session)
    assert view.tools_by_name(3) == {'x':{'required':['old']}}
    assert view.tools_by_name(7) == {}
    assert view.tools_by_name(12) == {'x':{'required':['new']}}
    for cutoff in [None] + list(range(15,0,-1)):
        assert view.tools_by_name(cutoff) == session.tools_by_name(cutoff)


@pytest.mark.parametrize('other', [
    {'id':1,'method':'tools/call'},
    {'id':1,'method':'ping'},
    {'id':1,'result':None},
    {'id':1,'error':{'code':-32603}},
    {'id':1,'result':{},'error':{'code':-32603}},
])
def test_projection_retains_nonlist_traffic_that_can_change_ownership(other):
    rows = [{'id':1,'method':'tools/list'}, other,
            {'id':1,'result':{'tools':[{'name':'x','inputSchema':{'required':['x']}}]}}]
    session = parsed(rows)
    view = _DiagnosisSession(session)
    assert view.tools_by_name() == session.tools_by_name() == {}


def test_new_diagnosis_sees_caller_mutation_without_stale_projection():
    session = traffic(1)
    first = diagnose(session)
    session.messages[:] = parsed([{'id':1,'method':'tools/list'},
                                  {'id':1,'result':{'tools':[]}}]).messages
    assert diagnose(session) != first
    assert any(f.code == 'EMPTY_TOOLS_LIST' for f in diagnose(session))
