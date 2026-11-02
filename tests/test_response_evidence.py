"""Only a unique outstanding request can claim a chronological response."""
import json
import pytest
from mcptriage.transcript import parse_text
from mcptriage.rules import diagnose


def session(*rows):
    return parse_text('\n'.join(json.dumps(row) for row in rows))


@pytest.mark.parametrize('identifier',[0,1,'1',1.0])
@pytest.mark.parametrize('payload',[{'result':{'tools':[]}}, {'error':{'code':-32603}}])
def test_sequential_id_reuse_does_not_answer_later_request(identifier,payload):
    s=session({'id':identifier,'method':'tools/list'},dict(id=identifier,**payload),
              {'id':identifier,'method':'tools/list'})
    a,b=s.requests()
    assert s.response_for(a).line_no==2
    assert s.response_for(b) is None
    hangs=[f for f in diagnose(s) if f.code=='TOOLS_LIST_HANG']
    assert len(hangs)==1 and 'line 3:' in hangs[0].evidence


@pytest.mark.parametrize('identifier',[0,1,'1',1.0])
def test_orphan_before_request_is_not_answer(identifier):
    s=session({'id':identifier,'result':{'tools':[]}},
              {'id':identifier,'method':'tools/list'})
    assert s.response_for(s.requests()[0]) is None
    assert any(f.code=='TOOLS_LIST_HANG' for f in diagnose(s))


@pytest.mark.parametrize('methods',[('tools/list','tools/list'),('initialize','tools/list'),
                                    ('tools/call','tools/list'),('resources/list','tools/list')])
@pytest.mark.parametrize('payload',[{'result':{'tools':[]}}, {'error':{'code':-32603}}])
def test_overlapping_id_requests_do_not_claim_shared_response(methods,payload):
    s=session({'id':7,'method':methods[0]}, {'id':7,'method':methods[1]},dict(id=7,**payload))
    assert all(s.response_for(req) is None for req in s.requests())
    codes={f.code for f in diagnose(s)}
    assert 'DIRECTION_AMBIGUOUS' in codes
    assert not codes & {'EMPTY_TOOLS_LIST','TOOLS_LIST_ERROR','MISSING_TOOLS_CAPABILITY'}


@pytest.mark.parametrize('identifier',[0,1,'1',1.0])
def test_overlap_taints_later_same_id_exchange(identifier):
    s=session({'id':identifier,'method':'tools/list'}, {'id':identifier,'method':'resources/list'},
              {'id':identifier,'result':{}}, {'id':identifier,'method':'tools/list'},
              {'id':identifier,'result':{'tools':[]}})
    a,b,c=s.requests()
    assert s.response_for(a) is None and s.response_for(b) is None
    assert s.response_for(c) is None


@pytest.mark.parametrize('request_id,response_id',[(1,'1'),('1',1)])
def test_typed_id_mismatch_stays_unanswered(request_id,response_id):
    s=session({'id':request_id,'method':'tools/list'}, {'id':response_id,'result':{'tools':[]}})
    assert s.response_for(s.requests()[0]) is None
    assert any(f.code=='TOOLS_LIST_HANG' for f in diagnose(s))


@pytest.mark.parametrize('identifier',[0,1,'1',1.0])
def test_unique_interleaved_requests_keep_correct_responses(identifier):
    s=session({'id':identifier,'method':'tools/list'}, {'id':'other','method':'resources/list'},
              {'id':'other','result':{}}, {'id':identifier,'result':{'tools':[]}})
    assert s.response_for(s.requests()[0]).line_no==4
    assert s.response_for(s.requests()[1]).line_no==3
    assert not any(f.code=='TOOLS_LIST_HANG' for f in diagnose(s))


def test_later_overlap_does_not_rewrite_prior_completed_pair():
    s=session({'id':1,'method':'tools/list'}, {'id':1,'result':{'tools':[]}},
              {'id':1,'method':'tools/list'}, {'id':1,'method':'resources/list'},
              {'id':1,'result':{}})
    a,b,c=s.requests()
    assert s.response_for(a).line_no==2
    assert s.response_for(b) is None and s.response_for(c) is None


def test_ambiguous_id_does_not_drop_other_ids_pair():
    s=session({'id':1,'method':'tools/list'}, {'id':1,'method':'resources/list'},
              {'id':2,'method':'tools/list'}, {'id':1,'result':{}},
              {'id':2,'result':{'tools':[]}})
    assert s.response_for(s.requests()[2]).line_no==5


def test_number_and_string_ids_can_be_open_at_same_time():
    s=session({'id':1,'method':'tools/list'}, {'id':'1','method':'tools/list'},
              {'id':'1','result':{'tools':[]}}, {'id':1,'result':{'tools':[]}})
    assert s.response_for(s.requests()[0]).line_no==4
    assert s.response_for(s.requests()[1]).line_no==3
    assert not any(f.code in ('DIRECTION_AMBIGUOUS','TOOLS_LIST_HANG') for f in diagnose(s))
