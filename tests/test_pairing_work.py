"""Deterministic transcript-iteration budget, not a wall-clock speed assertion."""
import json
from mcptriage.transcript import parse_text
from mcptriage.rules import diagnose

class CountedMessages(list):
    def __init__(self, messages):
        super().__init__(messages)
        self.visited = 0
    def __iter__(self):
        for message in super().__iter__():
            self.visited += 1
            yield message

def measured(n):
    rows=[{'id':0,'method':'initialize'},
          {'id':0,'result':{'capabilities':{'tools':{}}}},
          {'method':'notifications/initialized'}]
    for i in range(1,n+1):
        rows.extend([{'id':i,'method':'tools/list'},{'id':i,'result':{'tools':[]}}])
    session=parse_text('\n'.join(json.dumps(r) for r in rows))
    session.messages=CountedMessages(session.messages)
    findings=diagnose(session)
    assert len(findings)==n
    assert all(f.code=='EMPTY_TOOLS_LIST' for f in findings)
    return session.messages.visited

def test_list_diagnosis_does_not_rescan_for_every_response():
    small=measured(40)
    large=measured(160)
    assert large <= 5*small

def test_response_identity_not_dataclass_equality():
    from mcptriage.transcript import Message
    session=parse_text('{"id":1,"method":"tools/list"}\n{"id":1,"result":{"tools":[]}}')
    request=session.requests()[0]
    clone=Message(**vars(request))
    assert clone==request
    assert session.response_for(clone) is None
    assert session.response_for(request).line_no==2

def test_no_stale_cache_after_appending_response():
    session=parse_text('{"id":1,"method":"tools/list"}')
    req=session.requests()[0]
    assert session.response_for(req) is None
    response=parse_text('{"id":1,"result":{"tools":[]}}').messages[0]
    response.line_no=2
    session.messages.append(response)
    assert session.response_for(req) is response
    assert not any(f.code=='TOOLS_LIST_HANG' for f in diagnose(session))
    session.messages.pop()
    assert session.response_for(req) is None
    assert any(f.code=='TOOLS_LIST_HANG' for f in diagnose(session))

def test_earlier_completed_pair_survives_later_overlap():
    session=parse_text('{"id":1,"method":"tools/list"}\n{"id":1,"result":{"tools":[]}}\n'
                       '{"id":1,"method":"tools/list"}\n{"id":1,"method":"tools/list"}\n'
                       '{"id":1,"result":{"tools":[]}}')
    requests=session.requests()
    assert session.response_for(requests[0]).line_no==2
    assert session.response_for(requests[1]) is None
    assert session.response_for(requests[2]) is None
    findings=diagnose(session)
    assert sum(f.code=='TOOLS_LIST_HANG' for f in findings)==2
    assert sum(f.code=='EMPTY_TOOLS_LIST' for f in findings)==1

def test_same_typed_sequential_requests_keep_own_response():
    session=parse_text('{"id":1,"method":"tools/list"}\n{"id":1,"result":{"tools":[]}}\n'
                       '{"id":1,"method":"tools/list"}\n{"id":1,"result":{"tools":[{"name":"x","inputSchema":{}}]}}')
    assert [session.response_for(r).line_no for r in session.requests()]==[2,4]
    assert sum(f.code=='EMPTY_TOOLS_LIST' for f in diagnose(session))==1
