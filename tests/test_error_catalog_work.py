"""Repeated invalid-params calls with unchanged catalog must not rescan it."""
import copy
import json
import pytest
from mcptriage.rules import diagnose, _DiagnosisSession
from mcptriage.transcript import parse_text
from test_call_schema_work import CountedMessages

def rows(n):
 out=[{'id':0,'method':'tools/list'}, {'id':0,'result':{'tools':[{'name':'x','inputSchema':{'required':['x']}}]}}]
 for i in range(1,n+1):
  out += [{'id':i,'method':'tools/call','params':{'name':'x','arguments':{}}}, {'id':i,'error':{'code':-32602}}]
 return out

def measured(n):
 s=parse_text('\n'.join(map(json.dumps,rows(n))));s.messages=CountedMessages(s.messages)
 fs=[f for f in diagnose(s) if f.code=='TOOL_CALL_ARG_MISMATCH'];assert len(fs)==n and all("missing required argument 'x'" in f.why for f in fs)
 return s.messages.visited

def test_unchanged_catalog_invalid_calls_have_bounded_transcript_iterations():
 assert measured(160)<=5*measured(40)

@pytest.mark.parametrize('extra', [
 [{'id':0,'method':'ping'}],
 [{'id':0,'result':{'tools':[{'name':'x','inputSchema':{'required':['new']}}]}}],
 [{'method':'notifications/tools/list_changed'}],
 [{'id':900,'method':'tools/list'},{'id':900,'result':{'tools':[{'name':'x','inputSchema':{'required':['new']}}]}}],
 [{'id':900,'method':'tools/list'},{'id':900,'error':{'code':-32603}}],
])
def test_batched_snapshots_match_uncached_request_time_state(extra):
 capture=rows(3)+extra+rows(3)[2:]
 # Unique call IDs keep this test focused on catalog changes, not call pairing.
 for i,r in enumerate(capture):
  if r.get('method')=='tools/call':r['id']=1000+i;capture[i+1]['id']=r['id']
 s=parse_text('\n'.join(map(json.dumps,capture)));before=copy.deepcopy(s.messages);indexed=_DiagnosisSession(s)
 for call in s.requests('tools/call'):
  assert indexed.tools_by_name(before_line=call.line_no)==s.tools_by_name(before_line=call.line_no)
 assert s.messages==before

def test_index_is_rebuilt_when_caller_mutates_capture_between_diagnoses():
 s=parse_text('\n'.join(map(json.dumps,rows(2))))
 assert all('missing required' in f.why for f in diagnose(s) if f.code=='TOOL_CALL_ARG_MISMATCH')
 change=parse_text('{"method":"notifications/tools/list_changed"}').messages[0]
 change.line_no=3;s.messages.insert(2,change)
 for i,m in enumerate(s.messages,1):m.line_no=i
 assert all('missing required' not in f.why for f in diagnose(s) if f.code=='TOOL_CALL_ARG_MISMATCH')

@pytest.mark.parametrize('seed',range(12))
def test_seeded_catalog_snapshots_equal_uncached_session(seed):
 import random
 rng=random.Random(seed);capture=[]
 for i in range(160):
  identifier=rng.choice([0,1,2,3,'0','1'])
  event=rng.randrange(7)
  if event==0:r={'id':identifier,'method':'tools/list'}
  elif event==1:r={'id':identifier,'method':'ping'}
  elif event==2:r={'id':identifier,'result':{'tools':[{'name':'x','inputSchema':{'required':[str(i)]}}]}}
  elif event==3:r={'id':identifier,'error':{'code':-32603}}
  elif event==4:r={'method':'notifications/tools/list_changed'}
  elif event==5:r={'id':identifier,'method':'tools/call','params':{'name':'x','arguments':{}}}
  else:r={'method':'notifications/resources/list_changed'}
  capture.append(r)
 s=parse_text('\n'.join(map(json.dumps,capture)));indexed=_DiagnosisSession(s)
 # Forward, reverse and random access expose both epoch reuse and changes.
 lines=list(range(1,len(capture)+2))
 for line in lines+lines[::-1]+rng.sample(lines,len(lines)):
  assert indexed.tools_by_name(before_line=line)==s.tools_by_name(before_line=line)
 assert indexed.tools_by_name()==s.tools_by_name()
