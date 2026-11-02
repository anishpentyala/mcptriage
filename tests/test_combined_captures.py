"""Synthetic, mixed captures exercise interactions rather than new diagnoses."""
import json
import pytest
from mcptriage.cli import main


def lines(rows):
    return '\n'.join(json.dumps(x) for x in rows)

def opening():
    return [{'id':0,'method':'initialize','params':{'protocolVersion':'2025-11-25'}},
            {'id':0,'result':{'protocolVersion':'2025-11-25','capabilities':{'tools':{}}}},
            {'method':'notifications/initialized'}]

@pytest.mark.parametrize('mode',['text','json'])
def test_mixed_capture_preserves_independent_diagnoses_and_masks(tmp_path,capsys,mode):
    rows=opening()+[
      {'id':401,'method':'tools/list'},
      {'id':401,'error':{'code':-32603,'message':'handler failed'}},
      {'id':2,'method':'tools/list'},
      {'id':2,'result':{'tools':[{'name':'x','inputSchema':{'type':'object','required':['city']}}]}},
      {'id':3,'method':'tools/call','params':{'name':'x','arguments':{}}},
      {'id':3,'error':{'code':-32602,'message':'bad params','data':{'token':'SYNTHETIC_SECRET'}}},
      {'id':4,'method':'tools/list'},
      {'id':4,'result':{'tools':None}},
      {'id':5,'method':'tools/list'},
    ]
    p=tmp_path/'mixed.jsonl';p.write_text(lines(rows))
    assert main(['diagnose',str(p),'--format',mode])==1
    out=capsys.readouterr().out
    for code in ['TOOLS_LIST_ERROR','TOOL_CALL_ARG_MISMATCH','UNUSABLE_TOOLS_CATALOG','TOOLS_LIST_HANG']:
        assert code in out
    assert 'AUTH_ON_LIST' not in out
    assert 'SYNTHETIC_SECRET' not in out
    assert "missing required argument 'city'" in out

@pytest.mark.parametrize('mode',['text','json'])
def test_large_clean_capture_has_no_false_diagnoses(tmp_path,capsys,mode):
    rows=opening()
    for i in range(1,501):
        rows.extend([{'id':i,'method':'tools/list'},
          {'id':i,'result':{'tools':[{'name':'x','inputSchema':{'type':'object'}}]}}])
    p=tmp_path/'healthy.jsonl';p.write_text(lines(rows))
    assert main(['diagnose',str(p),'--format',mode])==0
    out=capsys.readouterr().out
    if mode=='json':assert json.loads(out)['findings']==[]
    else:assert 'no problems found' in out

@pytest.mark.parametrize('mode',['text','json'])
def test_decoder_failure_between_valid_messages_keeps_later_hang(tmp_path,capsys,mode,rejected_nesting_depth):
    p=tmp_path/'damaged.jsonl'
    p.write_text(lines(opening())+'\n'+'['*rejected_nesting_depth+'0'+']'*rejected_nesting_depth+'\n'+
                 '{"id":401,"method":"tools/list"}')
    assert main(['diagnose',str(p),'--format',mode])==1
    out=capsys.readouterr().out
    assert 'TOOLS_LIST_HANG' in out
    assert 'STDIO_POLLUTION' in out
    assert 'NO_PROTOCOL_MESSAGES' not in out
