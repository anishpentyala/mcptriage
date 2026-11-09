"""Captured cancellation is not proof of server acceptance or of a hang."""
import copy
import json
import subprocess
import sys

import pytest

from mcptriage.rules import diagnose, HIGH
from mcptriage.transcript import parse_text
from mcptriage.report import render_json, render_text

OPEN = [
    {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize'},
    {'jsonrpc': '2.0', 'id': 1, 'result': {'capabilities': {'tools': {}}}},
    {'jsonrpc': '2.0', 'method': 'notifications/initialized'},
]
LIST = {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list'}
CANCEL = {'jsonrpc': '2.0', 'method': 'notifications/cancelled', 'params': {'requestId': 2}}
CODE = 'TOOLS_LIST_CANCELLATION_OBSERVED'


def findings(*rows):
    return diagnose(parse_text('\n'.join(json.dumps(r) for r in OPEN + list(rows))))


def codes(items):
    return [f.code for f in items]


def test_cancelled_list_is_interruption_evidence_not_server_hang():
    result = findings(LIST, CANCEL)
    assert codes(result) == [CODE]
    assert result[0].severity == 'medium'
    assert 'line 4' in result[0].evidence and 'line 5' in result[0].evidence
    assert 'does not prove receiver acceptance' in result[0].why
    assert not any(f.severity == HIGH for f in result)


def test_plain_missing_list_response_stays_high_without_claiming_a_cause():
    result = findings(LIST)
    assert codes(result) == ['TOOLS_LIST_HANG'] and result[0].severity == HIGH
    assert 'does not establish a cause' in result[0].why


@pytest.mark.parametrize('bad', [None, True, False, [], {}, 2.5, '2', 3])
def test_invalid_or_wrong_typed_id_cannot_waive_hang(bad):
    cancel = copy.deepcopy(CANCEL)
    cancel['params']['requestId'] = bad
    assert codes(findings(LIST, cancel)) == ['TOOLS_LIST_HANG']


@pytest.mark.parametrize('params', [None, [], 'text', {}, {'requestId': 2, 'reason': 5},
                                  {'requestId': 2, '_meta': True}])
def test_malformed_params_cannot_waive_hang(params):
    cancel = {**CANCEL, 'params': params}
    assert codes(findings(LIST, cancel)) == ['TOOLS_LIST_HANG']


@pytest.mark.parametrize('change', [{'id': 5}, {'id': None}, {'result': {}}, {'error': {}},
                                    {'jsonrpc': '1.0'}, {'method': None}])
def test_nonnotification_or_conflicting_envelope_cannot_waive_hang(change):
    result = findings(LIST, {**CANCEL, **change})
    assert CODE not in codes(result) and 'TOOLS_LIST_HANG' in codes(result)


def test_missing_rpc_version_is_not_enough_cancellation_evidence():
    cancel = copy.deepcopy(CANCEL)
    del cancel['jsonrpc']
    assert codes(findings(LIST, cancel)) == ['TOOLS_LIST_HANG']


@pytest.mark.parametrize('ident', [0, -5, '', 'abc', 9007199254740993])
def test_exact_string_and_large_integer_request_ids(ident):
    request = {**LIST, 'id': ident}
    cancel = {**CANCEL, 'params': {'requestId': ident}}
    assert codes(findings(request, cancel)) == [CODE]


@pytest.mark.parametrize('wire', ['2.0', '2e0'])
def test_integral_numeric_wire_id_is_exact(wire):
    text = '\n'.join(map(json.dumps, OPEN + [LIST])) + '\n' + (
        '{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":' + wire + '}}')
    assert codes(diagnose(parse_text(text))) == [CODE]


@pytest.mark.parametrize('wire', ['2.0000000000000001', '2e9999999999999999999999'])
def test_rounded_or_extreme_wire_id_cannot_alias_request(wire):
    text = '\n'.join(map(json.dumps, OPEN + [LIST])) + '\n' + (
        '{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":' + wire + '}}')
    assert codes(diagnose(parse_text(text))) == ['TOOLS_LIST_HANG']


def test_notification_before_request_is_not_its_cancellation():
    assert codes(findings(CANCEL, LIST)) == ['TOOLS_LIST_HANG']


def test_id_reuse_after_completed_request_does_not_inherit_old_cancel():
    reply = {'jsonrpc': '2.0', 'id': 2, 'result': {'tools': []}}
    result = findings(LIST, CANCEL, reply, LIST)
    assert CODE not in codes(result)
    assert codes(result).count('TOOLS_LIST_HANG') == 1
    assert codes(result).count('EMPTY_TOOLS_LIST') == 1


@pytest.mark.parametrize('rows', [[LIST, LIST, CANCEL], [LIST, CANCEL, LIST]])
def test_overlap_never_chooses_a_cancellation_owner(rows):
    result = findings(*rows)
    assert CODE not in codes(result)
    assert codes(result).count('TOOLS_LIST_HANG') == 2
    assert 'DIRECTION_AMBIGUOUS' in codes(result)


def test_other_method_reusing_pending_id_invalidates_old_cancel():
    result = findings(LIST, CANCEL, {**LIST, 'method': 'ping'})
    assert CODE not in codes(result) and 'TOOLS_LIST_HANG' in codes(result)


def test_bidirectional_capture_does_not_attribute_cancel_to_a_side():
    result = findings(LIST, {'jsonrpc': '2.0', 'id': 's', 'method': 'roots/list'}, CANCEL)
    assert CODE not in codes(result) and 'TOOLS_LIST_HANG' in codes(result)
    assert 'DIRECTION_AMBIGUOUS' in codes(result)


def test_new_initialize_does_not_use_previous_epoch_request_for_cancel():
    result = findings(LIST, {'jsonrpc': '2.0', 'id': 'new', 'method': 'initialize'}, CANCEL)
    assert CODE not in codes(result) and 'TOOLS_LIST_HANG' in codes(result)


def test_task_augmented_request_does_not_use_notification_cancellation():
    result = findings({**LIST, 'params': {'task': {}}}, CANCEL)
    assert CODE not in codes(result) and 'TOOLS_LIST_HANG' in codes(result)


@pytest.mark.parametrize('after', [True, False])
def test_response_race_keeps_existing_response_diagnosis(after):
    reply = {'jsonrpc': '2.0', 'id': 2, 'result': {'tools': []}}
    result = findings(LIST, *( [CANCEL, reply] if after else [reply, CANCEL]))
    assert codes(result) == ['EMPTY_TOOLS_LIST']


def test_one_cancel_does_not_weaken_unrelated_unanswered_request():
    result = findings(LIST, {**LIST, 'id': 3}, CANCEL)
    assert sorted(codes(result)) == sorted([CODE, 'TOOLS_LIST_HANG'])
    assert next(f for f in result if f.code == 'TOOLS_LIST_HANG').severity == HIGH


def test_reason_payload_is_not_copied_to_either_report():
    cancel = {**CANCEL, 'params': {'requestId': 2, 'reason': 'PRIVATE reason without a key=value pattern'}}
    result = findings(LIST, cancel)
    assert codes(result) == [CODE]
    assert 'PRIVATE' not in render_json(result, 'synthetic')
    assert 'PRIVATE' not in render_text(result, 'synthetic')


def test_repeated_cancel_is_one_observation_without_mutating_session():
    session = parse_text('\n'.join(map(json.dumps, OPEN + [LIST, CANCEL, CANCEL])))
    before = copy.deepcopy(session)
    assert codes(diagnose(session)) == [CODE]
    assert session == before
    assert codes(diagnose(session)) == [CODE]


def test_cli_cancelled_capture_no_longer_exits_for_high_hang(tmp_path):
    path = tmp_path / 'capture.jsonl'
    path.write_text('\n'.join(map(json.dumps, OPEN + [LIST, CANCEL])), encoding='utf-8')
    p = subprocess.run([sys.executable, '-m', 'mcptriage', 'diagnose', str(path), '--format', 'json'],
                       capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    assert [f['code'] for f in json.loads(p.stdout)['findings']] == [CODE]


def test_cancelled_list_index_has_linear_transcript_visit_budget():
    class Counted(list):
        visited = 0
        def __iter__(self):
            for item in super().__iter__():
                self.visited += 1
                yield item
    def measure(n):
        rows = list(OPEN)
        for ident in range(10, 10 + n):
            rows.extend([{**LIST, 'id': ident},
                         {**CANCEL, 'params': {'requestId': ident}}])
        session = parse_text('\n'.join(map(json.dumps, rows)))
        session.messages = Counted(session.messages)
        result = diagnose(session)
        assert codes(result) == [CODE] * n
        return session.messages.visited
    assert measure(160) <= 5 * measure(40)
