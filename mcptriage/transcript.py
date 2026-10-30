"""Parse captured MCP JSON-RPC traffic into a Session model.

Input is a line-oriented log: client MCP log channels, proxy dumps, or a
hand-saved .jsonl file. Lines may be bare JSON-RPC objects or log lines with
a JSON object embedded after a prefix (timestamps, channel tags). Lines with
no JSON object are kept as unparsed evidence - on a stdio transport they are
often the bug (a server printing to stdout corrupts the protocol stream).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

_REQUEST = "request"
_NOTIFICATION = "notification"
_RESPONSE = "response"
_UNPARSED = "unparsed"

_BRACE = re.compile(r"\{")


def _classify(obj: Any):
    """Return (kind, method, msg_id) for a parsed JSON value."""
    if not isinstance(obj, dict):
        return _UNPARSED, None, None
    method = obj.get("method")
    has_id = "id" in obj and obj.get("id") is not None
    if method is not None and has_id:
        return _REQUEST, method, obj.get("id")
    if method is not None:
        return _NOTIFICATION, method, None
    if has_id and ("result" in obj or "error" in obj):
        return _RESPONSE, None, obj.get("id")
    return _UNPARSED, None, None


@dataclass
class Message:
    line_no: int
    raw: str
    obj: Optional[Any]
    kind: str
    method: Optional[str] = None
    msg_id: Optional[Any] = None
    extracted: bool = False  # JSON was embedded inside a larger log line

    def error(self) -> Optional[Dict[str, Any]]:
        if self.kind == _RESPONSE and isinstance(self.obj, dict):
            err = self.obj.get("error")
            if isinstance(err, dict):
                return err
        return None

    def result(self) -> Optional[Any]:
        if self.kind == _RESPONSE and isinstance(self.obj, dict):
            return self.obj.get("result")
        return None


@dataclass
class Session:
    messages: List[Message] = field(default_factory=list)

    @property
    def parsed(self) -> List[Message]:
        return [m for m in self.messages if m.kind != _UNPARSED]

    @property
    def unparsed(self) -> List[Message]:
        return [m for m in self.messages if m.kind == _UNPARSED]

    def requests(self, method: Optional[str] = None) -> List[Message]:
        out = []
        for m in self.parsed:
            if m.kind == _REQUEST and (method is None or m.method == method):
                out.append(m)
        return out

    def notifications(self, method: Optional[str] = None) -> List[Message]:
        out = []
        for m in self.parsed:
            if m.kind == _NOTIFICATION and (method is None or m.method == method):
                out.append(m)
        return out

    def response_for(self, request: Message) -> Optional[Message]:
        """The first response after `request` carrying its id."""
        for m in self.messages:
            if m.line_no <= request.line_no:
                continue
            if m.kind == _RESPONSE and m.msg_id == request.msg_id:
                return m
        return None

    def orphan_responses(self) -> List[Message]:
        """Responses whose id no earlier request claims."""
        seen = set()
        orphans = []
        for m in self.messages:
            if m.kind == _REQUEST:
                seen.add(m.msg_id)
            elif m.kind == _RESPONSE and m.msg_id not in seen:
                orphans.append(m)
        return orphans

    def tools_by_name(self, before_line: Optional[int] = None) -> Dict[str, Dict[str, Any]]:
        """Tool name -> inputSchema from tools/list results seen so far."""
        tools: Dict[str, Dict[str, Any]] = {}
        for m in self.messages:
            if before_line is not None and m.line_no >= before_line:
                break
            if m.kind != _RESPONSE:
                continue
            result = m.result()
            if isinstance(result, dict) and isinstance(result.get("tools"), list):
                for t in result["tools"]:
                    if isinstance(t, dict) and isinstance(t.get("name"), str):
                        schema = t.get("inputSchema")
                        tools[t["name"]] = schema if isinstance(schema, dict) else {}
        return tools

    def has_modern_markers(self) -> bool:
        """True if any message carries 2026-era protocol markers."""
        for m in self.parsed:
            if m.method == "server/discover":
                return True
            if isinstance(m.obj, dict):
                meta = None
                params = m.obj.get("params")
                if isinstance(params, dict) and isinstance(params.get("_meta"), dict):
                    meta = params["_meta"]
                elif isinstance(m.obj.get("_meta"), dict):
                    meta = m.obj["_meta"]
                if meta and "protocolVersion" in meta:
                    return True
        return False


def parse_text(text: str) -> Session:
    session = Session()
    decoder = json.JSONDecoder()
    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        obj = None
        extracted = False
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            for match in _BRACE.finditer(line):
                try:
                    obj, _end = decoder.raw_decode(line[match.start():])
                    extracted = True
                    break
                except json.JSONDecodeError:
                    continue
        if obj is None:
            session.messages.append(Message(line_no, raw_line.rstrip("\n"), None, _UNPARSED))
            continue
        kind, method, msg_id = _classify(obj)
        if kind == _UNPARSED:
            session.messages.append(Message(line_no, raw_line.rstrip("\n"), None, _UNPARSED))
        else:
            session.messages.append(
                Message(line_no, raw_line.rstrip("\n"), obj, kind, method, msg_id, extracted)
            )
    return session


def parse_file(path: str) -> Session:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return parse_text(fh.read())
