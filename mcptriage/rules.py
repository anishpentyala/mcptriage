"""Diagnosis rules over a parsed MCP transcript.

Each rule inspects the Session and returns zero or more Findings with the
evidence line, an explanation of the root cause, and a concrete fix. Rules
are deterministic: same transcript, same findings.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from .transcript import Message, Session

HIGH = "high"
MEDIUM = "medium"
LOW = "low"


@dataclass
class Finding:
    code: str
    severity: str
    title: str
    evidence: str
    why: str
    fix: str


def _clip(text: str, limit: int = 160) -> str:
    text = text.strip()
    return text if len(text) <= limit else text[: limit - 1] + "…"


_401_RE = re.compile(r"\b401\b")


def _looks_auth(err, raw_lower: str) -> bool:
    """True when a JSON-RPC error response carries an authentication rejection.

    JSON-RPC error codes and HTTP status codes are different layers; a 401 here
    is a value the server embedded in the error code, message, or data, not an
    HTTP status line.
    """
    if err.get("code") == 401:
        return True
    return bool(_401_RE.search(raw_lower)) or "unauthorized" in raw_lower or "unauthenticated" in raw_lower


_URL_USERINFO_RE = re.compile(r"(://)[^/@\s:]+:[^/@\s]+@")
_URL_QUERY_RE = re.compile(
    r"([?&](?:api[-_]?key|access[-_]?token|token|secret|password|key|sig|signature|credential)=)[^&\s]+",
    re.IGNORECASE)


_SECRET_JSON_RE = re.compile(
    r'("(?:authorization|api[-_]?key|access[-_]?token|refresh[-_]?token|token|secret|password|client[-_]?secret)"'
    r'\s*:\s*")([^"]+)(")', re.IGNORECASE)
_BEARER_RE = re.compile(r"(bearer\s+)\S+", re.IGNORECASE)
_AUTH_HEADER_RE = re.compile(r"(authorization\s*[:=]\s*)\S+(\s+\S+)?", re.IGNORECASE)


def redact(text: str) -> str:
    """Best-effort masking of credential-looking values before they appear in
    any report. Not a complete sanitizer: unusual formats can slip through, so
    review any log before sharing it."""
    text = _SECRET_JSON_RE.sub(lambda m: m.group(1) + "***" + m.group(3), text)
    text = _BEARER_RE.sub(lambda m: m.group(1) + "***", text)
    text = _AUTH_HEADER_RE.sub(lambda m: m.group(1) + "***", text)
    text = _URL_USERINFO_RE.sub(r"\1***:***@", text)
    text = _URL_QUERY_RE.sub(lambda m: m.group(1) + "***", text)
    return text


def _ev(message: Message) -> str:
    return "line %d: %s" % (message.line_no, _clip(redact(message.raw)))


# ---------------------------------------------------------------- schema check

def _type_ok(declared: Any, value: Any) -> bool:
    if declared == "string":
        return isinstance(value, str)
    if declared == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if declared == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if declared == "boolean":
        return isinstance(value, bool)
    if declared == "array":
        return isinstance(value, list)
    if declared == "object":
        return isinstance(value, dict)
    return True  # unknown or absent type: no opinion


def validate_arguments(schema: Dict[str, Any], args: Any) -> List[str]:
    """Top-level JSON Schema argument check. Returns human-readable problems."""
    problems: List[str] = []
    if not isinstance(schema, dict) or not isinstance(args, dict):
        return problems
    props = schema.get("properties")
    props = props if isinstance(props, dict) else {}
    required = schema.get("required")
    required = required if isinstance(required, list) else []
    for name in required:
        if name not in args:
            problems.append("missing required argument '%s'" % name)
    for name, value in args.items():
        spec = props.get(name)
        if spec is True:
            continue  # boolean schema: anything allowed
        if spec is False:
            problems.append("argument '%s' is not allowed by the schema" % name)
            continue
        if not isinstance(spec, dict):
            if schema.get("additionalProperties") is False:
                problems.append(
                    "unexpected argument '%s' (schema sets additionalProperties: false)" % name
                )
            continue
        declared = spec.get("type")
        if declared is not None and not _type_ok(declared, value):
            problems.append(
                "argument '%s' should be %s but got %s"
                % (name, declared, type(value).__name__)
            )
        enum = spec.get("enum")
        if isinstance(enum, list) and value not in enum:
            problems.append("argument '%s' is not one of %s" % (name, enum))
    return problems


# ---------------------------------------------------------------- rules

_HTTP_LINE = re.compile(r"^(HTTP/|(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s)")


def _looks_http(message: Message) -> bool:
    return bool(_HTTP_LINE.match(message.raw.strip()))


def rule_stdio_pollution(session: Session, strict: bool = False) -> List[Finding]:
    noise = session.unparsed
    if not noise:
        return []
    if not session.parsed:
        return []  # file simply is not a transcript
    if not strict:
        # HTTP-transport logs legitimately mix request/status lines with
        # JSON-RPC bodies. In non-strict mode only flag noise that sits
        # between two protocol messages and is not HTTP framing.
        parsed_lines = {m.line_no for m in session.parsed}
        first, last = min(parsed_lines), max(parsed_lines)
        noise = [
            m for m in noise
            if first < m.line_no < last and not _looks_http(m)
        ]
        if not noise:
            return []
    samples = "; ".join("line %d: %s" % (m.line_no, _clip(m.raw, 80)) for m in noise[:3])
    return [Finding(
        "STDIO_POLLUTION", HIGH,
        "%d line(s) in the stream are not JSON-RPC messages" % len(noise),
        samples,
        "On a stdio transport every byte on stdout must be a JSON-RPC message. "
        "A server that prints banners, logs, or tracebacks to stdout corrupts the "
        "stream; clients typically fail the handshake or silently drop the server.",
        "Route all server logging to stderr (or a file), never stdout. In Python use "
        "logging.StreamHandler(sys.stderr); in Node use console.error. Then recapture "
        "the transcript and confirm it is clean.",
    )]


def rule_version_downshift(session: Session, strict: bool = False) -> List[Finding]:
    findings = []
    for req in session.requests("initialize"):
        resp = session.response_for(req)
        if resp is None:
            continue
        params = req.obj.get("params") or {}
        offered = params.get("protocolVersion")
        result = resp.result()
        answered = result.get("protocolVersion") if isinstance(result, dict) else None
        if offered and answered and offered != answered:
            findings.append(Finding(
                "VERSION_DOWNSHIFT", MEDIUM,
                "server answered protocol version %r to an initialize offering %r"
                % (answered, offered),
                "%s | %s" % (_ev(req), _ev(resp)),
                "Version negotiation downshift is legal, but a client that does not "
                "support the answered version disconnects - often right after showing "
                "'connected'.",
                "Confirm the client supports the answered version. Every later HTTP "
                "request must also carry MCP-Protocol-Version with exactly this value.",
            ))
    return findings


def rule_missing_tools_capability(session: Session, strict: bool = False) -> List[Finding]:
    findings = []
    for req in session.requests("initialize"):
        resp = session.response_for(req)
        if resp is None:
            continue
        result = resp.result()
        if not isinstance(result, dict):
            continue
        caps = result.get("capabilities")
        caps = caps if isinstance(caps, dict) else {}
        if "tools" in caps:
            continue
        later_list = [r for r in session.requests("tools/list") if r.line_no > resp.line_no]
        if later_list:
            continue
        findings.append(Finding(
            "MISSING_TOOLS_CAPABILITY", HIGH,
            "in this capture, the initialize result does not declare the 'tools' capability",
            _ev(resp),
            "Most clients never send tools/list when the capability is absent, so the "
            "server shows as connected with zero tools. With the official SDKs this "
            "usually means tools were registered after the server connected to the "
            "transport.",
            "Register all tools before connecting the transport, and declare the tools "
            "capability. If tools are added later, set listChanged: true and send "
            "notifications/tools/list_changed.",
        ))
    return findings


_TOOLS_LIST_ERROR_DETAIL = {
    -32601: (
        "method not found: the server advertises tools but has no tools/list handler",
        "Add a tools/list handler, or stop advertising the tools capability.",
    ),
    -32602: (
        "invalid params: the list request was malformed for this protocol era "
        "(2026-era servers require the protocol version in _meta)",
        "Compare the request params against the protocol revision the server implements.",
    ),
    -32603: (
        "internal error: the handler threw, often while building a schema or calling a backend",
        "Read the server log for this request id and fix the exception in the handler.",
    ),
    -32022: (
        "unsupported protocol version (2026 era)",
        "Retry with one of the versions the server reports in error.data.supported.",
    ),
}


def rule_tools_list_error(session: Session, strict: bool = False) -> List[Finding]:
    findings = []
    for req in session.requests("tools/list"):
        resp = session.response_for(req)
        if resp is None:
            continue
        err = resp.error()
        if err is None:
            continue
        raw = resp.raw.lower()
        if _looks_auth(err, raw):
            continue  # AUTH_ON_LIST reports this response with a sharper diagnosis
        code = err.get("code")
        detail, fix = _TOOLS_LIST_ERROR_DETAIL.get(
            code, ("tools/list returned JSON-RPC error %s" % code,
                   "Read the server log for this request id."))
        extra = ""
        if code == -32022 and isinstance(err.get("data"), dict):
            supported = err["data"].get("supported")
            if supported:
                extra = " Server supports: %s." % supported
        findings.append(Finding(
            "TOOLS_LIST_ERROR", HIGH,
            "tools/list failed: %s" % detail,
            "%s | %s" % (_ev(req), _ev(resp)),
            "The client shows 'connected' because initialize succeeded, but the tools "
            "list never loads.%s" % extra,
            fix,
        ))
    return findings


def rule_tools_list_hang(session: Session, strict: bool = False) -> List[Finding]:
    findings = []
    answered = {m.msg_id for m in session.parsed if m.kind == "response"}
    for req in session.requests("tools/list"):
        if req.msg_id in answered:
            continue
        findings.append(Finding(
            "TOOLS_LIST_HANG", HIGH,
            "tools/list was sent but no response appears in this capture",
            _ev(req),
            "The handler is waiting on a backend, or a proxy is buffering the streamed "
            "response. Clients show this as stuck on 'Loading tools'.",
            "Check the server log for this request id. Serve list responses as plain "
            "JSON where possible and make sure proxies do not buffer SSE.",
        ))
    return findings


def rule_missing_initialized(session: Session, strict: bool = False) -> List[Finding]:
    if not session.requests("initialize"):
        return []
    if session.notifications("notifications/initialized"):
        return []
    resp = None
    for req in session.requests("initialize"):
        resp = session.response_for(req)
        if resp is not None:
            break
    if resp is None:
        return []
    return [Finding(
        "MISSING_INITIALIZED", LOW,
        "no notifications/initialized after a successful initialize in this capture",
        _ev(resp),
        "Some servers wait for the initialized notification before serving requests; "
        "skipping it can produce hangs that look like server bugs.",
        "Make sure the client sends notifications/initialized after the initialize "
        "response.",
    )]


def rule_empty_tools_list(session: Session, strict: bool = False) -> List[Finding]:
    findings = []
    for req in session.requests("tools/list"):
        resp = session.response_for(req)
        if resp is None:
            continue
        result = resp.result()
        if isinstance(result, dict) and result.get("tools") == []:
            findings.append(Finding(
                "EMPTY_TOOLS_LIST", MEDIUM,
                "tools/list succeeded but returned an empty array",
                _ev(resp),
                "Some servers return an empty list to anonymous callers and the full "
                "list only after sign-in; others allow initialize without a token and "
                "reject only later calls.",
                "If the server needs auth, it should return a 401 challenge on the "
                "first request so clients start OAuth before reporting 'connected'. "
                "Otherwise check that tools were actually registered.",
            ))
    return findings


_SESSION_ID_RE = re.compile(r"mcp-session-id", re.IGNORECASE)
_SESSION_FAIL_RE = re.compile(r"\b(400|404)\b")


def rule_session_id_lost(session: Session, strict: bool = False) -> List[Finding]:
    saw_session_header = any(_SESSION_ID_RE.search(m.raw) for m in session.messages)
    if not saw_session_header:
        return []
    hits = [
        m for m in session.messages
        if "session" in m.raw.lower() and _SESSION_FAIL_RE.search(m.raw)
    ]
    if not hits:
        return []
    return [Finding(
        "SESSION_ID_LOST", MEDIUM,
        "a request after initialize failed with 400/404 involving the session id",
        "; ".join(_ev(m) for m in hits[:3]),
        "On 2025-era Streamable HTTP the client must echo the Mcp-Session-Id from the "
        "initialize response on every later request. 400 means the header is missing; "
        "404 means the session expired. Causes include CORS not exposing the header, "
        "load balancers without sticky routing, and fast session expiry.",
        "Expose Mcp-Session-Id in Access-Control-Expose-Headers, use shared session "
        "storage or sticky routing, and make the client re-initialize on a 404.",
    )]


def rule_auth_on_list(session: Session, strict: bool = False) -> List[Finding]:
    findings = []
    for req in session.requests("tools/list"):
        resp = session.response_for(req)
        if resp is None:
            continue
        err = resp.error()
        raw = resp.raw.lower()
        if err is not None and _looks_auth(err, raw):
            findings.append(Finding(
                "AUTH_ON_LIST", HIGH,
                "tools/list was rejected for authentication while initialize succeeded",
                "%s | %s" % (_ev(req), _ev(resp)),
                "Clients treat a successful initialize as 'connected' and many do not "
                "surface a 401 on tools/list as a sign-in challenge, so the server "
                "looks connected but shows no tools.",
                "Return the 401 challenge on the first request (initialize) so the "
                "client starts OAuth before reporting the server as connected.",
            ))
    return findings


def rule_pagination_incomplete(session: Session, strict: bool = False) -> List[Finding]:
    findings = []
    list_reqs = session.requests("tools/list")
    requested_cursors = set()
    for req in list_reqs:
        params = req.obj.get("params") or {}
        if isinstance(params, dict) and params.get("cursor"):
            requested_cursors.add(params["cursor"])
    for req in list_reqs:
        resp = session.response_for(req)
        if resp is None:
            continue
        result = resp.result()
        if not isinstance(result, dict):
            continue
        cursor = result.get("nextCursor")
        if cursor and cursor not in requested_cursors:
            count = len(result.get("tools") or [])
            findings.append(Finding(
                "PAGINATION_INCOMPLETE", MEDIUM,
                "tools/list returned nextCursor but no later page request appears in this capture",
                _ev(resp),
                "The transcript shows %d tool(s) on this page; the remaining tools are "
                "behind a cursor the client never requested, so the visible list is "
                "incomplete." % count,
                "Fix the client to follow nextCursor until it is absent, or raise the "
                "server's page size.",
            ))
    return findings


def rule_schema_issues(session: Session, strict: bool = False) -> List[Finding]:
    problems = []
    for m in session.parsed:
        result = m.result()
        if not (isinstance(result, dict) and isinstance(result.get("tools"), list)):
            continue
        for t in result["tools"]:
            if not isinstance(t, dict):
                continue
            name = t.get("name", "?")
            schema = t.get("inputSchema")
            if schema is None:
                problems.append("tool '%s' has no inputSchema" % name)
            elif not isinstance(schema, dict):
                problems.append("tool '%s' inputSchema is not an object" % name)
            elif schema.get("type") not in (None, "object"):
                problems.append(
                    "tool '%s' inputSchema type is %r (clients expect 'object')"
                    % (name, schema.get("type"))
                )
    if not problems:
        return []
    return [Finding(
        "SCHEMA_ISSUES", LOW,
        "%d tool schema problem(s) in tools/list results" % len(problems),
        "; ".join(problems[:5]),
        "Clients validate or render tool forms from inputSchema; malformed schemas get "
        "tools dropped or calls rejected before the server runs.",
        "Validate every tool's inputSchema as JSON Schema and give each tool an "
        "object-typed schema with a description.",
    )]


def rule_orphan_responses(session: Session, strict: bool = False) -> List[Finding]:
    orphans = session.orphan_responses()
    if not orphans:
        return []
    return [Finding(
        "ORPHAN_RESPONSES", LOW,
        "%d response(s) have ids no request in the transcript claims" % len(orphans),
        "; ".join(_ev(m) for m in orphans[:3]),
        "Responses without matching requests mean broken framing (mixed streams, "
        "duplicated ids, or a capture that missed the request).",
        "Recapture the full exchange from the start; if it persists, check for two "
        "writers on the same transport.",
    )]


def rule_era_mix(session: Session, strict: bool = False) -> List[Finding]:
    if not session.requests("initialize"):
        return []
    if not session.has_modern_markers():
        return []
    return [Finding(
        "ERA_MIX", MEDIUM,
        "transcript mixes a 2025-era initialize handshake with 2026-era markers",
        _ev(session.requests("initialize")[0]),
        "2026-era servers have no handshake and no sessions; each request carries its "
        "own version. A 2026-only client talking to a 2025-only server (or the "
        "reverse) can fail on the first list call.",
        "Pin client and server to the same protocol revision, or use a client that "
        "falls back to initialize when the modern request is rejected.",
    )]


def rule_tool_call_problems(session: Session, strict: bool = False) -> List[Finding]:
    findings = []
    for req in session.requests("tools/call"):
        resp = session.response_for(req)
        if resp is None:
            continue
        params = req.obj.get("params") or {}
        name = params.get("name", "?")
        args = params.get("arguments")
        schemas = session.tools_by_name(before_line=req.line_no)
        err = resp.error()
        if err is not None and err.get("code") == -32602:
            detail = ""
            schema = schemas.get(name)
            if schema and isinstance(args, dict):
                problems = validate_arguments(schema, args)
                if problems:
                    detail = " Arguments violate the tool's own inputSchema: " + "; ".join(problems) + "."
            findings.append(Finding(
                "TOOL_CALL_ARG_MISMATCH", HIGH,
                "tools/call '%s' rejected with invalid params" % name,
                "%s | %s" % (_ev(req), _ev(resp)),
                "The server rejected the arguments the client sent.%s" % detail,
                "Fix the caller to send arguments matching the tool's inputSchema. If "
                "an agent built the call, surface the schema violation in its retry "
                "feedback instead of the raw JSON-RPC error.",
            ))
            continue
        result = resp.result()
        if isinstance(result, dict) and result.get("isError") is True:
            snippet = ""
            content = result.get("content")
            if isinstance(content, list) and content:
                first = content[0]
                if isinstance(first, dict) and isinstance(first.get("text"), str):
                    snippet = " First content: " + _clip(first["text"], 100)
            findings.append(Finding(
                "TOOL_CALL_FAILED", MEDIUM,
                "tools/call '%s' returned isError: true" % name,
                "%s | %s" % (_ev(req), _ev(resp)),
                "The protocol exchange succeeded; the tool itself failed inside the "
                "server.%s" % snippet,
                "Debug the tool implementation or its backend, not the MCP connection.",
            ))
    return findings



# Methods only a server initiates (2025-era client features). Seeing these as
# requests proves the stream is bidirectional.
_SERVER_INITIATED_METHODS = {"sampling/createmessage", "roots/list", "elicitation/create"}


def rule_capture_incomplete(session: Session, strict: bool = False) -> List[Finding]:
    parsed = session.parsed
    if not parsed:
        return []
    first = parsed[0]
    if first.kind == "request" and first.method in ("initialize", "server/discover"):
        return []
    return [Finding(
        "CAPTURE_INCOMPLETE", LOW,
        "capture does not start at the session opening",
        _ev(first),
        "The first protocol message is not initialize or server/discover, so earlier "
        "traffic was missed. Findings based on absence (no tools/list sent, no "
        "initialized notification, no next page requested) are tentative: the missing "
        "message may have happened before the capture started.",
        "Recapture from client startup for definitive absence-based diagnoses.",
    )]


def rule_direction_ambiguous(session: Session, strict: bool = False) -> List[Finding]:
    server_methods = {
        m.method for m in session.requests()
        if isinstance(m.method, str) and m.method.lower() in _SERVER_INITIATED_METHODS
    }
    # duplicate in-flight ids: same id requested again before any response to it
    open_ids = set()
    duplicated = False
    for m in session.messages:
        if m.kind == "request":
            if m.msg_id in open_ids:
                duplicated = True
            open_ids.add(m.msg_id)
        elif m.kind == "response":
            open_ids.discard(m.msg_id)
    if not server_methods and not duplicated:
        return []
    parts = []
    if server_methods:
        parts.append("server-initiated requests present (%s)" % ", ".join(sorted(server_methods)))
    if duplicated:
        parts.append("a request id was reused while still unanswered")
    return [Finding(
        "DIRECTION_AMBIGUOUS", LOW,
        "transcript direction is ambiguous: " + "; ".join(parts),
        "capture contains both client-to-server and server-to-client traffic without "
        "direction markers",
        "Without direction markers, request/response pairing relies on id order. When "
        "both sides can send requests, an id can be in flight in both directions at "
        "once, so a pairing (and any finding built on it) may attribute a response to "
        "the wrong side.",
        "Capture with direction markers (a proxy log with send/receive tags) when a "
        "diagnosis depends on exact pairing.",
    )]

ALL_RULES: List[Callable[[Session, bool], List[Finding]]] = [
    rule_stdio_pollution,
    rule_version_downshift,
    rule_missing_tools_capability,
    rule_tools_list_error,
    rule_tools_list_hang,
    rule_missing_initialized,
    rule_empty_tools_list,
    rule_session_id_lost,
    rule_auth_on_list,
    rule_pagination_incomplete,
    rule_schema_issues,
    rule_orphan_responses,
    rule_era_mix,
    rule_tool_call_problems,
    rule_capture_incomplete,
    rule_direction_ambiguous,
]

_SEVERITY_ORDER = {HIGH: 0, MEDIUM: 1, LOW: 2}


# Findings whose diagnosis rests partly on what the capture does NOT show.
_ABSENCE_BASED = {"TOOLS_LIST_HANG", "MISSING_TOOLS_CAPABILITY", "PAGINATION_INCOMPLETE"}
_CAPTURE_FLAGS = {"CAPTURE_INCOMPLETE", "DIRECTION_AMBIGUOUS"}


def diagnose(session: Session, strict_stdio: bool = False) -> List[Finding]:
    findings: List[Finding] = []
    for rule in ALL_RULES:
        findings.extend(rule(session, strict_stdio))
    flags = {f.code for f in findings} & _CAPTURE_FLAGS
    if flags:
        # An incomplete or direction-ambiguous capture weakens absence-based
        # conclusions: the missing message may exist outside the capture or be
        # paired to the wrong side. Reflect that in severity, not just wording.
        for f in findings:
            if f.code in _ABSENCE_BASED and f.severity == HIGH:
                f.severity = MEDIUM
                f.why += (" (Severity lowered: %s means the missing traffic may "
                          "simply be outside this capture.)"
                          % " and ".join(sorted(flags)))
    findings.sort(key=lambda f: (_SEVERITY_ORDER.get(f.severity, 3), f.code))
    return findings
