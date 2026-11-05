"""Diagnosis rules over a parsed MCP transcript.

Each rule inspects the Session and returns zero or more Findings with the
evidence line, an explanation of the root cause, and a concrete fix. Rules
are deterministic: same transcript, same findings.
"""

from __future__ import annotations

import re
from bisect import bisect_left
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from .transcript import Message, Session, WireNumber

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


def _integer_number(value: Any) -> bool:
    if isinstance(value, WireNumber):
        return value.exact.is_finite() and value.exact == value.exact.to_integral_value()
    return type(value) is int or (type(value) is float and value.is_integer())


def _usable_error_code(value: Any) -> bool:
    return _integer_number(value)


def _looks_auth(err) -> bool:
    """True when a JSON-RPC error response carries an authentication rejection.

    JSON-RPC error codes and HTTP status codes are different layers; a 401 here
    is a value the server embedded in the error code, message, or data, not an
    HTTP status line.
    """
    if _json_equal(err.get("code"), 401):
        return True
    # A decoder may accept deeper values than json.dumps can encode. Walk
    # JSON leaves and member names without recursive calls or re-encoding.
    pending = [dict(err)]
    if isinstance(err.get("code"), (int, float)):
        pending[0].pop("code", None)
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            pending.extend(value.keys())
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
        elif isinstance(value, (str, int, float)) and not isinstance(value, bool):
            text = str(value).lower()
            if (_401_RE.search(text) or "unauthorized" in text
                    or "unauthenticated" in text):
                return True
    return False



_URL_USERINFO_RE = re.compile(r"(://)[^/@\s:]+:[^/@\s]+@")
_URL_QUERY_RE = re.compile(
    r"([?&](?:api[-_]?key|access[-_]?token|token|secret|password|key|sig|signature|credential)=)[^&\s]+",
    re.IGNORECASE)


_SECRET_JSON_RE = re.compile(
    r'("(?:authorization|api[-_]?key|access[-_]?token|refresh[-_]?token|token|secret|password|client[-_]?secret)"'
    r'\s*:\s*")((?:\\.|[^"\\])+)(")', re.IGNORECASE)
# One JSON-string layer is common in tools/call text content. Match its
# escaped key/value quotes before evidence clipping removes the terminator.
_SECRET_ESCAPED_JSON_RE = re.compile(
    r'(\\"(?:authorization|api[-_]?key|access[-_]?token|refresh[-_]?token|token|secret|password|client[-_]?secret)\\"'
    r'\s*:\s*\\")((?:\\\\\\\\|\\\\\\"|\\\\[^"\\]|[^"\\])*)(\\")', re.IGNORECASE)
_BEARER_RE = re.compile(r"(bearer\s+)\S+", re.IGNORECASE)
_AUTH_HEADER_RE = re.compile(r"(authorization\s*[:=]\s*)\S+(\s+\S+)?", re.IGNORECASE)


def redact(text: str) -> str:
    """Best-effort masking of credential-looking values before they appear in
    any report. Not a complete sanitizer: unusual formats can slip through, so
    review any log before sharing it."""
    text = _SECRET_ESCAPED_JSON_RE.sub(lambda m: m.group(1) + "***" + m.group(3), text)
    text = _SECRET_JSON_RE.sub(lambda m: m.group(1) + "***" + m.group(3), text)
    text = _BEARER_RE.sub(lambda m: m.group(1) + "***", text)
    text = _AUTH_HEADER_RE.sub(lambda m: m.group(1) + "***", text)
    text = _URL_USERINFO_RE.sub(r"\1***:***@", text)
    text = _URL_QUERY_RE.sub(lambda m: m.group(1) + "***", text)
    return text


def _ev(message: Message) -> str:
    return "line %d: %s" % (message.line_no, _clip(redact(message.raw)))


# ---------------------------------------------------------------- schema check

_JSON_TYPES = {"string", "number", "integer", "boolean", "array", "object", "null"}


def _type_ok(declared: Any, value: Any) -> bool:
    if isinstance(declared, list):
        # A malformed union is not evidence for a narrower supported subset.
        if (not declared or not all(isinstance(item, str) and item in _JSON_TYPES
                                    for item in declared)
                or len(set(declared)) != len(declared)):
            return True
        return any(_type_ok(item, value) for item in declared)
    if declared == "null":
        return value is None
    if declared == "string":
        return isinstance(value, str)
    if declared == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if declared == "integer":
        return _integer_number(value)
    if declared == "boolean":
        return isinstance(value, bool)
    if declared == "array":
        return isinstance(value, list)
    if declared == "object":
        return isinstance(value, dict)
    return True  # unknown or absent type: no opinion


def _valid_required(value: Any) -> bool:
    return (isinstance(value, list) and all(isinstance(x, str) for x in value)
            and len(set(value)) == len(value))


def _json_equal(left: Any, right: Any) -> bool:
    """Compare JSON values iteratively, without Python bool/number aliasing."""
    pending = [(left, right)]
    while pending:
        left, right = pending.pop()
        if isinstance(left, bool) or isinstance(right, bool):
            if type(left) is not type(right) or left != right:
                return False
        elif isinstance(left, (int, float)) and isinstance(right, (int, float)):
            left = left.exact if isinstance(left, WireNumber) else left
            right = right.exact if isinstance(right, WireNumber) else right
            if left != right:
                return False
        elif type(left) is not type(right):
            return False
        elif isinstance(left, list):
            if len(left) != len(right):
                return False
            pending.extend(zip(left, right))
        elif isinstance(left, dict):
            if left.keys() != right.keys():
                return False
            pending.extend((left[key], right[key]) for key in left)
        elif left != right:
            return False
    return True


def _enum_summary(enum: list) -> str:
    try:
        summary = redact(str(enum))
        if len(summary) > 160:
            return "the declared enum (%d value(s); details omitted)" % len(enum)
        return summary
    except RecursionError:
        return "the declared enum (%d deeply nested value(s))" % len(enum)


def validate_arguments(schema: Dict[str, Any], args: Any) -> List[str]:
    """Top-level JSON Schema argument check. Returns human-readable problems."""
    problems: List[str] = []
    if not isinstance(schema, dict) or not isinstance(args, dict):
        return problems
    # Decimal's exponent representation is bounded. Do not invent a schema
    # violation when exact wire numbers exceed that range. This only affects
    # schema explanations, not the observed server rejection itself.
    pending = [schema, args]
    while pending:
        value = pending.pop()
        if isinstance(value, WireNumber) and not value.exact.is_finite():
            return problems
        if isinstance(value, dict):
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
    raw_props = schema.get("properties", {})
    props = raw_props if isinstance(raw_props, dict) else {}
    # additionalProperties excludes names matched by patternProperties too.
    # We do not execute captured regexes (dialect/resource limits). A nonempty
    # or malformed pattern map makes that narrow exclusion claim unproven.
    # Do not discard independent explicit-property or required evidence.
    patterns = schema.get("patternProperties", {})
    can_exclude_extra = (isinstance(raw_props, dict)
                         and isinstance(patterns, dict) and not patterns)
    required = schema.get("required")
    required = required if _valid_required(required) else []
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
            if (name not in props and can_exclude_extra
                    and schema.get("additionalProperties") is False):
                problems.append(
                    "unexpected argument '%s' (schema sets additionalProperties: false)" % name
                )
            continue
        declared = spec.get("type")
        if declared is not None and not _type_ok(declared, value):
            problems.append(
                "argument '%s' should be %s but got %s"
                % (name, " or ".join(declared) if isinstance(declared, list) else declared,
                   type(value).__name__)
            )
        enum = spec.get("enum")
        if isinstance(enum, list) and not any(_json_equal(value, item) for item in enum):
            problems.append("argument '%s' is not one of %s" % (name, _enum_summary(enum)))
    return problems


# ---------------------------------------------------------------- rules

_HTTP_LINE = re.compile(r"^(HTTP/|(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s)")


def _looks_http(message: Message) -> bool:
    return bool(_HTTP_LINE.match(message.raw.strip()))


def rule_no_protocol_messages(session: Session, strict: bool = False) -> List[Finding]:
    if any(m.kind != "unparsed" for m in session.messages):
        return []  # invalid-ID messages have their own explicit diagnostic
    evidence = "; ".join(_ev(m) for m in session.messages[:3])
    return [Finding(
        "NO_PROTOCOL_MESSAGES", HIGH,
        "capture contains no recognized JSON-RPC messages",
        evidence or "capture is empty or contains only whitespace",
        "There is no protocol exchange to diagnose. An empty file, unrelated log "
        "or unsupported capture format is not evidence that the MCP session is healthy.",
        "Capture JSON-RPC traffic from the client or server, check the file or stdin "
        "input, and recapture from startup. This tool expects line-oriented messages.",
    )]


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
    samples = "; ".join("line %d: %s" % (m.line_no, _clip(redact(m.raw), 80)) for m in noise[:3])
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
        params = req.obj.get("params", {})
        if not isinstance(params, dict):
            continue  # rule_unusable_params keeps the malformed evidence explicit
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


def _list_startup_context(session: Session):
    """Latest earlier initialize attempt, not a future or superseded success.

    Object result is the existing startup evidence threshold, not complete
    InitializeResult validation. Return an indexed lookup for repeated failures.
    """
    attempts = session.requests("initialize")
    lines = [m.line_no for m in attempts]
    pairs = session.response_pairs()

    def context(request):
        index = bisect_left(lines, request.line_no) - 1
        response = pairs.get(id(attempts[index])) if index >= 0 else None
        if (response is not None and response.line_no < request.line_no
                and isinstance(response.result(), dict)):
            return (" An earlier initialize returned an object result before this "
                    "list request; this is not full startup validation.",
                    " | earlier initialize: " + _ev(response))
        return (" Successful initialize before this list request is not established "
                "by the latest captured initialize attempt. The list error itself "
                "is still observed.", "")
    return context


def rule_tools_list_error(session: Session, strict: bool = False) -> List[Finding]:
    findings = []
    startup_context = _list_startup_context(session)
    for req in session.requests("tools/list"):
        resp = session.response_for(req)
        if resp is None:
            continue
        err = resp.error()
        if err is None:
            continue
        if _looks_auth(err):
            continue  # AUTH_ON_LIST reports this response with a sharper diagnosis
        code = err.get("code")
        if not _usable_error_code(code):
            continue
        detail, fix = _TOOLS_LIST_ERROR_DETAIL.get(
            code, ("tools/list returned JSON-RPC error %s" % code,
                   "Read the server log for this request id."))
        extra = ""
        if _json_equal(code, -32022) and isinstance(err.get("data"), dict):
            supported = err["data"].get("supported")
            if supported:
                try:
                    detail_summary = redact(str(supported))
                    if len(detail_summary) > 320:
                        detail_summary = "[version details too long to display]"
                except RecursionError:
                    detail_summary = "[version details too deeply nested to display]"
                extra = " Server supports: %s." % detail_summary
        startup, startup_evidence = startup_context(req)
        findings.append(Finding(
            "TOOLS_LIST_ERROR", HIGH,
            "tools/list failed: %s" % detail,
            "%s | %s%s" % (_ev(req), _ev(resp), startup_evidence),
            "The captured tools/list request returned a protocol error, so this "
            "exchange did not supply a successful tool list.%s%s" % (startup, extra),
            fix,
        ))
    return findings


def rule_tools_list_hang(session: Session, strict: bool = False) -> List[Finding]:
    findings = []
    for req in session.requests("tools/list"):
        if session.response_for(req) is not None:
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
    notifications = session.notifications("notifications/initialized")
    resp = None
    for req in session.requests("initialize"):
        candidate = session.response_for(req)
        if (candidate is None or candidate.error() is not None
                or not isinstance(candidate.result(), dict)):
            continue
        if any(note.line_no > candidate.line_no for note in notifications):
            continue
        resp = candidate
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
    startup_context = _list_startup_context(session)
    for req in session.requests("tools/list"):
        resp = session.response_for(req)
        if resp is None:
            continue
        err = resp.error()
        if err is not None and _looks_auth(err):
            startup, startup_evidence = startup_context(req)
            findings.append(Finding(
                "AUTH_ON_LIST", HIGH,
                "tools/list returned an error containing authentication markers",
                "%s | %s%s" % (_ev(req), _ev(resp), startup_evidence),
                "The captured list error contains authentication markers. Many "
                "clients do not surface such a list error as a sign-in challenge."
                + startup,
                "Return the 401 challenge on the first request (initialize) so the "
                "client starts OAuth before reporting the server as connected.",
            ))
    return findings


def rule_pagination_incomplete(session: Session, strict: bool = False) -> List[Finding]:
    findings = []
    list_reqs = session.requests("tools/list")
    requested_cursors = {}
    for req in list_reqs:
        params = req.obj.get("params")
        if isinstance(params, dict) and isinstance(params.get("cursor"), str):
            requested_cursors.setdefault(params["cursor"], []).append(req.line_no)
    for req in list_reqs:
        resp = session.response_for(req)
        if resp is None:
            continue
        result = resp.result()
        if not isinstance(result, dict):
            continue
        cursor = result.get("nextCursor")
        if isinstance(cursor, str) and not any(
                line > resp.line_no for line in requested_cursors.get(cursor, [])):
            tools = result.get("tools")
            count = len(tools) if isinstance(tools, list) else 0
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


def rule_unusable_cursor(session: Session, strict: bool = False) -> List[Finding]:
    findings = []
    for req in session.requests("tools/list"):
        params = req.obj.get("params")
        resp = session.response_for(req)
        result = resp.result() if resp is not None else None
        for message, obj, field in ((req, params, "cursor"),
                                    (resp, result, "nextCursor")):
            if (message is None or not isinstance(obj, dict)
                    or field not in obj or isinstance(obj[field], str)):
                continue
            findings.append(Finding(
                "UNUSABLE_CURSOR", HIGH,
                "tools/list %s is not a string" % field,
                _ev(message),
                "Pagination cursors are opaque strings. This captured value "
                "cannot establish a page request or a continuation cursor, "
                "so it is omitted from pagination completion evidence. "
                "The original message is retained.",
                "Check the emitter or capture adapter and preserve the exact "
                "string cursor without coercing arrays, objects or numbers.",
            ))
    return findings


def rule_unusable_tools_catalog(session: Session, strict: bool = False) -> List[Finding]:
    findings = []
    for req in session.requests("tools/list"):
        resp = session.response_for(req)
        if resp is None or not resp.usable_response() or resp.error() is not None:
            continue
        result = resp.result()
        problem = None
        if not isinstance(result, dict) or not isinstance(result.get("tools"), list):
            problem = "tools/list result must be an object with a tools array"
        elif any(not isinstance(tool, dict) or not isinstance(tool.get("name"), str)
                 for tool in result["tools"]):
            problem = "tools/list entries must be objects with string names"
        if problem is not None:
            findings.append(Finding(
                "UNUSABLE_TOOLS_CATALOG", HIGH, problem, _ev(resp),
                "This paired tools/list response cannot establish a usable tool "
                "catalog. Malformed entries are not treated as valid tool definitions. "
                "Other supported checks still run; this is not a full result validator.",
                "Check the emitting server or capture adapter. Preserve the original "
                "response and return an object with a tools array containing named "
                "tool definitions and their input schemas.",
            ))
    return findings


def rule_duplicate_tool_names(session: Session, strict: bool = False) -> List[Finding]:
    findings = []
    for req in session.requests("tools/list"):
        resp = session.response_for(req)
        result = resp.result() if resp is not None else None
        if not isinstance(result, dict) or not isinstance(result.get("tools"), list):
            continue
        names = [t["name"] for t in result["tools"]
                 if isinstance(t, dict) and isinstance(t.get("name"), str)]
        seen = set()
        repeated_names = set()
        for name in names:
            if name in seen:
                repeated_names.add(name)
            seen.add(name)
        repeated = len(repeated_names)
        if repeated:
            findings.append(Finding(
                "DUPLICATE_TOOL_NAMES", MEDIUM,
                "tools/list response repeats %d tool name(s)" % repeated,
                _ev(resp),
                "A single captured tools/list response contains repeated names. "
                "There is no evidence for choosing one definition for a call. "
                "Schemas for those names are omitted from argument explanations; "
                "uniquely named tools remain available.",
                "Give tools distinct names within the server or disambiguate "
                "aggregated tools before presenting the catalog. Check the "
                "server or proxy rather than assuming the last definition wins.",
            ))
    return findings


def rule_duplicate_catalog_pages(session: Session, strict: bool = False) -> List[Finding]:
    return [Finding(
        "DUPLICATE_CATALOG_PAGE_NAMES", MEDIUM,
        "linked tools/list page repeats %d earlier tool name(s)" % count,
        _ev(response),
        "An accepted continuation page repeats names already observed in this "
        "catalog's cursor chain. Page order cannot choose a definition; schemas "
        "for those names are omitted until a fresh catalog starts. Other names "
        "and earlier call-time evidence remain usable.",
        "Check the server or capture adapter for overlapping pages. Return "
        "distinct names across one listing, or refresh the list after it changes. "
        "This capture does not prove which definition a live client used.",
    ) for response, count in session._catalog_state()[1]]


def rule_schema_issues(session: Session, strict: bool = False) -> List[Finding]:
    problems = []
    for req in session.requests("tools/list"):
        m = session.response_for(req)
        if m is None or m.error() is not None:
            continue
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
                declared = schema.get("type")
                # Only canonical JSON type names are useful diagnostic values.
                # Do not stringify arbitrary captured objects or unbounded text.
                if isinstance(declared, str) and declared in _JSON_TYPES:
                    problems.append(
                        "tool '%s' inputSchema type is %r (clients expect 'object')"
                        % (name, declared)
                    )
                else:
                    problems.append(
                        "tool '%s' inputSchema has a non-object type declaration "
                        "(value omitted; clients expect 'object')" % name
                    )
            if isinstance(schema, dict) and "required" in schema and not _valid_required(schema["required"]):
                problems.append("tool '%s' required must be a list of unique strings" % name)
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
        params = req.obj.get("params", {})
        if not isinstance(params, dict):
            continue  # no invented empty-object argument explanation
        name = params.get("name")
        if not isinstance(name, str):
            continue
        args = params.get("arguments")
        err = resp.error()
        if err is not None and _usable_error_code(err.get("code")) and _json_equal(err.get("code"), -32602):
            detail = ""
            schema = None
            if isinstance(args, dict):
                schema = session.tools_by_name(before_line=req.line_no).get(name)
            if schema:
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
        if err is not None and _usable_error_code(err.get("code")):
            findings.append(Finding(
                "TOOL_CALL_PROTOCOL_ERROR", HIGH,
                "tools/call '%s' returned JSON-RPC error %s" % (name, err["code"]),
                "%s | %s" % (_ev(req), _ev(resp)),
                "The server returned a protocol-level rejection, not an isError "
                "tool-execution result. The error code alone does not prove which "
                "request field or server component caused it.",
                "Read the server's error details and logs for this request id. "
                "Check that the named tool is available and the request matches "
                "the server's supported protocol before retrying.",
            ))
            continue
        result = resp.result()
        if isinstance(result, dict) and result.get("isError") is True:
            snippet = ""
            content = result.get("content")
            if isinstance(content, list) and content:
                first = content[0]
                if isinstance(first, dict) and isinstance(first.get("text"), str):
                    snippet = " First content: " + _clip(redact(first["text"]), 100)
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
            if (type(m.msg_id), m.msg_id) in open_ids:
                duplicated = True
            open_ids.add((type(m.msg_id), m.msg_id))
        elif m.kind == "response":
            open_ids.discard((type(m.msg_id), m.msg_id))
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

def rule_invalid_rpc_id(session: Session, strict: bool = False) -> List[Finding]:
    """MCP request IDs are strings or integers, never Python bool aliases."""
    return [Finding(
        "INVALID_RPC_ID", HIGH,
        "JSON-RPC message has an invalid or unsupported request identifier",
        _ev(message),
        "MCP requires string or integer request IDs. Null, boolean, fractional, "
        "array and object IDs cannot be used to pair requests with responses. "
        "Exponent-form IDs requiring 4301 or more decimal integer digits are "
        "outside this parser's supported range and are also left unpaired. "
        "This message is retained as evidence but excluded from pairing.",
        "Fix the emitting client/server or capture adapter to preserve valid "
        "request IDs and return the same ID type and value in the response. "
        "A null-ID error for an unreadable malformed request is exempt.",
    ) for message in session.messages if message.kind == "invalid_id"]


def rule_invalid_rpc_version(session: Session, strict: bool = False) -> List[Finding]:
    return [Finding(
        "INVALID_RPC_VERSION", HIGH,
        "captured jsonrpc member is not the string 2.0",
        _ev(message),
        "JSON-RPC 2.0 requires a present jsonrpc member to be exactly the "
        "string 2.0. This line is retained but cannot establish requests, "
        "responses or tool schemas. Captures omitting the member keep the "
        "existing permissive behavior; this is not full protocol validation.",
        "Check the emitting client/server or capture adapter and preserve "
        "the actual protocol version without coercing it.",
    ) for message in session.messages if message.kind == "invalid_rpc_version"]


def rule_invalid_rpc_method(session: Session, strict: bool = False) -> List[Finding]:
    return [Finding(
        "INVALID_RPC_METHOD", HIGH,
        "JSON-RPC message has a non-string method member",
        _ev(message),
        "JSON-RPC requires a present method member to be a string. A null, "
        "boolean, numeric, array or object method cannot establish request or "
        "notification traffic. It is not reinterpreted as a response even if "
        "result/error members are present, and cannot supply catalog schemas.",
        "Fix the emitting client/server or capture adapter to preserve a "
        "string method name. This check does not validate supported method "
        "names or every other request member.",
    ) for message in session.messages if message.kind == "invalid_method"]


def rule_unusable_params(session: Session, strict: bool = False) -> List[Finding]:
    return [Finding(
        "UNUSABLE_PARAMS", HIGH,
        "captured %s params are not an object" % message.method,
        _ev(message),
        "This rule expects object-valued params for initialize and tools/call. "
        "The supplied value cannot be inspected safely; it is retained as "
        "evidence, and method-specific parameter explanations are omitted. "
        "This is not a complete request schema validator.",
        "Check the emitting client or capture adapter and recapture the "
        "request with object-valued params. Do not replace malformed values "
        "with an empty object when investigating the original failure.",
    ) for message in session.requests()
       if message.method in ("initialize", "tools/call")
       and "params" in message.obj
       and not isinstance(message.obj["params"], dict)]


def rule_unusable_error_code(session: Session, strict: bool = False) -> List[Finding]:
    return [Finding(
        "UNUSABLE_ERROR_CODE", HIGH,
        "captured JSON-RPC error code is not an integer number",
        _ev(message),
        "This error code cannot select a JSON-RPC error explanation safely. "
        "The original response is retained and code-specific details are omitted.",
        "Check the emitting server or capture adapter and preserve an integer "
        "error code without coercing strings, booleans, arrays or objects.",
    ) for message in session.parsed
       if message.error() is not None
       and not _usable_error_code(message.error().get("code"))]


def rule_unusable_tool_name(session: Session, strict: bool = False) -> List[Finding]:
    return [Finding(
        "UNUSABLE_TOOL_NAME", HIGH,
        "captured tools/call name is missing or not a string",
        _ev(message),
        "A non-string or missing tool name cannot identify a tool schema. "
        "The request is retained; tool-specific explanations are omitted.",
        "Check the emitting client or capture adapter and preserve the exact "
        "string tool name. Do not stringify malformed values.",
    ) for message in session.requests("tools/call")
       if isinstance(message.obj.get("params", {}), dict)
       and not isinstance(message.obj.get("params", {}).get("name"), str)]


def rule_unusable_response(session: Session, strict: bool = False) -> List[Finding]:
    return [Finding(
        "UNUSABLE_RESPONSE", HIGH,
        "captured response must contain exactly one result or object-valued error",
        _ev(message),
        "This response has conflicting result/error members or a non-object error. "
        "It establishes neither protocol success nor protocol failure. It still "
        "answers its request for chronology, so it is not called a missing response. "
        "This check does not validate every response or result field.",
        "Check the emitting server or capture adapter and preserve the original "
        "response. Return exactly one result member or one object-valued error.",
    ) for message in session.messages
       if message.kind == "response" and not message.usable_response()]


def rule_nonfinite_json_constant(session: Session, strict: bool = False) -> List[Finding]:
    return [Finding(
        "NONFINITE_JSON_CONSTANT", HIGH,
        "captured message contains a non-JSON numeric literal",
        "line %d: [non-JSON numeric literal; content omitted]" % message.line_no,
        "Bare NaN, Infinity and -Infinity are not JSON numbers. This line is "
        "retained but excluded from pairing, startup and catalog evidence; "
        "no nested substitute message is extracted. Quoted strings and "
        "valid exponent-form JSON numbers are unaffected.",
        "Fix the emitting serializer or capture adapter to emit JSON values "
        "without nonfinite numeric literals, then recapture the exchange.",
    ) for message in session.messages if message.kind == "nonfinite_json_constant"]


def rule_duplicate_json_key(session: Session, strict: bool = False) -> List[Finding]:
    return [Finding(
        "DUPLICATE_JSON_KEY", HIGH,
        "captured JSON object contains repeated member names",
        "line %d: [ambiguous JSON object; names and values omitted]" % message.line_no,
        "A parser could choose different values for repeated members. This line "
        "is retained but excluded from protocol pairing, startup and schema evidence; "
        "no nested substitute message is extracted from it.",
        "Check the emitting client, server or capture adapter and recapture "
        "objects with unique member names. Do not choose a duplicate value by hand "
        "and call it evidence of the original exchange.",
    ) for message in session.messages if message.kind == "duplicate_json_key"]


ALL_RULES: List[Callable[[Session, bool], List[Finding]]] = [
    rule_duplicate_json_key,
    rule_nonfinite_json_constant,
    rule_unusable_response,
    rule_invalid_rpc_id,
    rule_invalid_rpc_method,
    rule_invalid_rpc_version,
    rule_unusable_error_code,
    rule_unusable_tool_name,
    rule_unusable_params,
    rule_no_protocol_messages,
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
    rule_unusable_cursor,
    rule_unusable_tools_catalog,
    rule_duplicate_tool_names,
    rule_duplicate_catalog_pages,
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


class _DiagnosisSession(Session):
    """One diagnosis pass shares an ownership index, never cached on caller state."""
    def __init__(self, session: Session):
        super().__init__(messages=session.messages)
        self._pairs = session.response_pairs()
        # Only traffic with an ID ever used for tools/list can change catalog
        # ownership. Include unrelated methods reusing those IDs and every
        # response, not just successful list replies. List-change notifications
        # and initialize attempts invalidate prior catalog/cursor evidence. The index is local to this diagnosis pass.
        list_ids = {(type(m.msg_id), m.msg_id)
                    for m in self.messages
                    if m.kind == "request" and m.method == "tools/list"}
        catalog_messages = [
            m for m in self.messages
            if ((m.kind in ("request", "response")
                 and (type(m.msg_id), m.msg_id) in list_ids)
                or (m.kind == "notification"
                    and m.method == "notifications/tools/list_changed")
                or (m.kind == "request" and m.method == "initialize"))]
        self._catalog_session = Session(messages=catalog_messages)
        self._catalog_events = sorted(m.line_no for m in catalog_messages)
        self._catalog_epoch = None
        self._catalog_snapshot = None

    def tools_by_name(self, before_line: Optional[int] = None):
        # Consecutive failed calls between catalog events share one snapshot.
        # Keep only the last snapshot, rather than retaining one copy per call.
        epoch = (len(self._catalog_events) if before_line is None
                 else bisect_left(self._catalog_events, before_line))
        if epoch != self._catalog_epoch:
            self._catalog_snapshot = self._catalog_session.tools_by_name(before_line=before_line)
            self._catalog_epoch = epoch
        return self._catalog_snapshot

    def response_for(self, request: Message) -> Optional[Message]:
        return self._pairs.get(id(request))


def diagnose(session: Session, strict_stdio: bool = False) -> List[Finding]:
    session = _DiagnosisSession(session)
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
