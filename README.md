# mcptriage

Diagnose why an MCP server shows as connected but its tools never appear - from
the evidence you already have: the captured JSON-RPC transcript and the client
config file. Offline, deterministic, zero dependencies (Python 3.9+ stdlib).

## The problem

"Connected" in an MCP client usually means only that the first request
succeeded. Listing tools takes several more steps, and the client's status
indicator rarely says which one failed. Developers describe spending hours
restarting clients, re-adding configs, and hand-correlating timestamps across
log files to find causes like:

- the server never declared the `tools` capability (tools registered after
  connect), so the client never even asks for the list
- `tools/list` returns an error (`-32601`, `-32602`, `-32603`, or the 2026-era
  `-32022` UnsupportedProtocolVersionError) or hangs behind a buffering proxy
- a server printing banners or logs to stdout, corrupting the stdio stream
- a lost `Mcp-Session-Id` (400/404 after initialize)
- auth that rejects only `tools/list`, so the server looks connected
- a `nextCursor` page the client never fetches
- version-era mismatches (2025 handshake vs 2026 per-request versioning)
- tool calls rejected with `-32602` because the arguments violate the tool's
  own `inputSchema`

These are documented, recurring failure modes (see Sources). Today you diagnose
them by reading the raw exchange and comparing it against the spec by hand.
mcptriage encodes that comparison as rules and points at the exact log line
that proves the cause.

## Install

```bash
pip install .
# or run without installing:
python -m mcptriage --help   # from the repo root with PYTHONPATH=.
```

## Use

Point it at a captured transcript - a client MCP log channel, a proxy dump,
or a hand-saved `.jsonl` file:

```bash
mcptriage diagnose /path/to/mcp-log.txt
mcptriage diagnose session.jsonl --stdio        # strict: every non-JSON line is pollution
mcptriage diagnose session.jsonl --format json  # machine-readable, for CI
```

Check a client config (Claude Desktop / Claude Code `mcpServers`, VS Code
`servers` shapes):

```bash
mcptriage check-config ~/.config/claude/claude_desktop_config.json
```

Both at once:

```bash
mcptriage diagnose log.txt --config mcp.json
```

Exit code is 1 when any high-severity finding exists (CI-friendly), 0
otherwise; `--exit-zero` disables that.

Example output:

```text
[HIGH] MISSING_TOOLS_CAPABILITY: initialize result does not declare the 'tools' capability
  evidence: line 2: {"jsonrpc":"2.0","id":1,"result":{..."capabilities":{}...}}
  why: Most clients never send tools/list when the capability is absent, so the
  server shows as connected with zero tools. With the official SDKs this usually
  means tools were registered after the server connected to the transport.
  fix: Register all tools before connecting the transport, and declare the tools
  capability. ...
```

## What it checks

Transcript rules (input: captured JSON-RPC exchange):

| Code | Severity | Detects |
| --- | --- | --- |
| STDIO_POLLUTION | high | non-JSON lines in a stdio stream |
| MISSING_TOOLS_CAPABILITY | high | initialize result lacks `tools`, client never lists |
| TOOLS_LIST_ERROR | high | `tools/list` JSON-RPC error, per-code diagnosis |
| TOOLS_LIST_HANG | high | `tools/list` sent, no response |
| AUTH_ON_LIST | high | 401/unauthorized on `tools/list` after a clean initialize |
| TOOL_CALL_ARG_MISMATCH | high | `-32602` call, with arguments checked against the tool's own inputSchema |
| VERSION_DOWNSHIFT | medium | negotiated protocol version differs from offered |
| SESSION_ID_LOST | medium | 400/404 involving `Mcp-Session-Id` after initialize |
| EMPTY_TOOLS_LIST | medium | list succeeds but returns `[]` (auth-gated or none registered) |
| PAGINATION_INCOMPLETE | medium | `nextCursor` returned, next page never requested |
| ERA_MIX | medium | 2025 handshake mixed with 2026-era markers |
| TOOL_CALL_FAILED | medium | call returns `isError: true` (server-side, not protocol) |
| MISSING_INITIALIZED | low | no `notifications/initialized` after initialize |
| UNUSABLE_TOOLS_CATALOG | high | malformed tools/list result, tools array or entry/name shape |
| SCHEMA_ISSUES | low | missing/invalid `inputSchema` in listed tools |
| ORPHAN_RESPONSES | low | responses with ids no request claims (broken framing) |
| INVALID_RPC_ID | high | null, boolean, fractional, array or object IDs that cannot pair safely |

Config rules (input: client config file): invalid JSON with position, missing
or empty servers map, entries with neither/both of `command` and `url`,
unrecognized transport type, command paths that don't exist or aren't on PATH,
`${env:VAR}` references that aren't set, and missing `envFile` paths.

## How this differs from existing tools

Positioning is based on the documentation of each tool checked as of October
2026; it describes differentiation among the tools reviewed, not an exhaustive
claim about everything that exists.

- **MCP Inspector** (`@modelcontextprotocol/inspector`) is an interactive
  client: it connects to a live server so you can poke at it. mcptriage never
  connects to anything; it diagnoses from logs you already captured, including
  from machines you can't reach.
- **mcp-doctor** audits a live server against best practices (descriptions,
  schemas, security posture). mcptriage instead explains a specific observed
  failure.
- **mcp-msgdump** proxies and counts traffic (totals, errors, schema audits).
  mcptriage maps observed symptoms to root causes and fixes.
- **mcp-why** reads client config for client-side quirks (Windows npx, GUI
  PATH). mcptriage's config mode is deliberately light and general; its depth
  is the transcript rule engine.

## Captures, evidence, and privacy

- mcptriage never contacts the server or the network. It reads only the files
  you point it at.
- Evidence lines are redacted before display, in both text and JSON output:
  `Authorization` headers, bearer tokens, URL userinfo and credential query
  parameters, and JSON fields named like `token`, `secret`, `password`, or
  `api_key` are masked as `***`. Redaction is best-effort, not complete
  sanitization - review any log before sharing it, and never commit raw
  captured logs to a repository.
- Most client log captures are one-directional excerpts. mcptriage reports
  `CAPTURE_INCOMPLETE` when the capture does not start at session open, and
  `DIRECTION_AMBIGUOUS` when server-initiated requests or reused ids make
  request/response pairing uncertain. When either flag is present,
  absence-based findings ("client never sent X") are automatically lowered
  from high to medium severity - uncertainty changes the result, not just the
  wording.
- JSON-RPC error codes and HTTP status codes are different layers. Rules that
  mention a `401` mean a value the server embedded in a JSON-RPC error, not an
  HTTP status line.

## Limits

- Heuristic, not spec-complete: rules cover documented recurring failure
  modes, not every possible fault. Rules are written against the protocol
  revisions cited in Sources; newer revisions may change behavior.
- Schema-shape diagnostics require a chronologically paired, non-error
  `tools/list` response. A payload merely containing a `tools` field, an orphan
  response or an ambiguous ID exchange is not enough to attribute a schema
  problem to the tool catalog. This is not full result-envelope validation.
- Transcript quality gates diagnosis quality. A capture that starts
  mid-session can produce orphan-response noise and tentative absence-based
  findings (flagged as such).
- The argument validator checks the top level of `inputSchema` (required,
  primitive types, enum, additionalProperties, boolean subschemas). Unknown or
  unsupported JSON Schema constructs are ignored - never reported as
  violations - so a valid schema is not flagged for using features the
  validator does not understand.
- Config checks cover the common cross-client cases. Deep client-specific
  quirks belong to dedicated client checkers.

## Development

```bash
python -m pip install . pytest
python -m pytest -q                   # full suite, including parametrized controls
python -m unittest discover -s tests # original stdlib-only subset
```

The `examples/` folder holds synthetic transcripts for the main failure modes
plus healthy sessions for both supported protocol revisions (2025-11-25
handshake and 2026-07-28 per-request versioning); a healthy capture must
produce zero findings, and the CLI end-to-end tests enforce that.

## Authorship

Developed with AI assistance for implementation, tests, documentation and review.
Anish Pentyala sets project direction; this does not imply he personally wrote,
ran or reviewed every change. All examples and fixtures are synthetic; no real
user data is included.

## Sources

Protocol behavior is grounded in the official specification (primary):

- MCP specification 2025-11-25, Lifecycle (version negotiation, `initialized`
  notification): https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle
- MCP specification 2025-11-25, Tools (`tools` capability, `listChanged`,
  `nextCursor` pagination): https://modelcontextprotocol.io/specification/2025-11-25/server/tools
- MCP specification 2025-11-25, Transports (`MCP-Session-Id` 400/404,
  `MCP-Protocol-Version` header):
  https://modelcontextprotocol.io/specification/2025-11-25/basic/transports
- MCP specification 2026-07-28, Versioning and Compatibility (`server/discover`,
  per-request `_meta` version, `-32022` UnsupportedProtocolVersionError, era
  detection and fallback):
  https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning
- MCP specification 2026-07-28, Tools (`ttlMs`/`cacheScope`, per-authorization
  list variation, `x-mcp-header` client-side rejection):
  https://modelcontextprotocol.io/specification/2026-07-28/server/tools

Failure-mode cataloging and demand evidence (secondary, practitioner):

- mcptest.io, "MCP server connected but no tools: how to find the cause":
  https://mcptest.io/learn/mcp-server-connected-but-no-tools
- The Code Guy, "The MCP Reality Check in 2026":
  https://www.thecodeguy.co.uk/blog/the-mcp-reality-check
- Taraghi, Morovati, Khomh, "Real Faults in Model Context Protocol (MCP)
  Software: a Comprehensive Taxonomy": https://arxiv.org/abs/2603.05637

## License

MIT

### Malformed request identifiers

MCP request IDs must be strings or integers. Messages with boolean, fractional,
array, object or null IDs remain available as evidence but are excluded
from request/response pairing and tool-schema discovery. `INVALID_RPC_ID` is a
high-severity finding instead of a crash or a misleading match (`true` must not
match integer `1`). Integer `1` and string `"1"` remain distinct. Integral JSON numbers such as
`1.0` and `1e0` pair with integer `1` without truncating fractional IDs. A null-ID error
for a malformed request whose identifier could not be read is exempt and stays
unpaired. Exponent-form IDs needing 4301 or more decimal integer digits are outside the
parser's supported range and receive the same diagnostic without expansion.
This is targeted identifier validation, not a complete JSON-RPC schema
validator; direction ambiguity and incomplete-capture caveats still apply.

Source: [MCP 2026-07-28 basic messages](https://modelcontextprotocol.io/specification/2026-07-28/basic),
checked 2026-11-02; the 2025-11-25 basic spec has the same ID type rule.

### Tool-schema evidence

Argument explanations use schemas only from the first response to a unique,
earlier captured `tools/list` request with the same ID type and value. Orphan
responses, unrelated methods and duplicate responses do not supply schemas.
A repeated ID anywhere before the diagnosed call makes that ID ambiguous in
an untagged bidirectional capture, so its schema evidence is omitted. This can
reduce detail for captures with valid sequential ID reuse, but avoids guessing
which side or method owns the response. Other unique exchanges still contribute.
Later messages outside the diagnostic's capture cutoff cannot change earlier
schema evidence. This is a conservative evidence filter, not direction detection
or complete protocol validation.

### Unusable parameter evidence

Explicit non-object `params` on captured `initialize` and `tools/call` requests
produce high-severity `UNUSABLE_PARAMS` findings. The original parsed object is
retained, diagnostic evidence receives the existing best-effort redaction, and
parameter-specific explanations are omitted instead of treating a malformed
value as an empty object or crashing. Missing params keep the existing behavior.
This targeted guard is not complete method-schema validation; other diagnostic
rules can still report independent evidence from the same exchange.

### Pagination evidence

Pagination follow-through requires a later captured `tools/list` request with
the exact string cursor returned by a page response. An earlier request cannot
prove that a later page was followed. Empty strings are valid opaque cursors,
not an end-of-results signal. Explicit non-string cursors produce high-severity
`UNUSABLE_CURSOR`, remain as evidence and do not satisfy continuation checks.
These checks cannot prove completeness outside the capture or distinguish
concurrent list contexts that share a cursor in an untagged log.

Source: [MCP pagination](https://modelcontextprotocol.io/specification/2026-07-28/server/utilities/pagination),
checked 2026-11-02. The specification calls cursors opaque string tokens and
explicitly says an empty string must not be treated as the end of results.

### Safe schema evidence

The supported top-level `required` check uses only arrays of unique strings.
Malformed values produce `SCHEMA_ISSUES` and do not supply missing-argument
explanations. Other supported checks still run. Enum comparison respects JSON
types recursively: boolean `true` does not equal number `1`, including inside
arrays or objects; numerically equal `1` and `1.0` do match. This is a targeted
subset, not a complete JSON Schema validator or support for arbitrary schemas.

Sources: [JSON Schema validation](https://json-schema.org/draft/2020-12/json-schema-validation)
(required and enum) and [JSON Schema core](https://json-schema.org/draft/2020-12/json-schema-core)
(instance equality), checked 2026-11-02.

### Report masking

Text and JSON reports apply the existing best-effort credential masker to their
source label and free-text finding fields. Stdio pollution samples are masked
before clipping. Finding objects are not changed by rendering. This closes known
paths that copied Authorization/Bearer headers, token-like JSON/query values or
URL credentials into reports. It is not a complete sanitizer: unknown formats,
ordinary text and arbitrary tool output may still contain sensitive data. Review
reports and captures before sharing them; no raw log is made safe by this guard.

### Response evidence and reused IDs

A response can answer only an earlier, uniquely outstanding request with the
same ID type and value. An orphan response cannot hide a later `tools/list`
hang, and an earlier completed reuse does not answer a new request. Sequential
reuse is supported when each response completes before the next request.

If the same typed ID is requested again while outstanding, direction and
ownership cannot be proven in this untagged capture. Neither overlapping request
nor later requests with that ID receive a guessed response. Earlier completed
pairs and other IDs are unaffected. `DIRECTION_AMBIGUOUS` keeps absence-based
conclusions tentative. Delayed duplicate responses remain indistinguishable
from a response to a later sequential reuse; use distinct IDs or direction-tagged
captures when that distinction matters.

Malformed JSON-RPC error codes and missing/non-string `tools/call` names produce
`UNUSABLE_ERROR_CODE` or `UNUSABLE_TOOL_NAME` instead of a crash or a guessed
code-specific/schema explanation. Integral numeric error codes retain their
mathematical integer meaning; booleans and numeric strings are not coerced.
Other supported checks keep running. These checks are not a full message validator.

Known credential forms in tool error content are masked before shortening the
`TOOL_CALL_FAILED` explanation, including long URL userinfo and quoted JSON
values whose closing delimiter would otherwise be clipped. This uses the same
best-effort masker and does not cover arbitrary secret formats.
The matcher also covers one JSON-string layer of escaped key/value quotes for
its listed credential keys. Arbitrary encoding layers and escaped characters
inside secret values are not a complete masking guarantee.

Config checks validate field shapes before using them: `command`, `url` and
`envFile` must be strings, `args` an array of strings and `env` an object of
string values. Malformed values produce `CFG_SHAPE` without echoing those values;
they cannot count as launch or endpoint evidence. These remain shared-format
checks rather than a guarantee that any specific client will accept the config.

For supported `type: integer` argument checks, integral JSON numbers such as
`1`, `1.0` and `1e0` satisfy the type. Booleans, numeric strings and fractional
numbers do not. This does not add arbitrary-precision decoding for argument
values or turn the checker into a full JSON Schema validator.

The missing initialized-notification check requires a paired object-valued
initialize result without an error, and a notification must occur after that
response to count as completion. Error responses and malformed result shapes
are not described as successful initialization. This does not fully validate
the initialize result schema or distinguish reconnect sessions in untagged logs.

Malformed paired non-error `tools/list` results produce `UNUSABLE_TOOLS_CATALOG`
when the result is not an object with a tools array, or an entry is not an object
with a string name. Other checks continue. This does not validate every field,
name convention, schema or JSON-RPC result envelope.
