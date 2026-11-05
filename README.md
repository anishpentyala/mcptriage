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
mcptriage diagnose examples/tool-call-protocol-error.jsonl  # synthetic protocol failure, exit 1
```

Try the synthetic conflicting-response example:

```bash
mcptriage diagnose examples/conflicting-response.jsonl
```

It reports `UNUSABLE_RESPONSE` with exit code 1: a response containing both
`result` and `error` cannot establish an empty catalog or a protocol error.
The capture is synthetic and contains no credentials.

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
| NO_PROTOCOL_MESSAGES | high | empty capture or no recognized JSON-RPC messages |
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
| TOOL_CALL_PROTOCOL_ERROR | high | `tools/call` returns a valid JSON-RPC error other than the separately diagnosed `-32602` |
| TOOL_CALL_FAILED | medium | call returns `isError: true` (server-side, not protocol) |
| MISSING_INITIALIZED | low | no `notifications/initialized` after initialize |
| UNUSABLE_TOOLS_CATALOG | high | malformed tools/list result, tools array or entry/name shape |
| DUPLICATE_CATALOG_PAGE_NAMES | medium | accepted continuation repeats names from earlier linked catalog pages |
| SCHEMA_ISSUES | low | missing/invalid `inputSchema` in listed tools |
| ORPHAN_RESPONSES | low | responses with ids no request claims (broken framing) |
| INVALID_RPC_ID | high | null, boolean, fractional, array or object IDs that cannot pair safely |
| UNUSABLE_RESPONSE | high | conflicting result/error members or a non-object error payload |

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
  sanitization. Known JSON credential fields handle escaped quotes and
  backslashes directly and inside one encoded JSON-string layer. Deeper
  encodings or other credential formats can still leak; review any log before
  sharing it, and never commit raw
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
- Responses with both `result` and `error`, or a non-object `error`, are
  reported as `UNUSABLE_RESPONSE`. They cannot establish successful startup,
  a tool catalog, or a method-specific failure. Their chronological ownership
  is preserved, so a malformed reply is not called a missing reply. This does
  not validate every response field.
- Schema-shape diagnostics require a chronologically paired, non-error
  `tools/list` response. A payload merely containing a `tools` field, an orphan
  response or an ambiguous ID exchange is not enough to attribute a schema
  problem to the tool catalog. This is not full result-envelope validation.
- Transcript quality gates diagnosis quality. A capture that starts
  mid-session can produce orphan-response noise and tentative absence-based
  findings (flagged as such).
- Enum value comparison uses a non-recursive structural check, including nested
  JSON arrays and objects. Long or deeply nested mismatched enum values use a bounded
  explanation that omits values instead of displaying a truncated prefix. This does not expand the
  schema keywords the validator supports.
- Config transport `type` fields must be strings when present. Malformed values
  produce a shape finding without printing the value; unknown string transports
  keep the existing low-severity compatibility warning.
- Long version-mismatch error details are omitted in reports. If a captured supported-
  version value is too deeply nested to render, diagnosis keeps the error and
  uses a short placeholder instead of aborting. This is not version-list validation.
- Tool schemas are looked up for call-argument validation only after an invalid-
  params response with object arguments. Successful calls and other outcomes do
  not rebuild a catalog they do not use.
- A successfully observed first page of `tools/list` starts a fresh catalog for
  later argument checks, including when the new tools list is empty. Continuation
  pages keep earlier pages only when their exact opaque cursor was advertised
  by the preceding accepted page before the continuation request. Unlinked,
  stale, or speculative page replies cannot supply argument schemas. Empty
  string cursors remain valid; list-change notifications, an observed new
  initialize request, and a fresh first page reset the chain. An initialization
  attempt also invalidates old schema evidence, including after an error or
  without a captured reply; only a fresh listing can supply schemas afterward.
  This is conservative handling of reconnects in a combined capture, not
  automatic transport/session demultiplexing. Failed or malformed listings do not prove an empty
  catalog or consume an advertised cursor. Earlier calls retain their earlier observed schema evidence. This is
  not a complete pagination, cache, authorization or transport-session model.
- The argument validator checks the top level of `inputSchema` (required,
  primitive types, enum, additionalProperties, boolean subschemas). Unknown or
  unsupported JSON Schema constructs are ignored - never reported as
  violations - so a valid schema is not flagged for using features the
  validator does not understand.
- Config checks cover the common cross-client cases. Deep client-specific
  quirks belong to dedicated client checkers.

Unreadable transcript or config inputs exit with a concise stderr error and status
2, without publishing a partial report or echoing the raw OS error/path.
`--exit-zero` applies to diagnostic findings, not input-read failures. This does
not change the Python file-reading APIs, and internal errors are not hidden.

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

- JSON-RPC 2.0, Response object (exclusive result/error, object-valued error):
  https://www.jsonrpc.org/specification

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

Config checks validate field shapes before using them: `command`, `url`, `envFile` and
`type` must be strings, `args` an array of strings and `env` an object of
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

An empty capture or input containing no recognized JSON-RPC messages produces
`NO_PROTOCOL_MESSAGES` rather than "no problems found". Invalid-ID messages keep
their own finding. A recognized message is not proof of a complete or valid
session: capture-quality flags and the other supported checks still apply.

If the Python runtime rejects an oversized decimal integer during JSON decoding,
the original line stays unparsed instead of crashing the capture. Other lines
continue through diagnosis. The parser does not search inside that rejected
object for a nested substitute message. Runtime integer limits vary; this does
not add arbitrary-size integer support or silently coerce the number.

JSON decoder recursion-limit failures are handled the same way: retain the
original line as unparsed evidence and continue other lines, without extracting
nested substitute traffic. This is not arbitrary-depth parsing or a general
resource-containment guarantee.

Repeated JSON object member names are not unique protocol evidence. The parser
retains the original line but excludes the entire ambiguous object, including
prefixed log objects, from request/response pairing and startup/schema evidence.
`DUPLICATE_JSON_KEY` is a high-severity finding with the line number only; member
names and values are omitted from that diagnostic. No nested substitute message
is extracted. Other lines continue to be checked. This does not determine which
value a client or server used, validate a complete exchange, or repair its data.


Config JSON decoding failures caused by runtime integer or nesting limits produce
high-severity `CFG_JSON_LIMIT` without echoing rejected values. Ordinary JSON
syntax errors retain `CFG_JSON_ERROR` and their line/column position. A runtime
limit does not prove the JSON syntax itself is invalid; no server checks ran.

Repeated JSON object keys produce high-severity `CFG_JSON_DUPLICATE_KEY`.
For example, two `command` keys must not become a clean last-value-wins
launch check. This applies to every object in the config, including server
maps and nested environment maps; no server entries are checked until the
ambiguity is removed. Repeated names and values are not included in the
finding. It does not predict which duplicate value a particular client uses.
Same names in distinct objects and repeated array values remain valid.


Diagnosis builds one chronological response-ownership index for that pass and
shares it across rules. The index is not kept on the mutable caller session,
so a later diagnosis sees appended or removed messages. This reduces repeated
pairing scans for large tool-list captures; it does not make every rule linear
or change the documented uncertainty of untagged request-ID reuse. Catalog
snapshots for failed-call argument checks use a per-diagnosis projection of
catalog-relevant traffic: tools/list IDs (including other methods and replies
reusing those IDs), initialization attempts, and list-change notifications.
Repeated snapshots do not rescan unrelated call traffic. The projection keeps
references to existing messages, not copies of their payloads; it does not make
catalog-heavy captures linear or remove catalog/schema validation work.

Authentication-on-list heuristics inspect the paired JSON-RPC error object,
not outer request IDs, unrelated response metadata or log prefixes. Existing
401/unauthorized markers inside that error still count as heuristic evidence;
this is not HTTP-status parsing or proof of an authentication root cause.

For top-level argument properties, supported JSON Schema types include `null`
and nonempty arrays of unique supported type names, such as
`["string", "null"]`. A value must match at least one listed type. Nullable
values still need to be present when required and still obey an `enum`.
Malformed or unknown type arrays supply no type-violation explanation rather
than being narrowed to their recognized members. Nested schemas, `anyOf`,
`oneOf` and other JSON Schema keywords remain outside this targeted check.
See [JSON Schema type](https://json-schema.org/understanding-json-schema/reference/type)
and [null](https://json-schema.org/understanding-json-schema/reference/null).

Repeated names within one captured `tools/list` response produce a medium
`DUPLICATE_TOOL_NAMES` finding. No array-order winner is selected: schemas for
those names, including older definitions, are omitted from call argument
explanations. Other uniquely named tools remain usable. A later unique response
can provide a schema again, without rewriting calls sent before it. Identical
repeated definitions are still ambiguous; this does not detect collisions across
separate pages or servers. MCP recommends unique names within a server:
[Tool Names](https://modelcontextprotocol.io/specification/2026-07-28/server/tools).

Root `inputSchema.type` diagnostics keep canonical JSON type names, but omit
arbitrary strings, arrays, objects and other malformed values rather than
serializing them into report evidence. This is a targeted evidence guard, not a
complete output sanitizer or a complete JSON Schema validator. Existing handling
of missing/null root type declarations is unchanged.

A captured `notifications/tools/list_changed` notification invalidates prior
catalog schemas for subsequent calls until new paired `tools/list` evidence
arrives. Earlier requests keep their request-time evidence. This conservative
guard does not infer a replacement catalog from the notification or implement
full pagination, authorization, or catalog-refresh semantics.

An argument explicitly listed in `properties` is not labeled an additional
property merely because its captured property schema is malformed. Unsupported
property schema values supply no type evidence; actual undeclared names still
respect `additionalProperties: false`. This does not validate every schema.

Repeated invalid-params calls between catalog evidence changes share one
request-time catalog snapshot within a diagnosis. A tool-list request, response,
reused ID relevant to tool-list ownership, or tools/list_changed notification
ends that reuse window. Only the latest snapshot is kept, and no cache survives
a diagnosis call. This avoids repeating full catalog scans for an unchanged
catalog; captures alternating catalog changes and failed calls can still need
repeated scans. The ownership and request-time evidence rules do not change.

## Optional SDK transport qualification

[`integration/sdk_lifecycle`](integration/sdk_lifecycle/README.md) runs a local
synthetic MCP SDK2.3.0 stdio exchange through the diagnostics. It checks schema
evidence before a tool-list change, conservative invalidation, and recovery after
a fresh listing. It uses a separate Python3.10+ environment and does not add SDK
dependencies to this package. It is not a network, Windows, raw-framing or full
MCP-conformance claim.

### Startup context in list-error findings

A captured `tools/list` error does not by itself prove that initialization
succeeded. Authentication and protocol-error findings keep the observed list
failure, but describe startup success as unestablished unless the latest earlier
captured initialize attempt has an unambiguously paired object result before
that list request. When present, that response is cited as separate evidence.
A pending, failed, malformed, ambiguous or future initialize exchange does not
supply that context. Object-result evidence is not full InitializeResult
validation or proof that the application completed startup.

A successful observed first `tools/list` page (an object-valued request params
without `cursor`, or omitted params) starts a new schema-evidence listing.
Tools omitted from that refresh no longer supply argument explanations for
later calls. Continuation pages still merge their tool definitions, including
an empty-string cursor. Calls before the refresh retain their earlier evidence.
This does not prove authorization equivalence, cache lifetime or full pagination
completion, and does not infer an empty catalog from a failed list request.

### Physical transcript records

JSON Lines records are separated by LF; CRLF is accepted too. Unicode NEL,
LINE SEPARATOR and PARAGRAPH SEPARATOR inside JSON strings are data, not
record boundaries. Tool descriptions, arguments and string request IDs keep
those characters without losing the catalog or inventing a missing response.
Escaped and literal forms of the same Unicode string have the same protocol
meaning. This does not decode pretty-printed multi-line JSON or validate raw
transport framing.

### Overlapping catalog pages

A successful continuation linked to the preceding advertised cursor belongs to
one observed listing, not a fresh catalog. If it repeats a name from an earlier
accepted page, `DUPLICATE_CATALOG_PAGE_NAMES` points to the continuation response.
Argument explanations omit all definitions for that name for the rest of the
listing, even if their schemas look equal or a third page repeats it. Unique
names stay usable; earlier calls keep the evidence available when they ran.
A new first page or catalog invalidation resets this ambiguity.

Separate first-page refreshes, unlinked/stale/speculative continuations and
case-distinct names are not cross-page duplicates. Error replies, unusable RPC
responses and results without a tools array do not consume the cursor or
establish collision evidence. Other malformed entries retain existing handling. This is conservative
handling of one captured server's list, not proof of which definition a live
client selected, a multi-server naming model or full pagination validation.

The MCP tools draft says names "SHOULD be unique within a server" and that
`tools/list` supports pagination (checked November 4, 2026):
https://modelcontextprotocol.io/specification/draft/server/tools .
The check applies that identity assumption across accepted pages rather than
letting page order silently select a schema. The separate within-response
`DUPLICATE_TOOL_NAMES` finding is unchanged.

### Numeric schema evidence from captured JSON

For the supported `enum` and `integer` argument checks, decimal/exponent JSON
numbers retain their exact wire value rather than borrowing a rounded binary
float. This prevents `1.00000000000000001` from matching enum `1` or satisfying
`integer`, and keeps `9007199254740993.0` equal to enum `9007199254740993`.
JSON Schema defines numbers as arbitrary-precision base-10 values and numeric
equality by mathematical value:
https://json-schema.org/draft/2020-12/json-schema-core (sections 4.2.1 and 4.2.2),
https://json-schema.org/understanding-json-schema/reference/numeric
(rechecked 2026-11-05).

The parser uses float-compatible values carrying exact decimal metadata for
these checks. This is not a general exact-arithmetic public API: ordinary float
arithmetic or re-encoding parsed objects with `json.dumps` can still round.
Direct API callers passing ordinary Python floats cannot recover precision
already lost before parsing. Exponents outside Python Decimal's supported range
suppress schema-specific explanations for that schema/call rather than making
up a mismatch. The observed server rejection is still reported. Request-ID
size limits, boolean/number distinctions and unsupported-schema limits remain.
Integer-valued error codes also use the exact wire value, so fractional codes
rounded to an integer cannot borrow that integer's protocol meaning.

### Conservative additional-property explanations

The top-level argument checker reports an `additionalProperties: false`
violation only when `properties` is absent or an object and
`patternProperties` is absent or an empty object. JSON Schema also permits
names matched by `patternProperties`, so ignoring a nonempty pattern map
cannot establish that a name is additional. Malformed maps likewise provide
no such evidence. The checker does not execute captured regular expressions:
dialect differences and expensive patterns remain outside this small validator.

This suppresses only the uncertain extra-name explanation. Independent explicit
property type/enum/boolean-schema checks and valid `required` checks still run;
the observed server rejection remains a finding. Nonmatching names and false
pattern subschemas can therefore remain unexplained. This is conservative
partial diagnosis, not a claim the arguments satisfy the full schema.

### Malformed method evidence

A present JSON-RPC `method` must be a string. Null, boolean, numeric, array or
object methods produce `INVALID_RPC_METHOD` and remain in the raw message
record, but are excluded from requests, notifications, response pairing and
catalog projection. In particular, `method: null` plus `result` is not treated
as a response merely because the method value is falsey. This diagnostic takes
precedence over identifier checks on the same unusable message.

String method names, including unknown or empty names, retain the existing
classification. This is a type check, not full request validation or a claim
that a method name exists. A malformed method cannot supply an authoritative
tool schema even if a nested value resembles protocol traffic.

Explicit `jsonrpc` members must be the string `"2.0"`. Other values are
retained as `INVALID_RPC_VERSION` evidence and excluded from request/response
pairing and tool catalogs, preventing an explicitly wrong-version reply from
supplying a schema or an empty-tool explanation. Missing `jsonrpc` members
keep the existing permissive capture behavior. This is not full JSON-RPC
validation or automatic support for JSON-RPC 1.0.

Bare `NaN`, `Infinity` and `-Infinity` literals are Python JSON extensions,
not JSON numbers (RFC 8259 section 6). When decoding a transcript line scans
one of these literals, the whole line is retained as
`NONFINITE_JSON_CONSTANT` evidence, excluded from pairing and catalogs, and
no nested protocol-shaped substitute is extracted from it; the diagnostic
cites the line number without echoing line content. A literal in surrounding
text that decoding never scans does not trigger the guard. Configs containing
one return `CFG_NONFINITE_JSON_CONSTANT` without checking any server entries
or echoing values. Quoted strings and valid exponent-form numbers retain
existing behavior; this is not a complete JSON validator.

### Numeric bound explanations

After an observed `tools/call` invalid-params rejection, supported top-level
argument properties now check `minimum`, `maximum`, `exclusiveMinimum` and
`exclusiveMaximum` with numeric bounds. Inclusive bounds allow equality;
exclusive bounds reject it. Wire numbers use their exact decimal values, not
rounded binary floats, including very large or small exponents. Direct Python
float inputs use their represented binary value. The added explanation omits
both instance and bound values; existing report evidence still receives only
best-effort redaction, not a new privacy guarantee.

Missing, nonnumeric, boolean and nonfinite bounds supply no bound evidence.
Nonnumeric arguments supply no bound evidence either; supported `type`, `enum`
and `required` checks still run. Boolean draft-04 exclusive-bound modifiers, nested property
traversal and general JSON Schema validation are not added. Existing handling of wire exponents beyond Decimal's range remains
unchanged. Successful calls are not scanned for new schema violations.

Source: [JSON Schema validation 2020-12, sections 6.2.2-6.2.5](https://json-schema.org/draft/2020-12/json-schema-validation),
checked 2026-11-05. This is a supported-subset expansion, not a claim that the
previous version promised numeric-bound validation.

### String, array and object size explanations

After an observed invalid-params `tools/call` rejection, supported top-level
argument properties also check `minLength`/`maxLength` for strings,
`minItems`/`maxItems` for arrays and `minProperties`/`maxProperties` for objects.
Bounds must be nonnegative integer-valued numbers; booleans, fractions,
negative numbers, nonfinite values and other malformed bounds supply no
size evidence. Equality satisfies both inclusive limits.

String length counts decoded Unicode code points, not UTF-8 bytes or visible
grapheme clusters. Array size counts immediate elements and object size counts
immediate keys, without recursively validating their contents. Keywords for
another instance kind have no effect. New explanations omit the content and
bound values, but existing raw report evidence retains only its best-effort
redaction. Successful calls are not scanned for new violations. This is a
supported-subset expansion, not full JSON Schema validation or a claim that
the previous version promised these checks.

Source: [JSON Schema validation 2020-12](https://json-schema.org/draft/2020-12/json-schema-validation),
sections 6.3.1-6.3.2, 6.4.1-6.4.2 and 6.5.1-6.5.2, checked 2026-11-05.

### Numeric multiple explanations

After an observed invalid-params `tools/call` rejection, supported top-level
argument properties also check numeric `multipleOf`. The divisor must be a
finite number strictly greater than zero. Zero is a multiple of every valid
divisor; negative instances use the same divisibility rule as positive ones.
Booleans, nonnumeric values and invalid divisors supply no multiple evidence.

Captured wire numbers use their exact decimal values, so wire `0.3` is a
multiple of wire `0.1` without a binary-float remainder error. Direct Python
float arguments instead use their represented binary values. Decimal
coefficient arithmetic and modular exponentiation avoid materializing enormous
powers of ten. Values or divisors with more than 4,300 coefficient digits are
outside this check's supported work budget and supply no multiple explanation;
other supported checks still run. Existing beyond-Decimal-range handling is
unchanged. The new explanation omits numeric values; raw report evidence still
uses only best-effort redaction.

This is a supported-subset expansion after observed rejection, not full JSON
Schema validation or a scan of successful calls. Source:
[JSON Schema validation 2020-12, section 6.2.1](https://json-schema.org/draft/2020-12/json-schema-validation),
checked 2026-11-05.
