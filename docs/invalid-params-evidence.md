# Invalid-params attribution evidence

Checked2026-11-09. External specifications describe semantics; error-message
text inside a capture is untrusted evidence, not a trusted diagnosis.

## MCP tools, current2026-07-28

https://modelcontextprotocol.io/specification/2026-07-28/server/tools

Error Handling lists protocol errors including:

> Unknown tool
> Malformed requests (requests that fail to satisfy CallToolRequest schema)
> Server errors

Its concrete JSON-RPC example has:

```json
{"code": -32602, "message": "Unknown tool: invalid_tool_name"}
```

It separately lists input validation errors under tool execution errors,
reported in results with `isError: true`. The checker must not infer that any
particular error text is correct, or change successful/isError classification
based on an unsupported schema guess.

## MCP tools,2025-11-25

https://modelcontextprotocol.io/specification/2025-11-25/server/tools

The older version likewise lists unknown tools under protocol errors and gives
the same `-32602`/`Unknown tool: invalid_tool_name` example. This is not a newly
introduced2026-only meaning.

## JSON-RPC2.0

https://www.jsonrpc.org/specification

The error-code table defines:

> -32602 | Invalid params | Invalid method parameter(s).

That identifies a category, not the MCP inputSchema field or server component
that caused a particular rejection.

## Implemented boundary

Only a chronologically owned usable tools/call response with the exact integral
code-32602 is considered for argument-schema detail. A supported violation from
an unambiguous earlier tool catalog retains TOOL_CALL_ARG_MISMATCH. Otherwise
TOOL_CALL_PROTOCOL_ERROR retains the rejection without inventing its cause.
Independent violations do not prove the server's causal reason either.

No unknown-tool classification is inferred from message wording or from absence
in a possibly incomplete catalog. No general JSON Schema validator, new nested
keyword support, protocol-version negotiation or live-server reproduction is
claimed. High severity and exit behavior do not change. The example and tests
are synthetic; no adoption or user-traffic claim.
