# VS Code environment-value evidence

Checked 2026-11-07. This is a narrow configuration-format correction, not a full VS Code validator or an execution test of VS Code.

- Official reference: https://code.visualstudio.com/docs/agents/reference/mcp-configuration
  - Describes the VS Code format as a top-level `servers` object and portable configurations as `mcpServers`.
  - The stdio field table says: `env` / `No` / `Environment variables for the server. Values can be strings, numbers, or null.`
- Actual current VS Code source, pinned commit b4bd9bd3c0171f72f54d742b8152db735fd9ce0a:
  https://raw.githubusercontent.com/microsoft/vscode/b4bd9bd3c0171f72f54d742b8152db735fd9ce0a/src/vs/workbench/contrib/mcp/common/mcpConfiguration.ts
  - The stdio schema's `env.additionalProperties.anyOf` lists `{ type: 'null' }`, `{ type: 'string' }`, `{ type: 'number' }`.
  - Fetched file SHA256: 8409b96acb10a18b83dbd668fed863ef45d02a5967ef3128e33ae3f606847406.
- Matching source type:
  https://raw.githubusercontent.com/microsoft/vscode/b4bd9bd3c0171f72f54d742b8152db735fd9ce0a/src/vs/workbench/contrib/mcp/common/mcpTypes.ts
  - `readonly env: Record<string, string | number | null>;`

The checker previously applied its string-only contract to both formats, producing a false `CFG_SHAPE` for supported VS Code values. The fix uses the map actually selected by the existing `_servers_from` precedence, not the mere presence of a `servers` key. It does not widen `mcpServers`, change map precedence, convert values into strings, apply environment settings, or launch a server.

Boolean values remain unsupported because booleans are not JSON Schema numbers. Nonfinite Python float results from exponent-overflow JSON are not accepted as usable numeric environment values. Malformed containers and whole-field types remain diagnosed without captured value text. Numeric or null values do not enter the existing string environment-reference scan; string values still do.
