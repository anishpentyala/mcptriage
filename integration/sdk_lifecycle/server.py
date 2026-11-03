"""Offline synthetic server for SDK2.3.0 catalog lifecycle qualification."""

import anyio
from mcp import types
from mcp.server import Server
from mcp.server.lowlevel.server import NotificationOptions
from mcp.server.stdio import stdio_server
from mcp.shared.exceptions import MCPError

state = {"epoch": 0}


async def listing(ctx, params):
    required = "before" if state["epoch"] == 0 else "after"
    return types.ListToolsResult(
        tools=[
            types.Tool.model_validate(
                {
                    "name": "subject",
                    "inputSchema": {"type": "object", "required": [required]},
                }
            ),
            types.Tool.model_validate(
                {"name": "change", "inputSchema": {"type": "object"}}
            ),
        ]
    )


async def calling(ctx, params):
    if params.name == "change":
        state["epoch"] += 1
        await ctx.session.send_tool_list_changed()
        return types.CallToolResult(content=[])
    required = "before" if state["epoch"] == 0 else "after"
    if required not in params.arguments:
        raise MCPError(code=-32602, message="synthetic required argument missing")
    return types.CallToolResult(content=[])


async def main():
    server = Server(
        "synthetic-catalog-lifecycle",
        version="0",
        on_list_tools=listing,
        on_call_tool=calling,
    )
    async with stdio_server() as (read, write):
        await server.run(
            read,
            write,
            server.create_initialization_options(
                NotificationOptions(tools_changed=True)
            ),
        )


anyio.run(main)
