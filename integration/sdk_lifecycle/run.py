"""Capture whole actual SDK exchange and compare selected baseline/head diagnostics.

No network, credentials, monkeypatched SDK, or omitted capture messages. Requires
mcp==2.3.0. Source roots are explicit arguments and are never written or imported
in the SDK process. Local synthetic interoperability only, not outside adoption.
"""

import argparse, json, os, subprocess, sys
from pathlib import Path
from importlib.metadata import version
import anyio
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.client.session import ClientSession
from mcp.shared.exceptions import MCPError
import hashlib


class Capture:
    def __init__(self, stream, rows):
        self.stream, self.rows = stream, rows

    async def send(self, item):
        self.rows.append(
            item.message.model_dump(mode="json", by_alias=True, exclude_none=True)
        )
        await self.stream.send(item)

    async def receive(self):
        item = await self.stream.receive()
        if not isinstance(item, Exception):
            self.rows.append(
                item.message.model_dump(mode="json", by_alias=True, exclude_none=True)
            )
        return item

    def __aiter__(self):
        return self

    async def __anext__(self):
        try:
            return await self.receive()
        except anyio.EndOfStream:
            raise StopAsyncIteration

    async def aclose(self):
        await self.stream.aclose()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.aclose()


async def _capture():
    rows = []
    params = StdioServerParameters(
        command=sys.executable, args=[str(Path(__file__).with_name("server.py"))]
    )
    async with stdio_client(params) as (r, w):
        async with ClientSession(Capture(r, rows), Capture(w, rows)) as client:
            await client.initialize()
            await client.list_tools()

            async def rejected():
                try:
                    await client.call_tool("subject", {})
                except MCPError as e:
                    assert e.code == -32602
                else:
                    raise AssertionError("synthetic invalid call unexpectedly accepted")

            await rejected()  # captured old definition
            changed = await client.call_tool("change", {})
            assert changed.is_error is not True, "change call failed"
            await rejected()  # invalidated, no fresh definition
            await client.list_tools()
            await rejected()  # captured new definition
            accepted = await client.call_tool("subject", {"after": True})
            assert accepted.is_error is not True, "valid call failed"
    return rows


async def capture():
    with anyio.fail_after(30):
        return await _capture()


DIAGNOSE = """import json,sys\nfrom mcptriage.rules import diagnose\nfrom mcptriage.transcript import parse_text\nfrom dataclasses import asdict\nprint(json.dumps([asdict(f) for f in diagnose(parse_text(sys.stdin.read()))]))"""


def findings(root, text):
    p = subprocess.run(
        [sys.executable, "-c", DIAGNOSE],
        input=text,
        text=True,
        capture_output=True,
        cwd=str(Path(root).anchor),
        env=dict(os.environ, PYTHONPATH=str(root)),
        check=True,
        timeout=30,
    )
    fs = json.loads(p.stdout)
    assert len(fs) == 3 and all(f["code"] == "TOOL_CALL_ARG_MISMATCH" for f in fs), fs
    return fs


def main():
    if not __debug__:
        raise RuntimeError(
            "run without Python -O: this qualification requires assertions"
        )
    p = argparse.ArgumentParser()
    p.add_argument("--baseline", type=Path)
    p.add_argument("--head", required=True, type=Path)
    p.add_argument("--output", required=True, type=Path)
    a = p.parse_args()
    a.head = a.head.resolve()
    if a.baseline is not None:
        a.baseline = a.baseline.resolve()
    for root in [a.head] + ([a.baseline] if a.baseline else []):
        if not (root / "mcptriage" / "rules.py").is_file():
            p.error("source root must contain mcptriage/rules.py: " + str(root))
    assert version("mcp") == "2.3.0", "qualification is pinned to SDK2.3.0"
    a.output.mkdir(parents=True, exist_ok=False)
    rows = anyio.run(capture)
    text = "\n".join(map(json.dumps, rows)) + "\n"
    (a.output / "capture.jsonl").write_text(text)
    assert len(rows) == 18, "unexpected pinned-SDK capture shape"
    calls = [row for row in rows if row.get("method") == "tools/call"]
    assert [row["params"]["name"] for row in calls] == [
        "subject",
        "change",
        "subject",
        "subject",
        "subject",
    ]
    assert calls[-1]["params"]["arguments"] == {"after": True}
    new = findings(a.head, text)
    old = findings(a.baseline, text) if a.baseline else None
    assert "missing required argument 'before'" in new[0]["why"]
    assert "missing required" not in new[1]["why"]
    assert "missing required argument 'after'" in new[2]["why"]
    if old is not None:
        assert "missing required argument 'before'" in old[1]["why"], old
    # Real complete trace proves fresh listing follows the middle failing call.
    methods = [r.get("method") for r in rows]
    assert (
        methods.count("notifications/tools/list_changed") == 1
        and methods.count("tools/list") == 2
    )
    summary = {
        "source_fingerprints": {
            label: {
                name: hashlib.sha256((root / name).read_bytes()).hexdigest()
                for name in ("mcptriage/transcript.py", "mcptriage/rules.py")
            }
            for label, root in [("head", a.head)]
            + ([("baseline", a.baseline)] if a.baseline else [])
        },
        "sdk": version("mcp"),
        "rows": len(rows),
        "baseline_root": str(a.baseline.resolve()) if a.baseline else None,
        "head_root": str(a.head.resolve()),
        "baseline": old,
        "head": new,
        "scope": "complete local synthetic stdio capture; no network/adoption claim",
    }
    (a.output / "result.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(
        "PASS:",
        len(rows),
        "actual SDK stdio messages; old definition, invalidation and fresh-definition recovery;",
        "baseline control checked" if old is not None else "no baseline requested",
    )


if __name__ == "__main__":
    main()
