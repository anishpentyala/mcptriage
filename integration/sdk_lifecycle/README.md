# Optional SDK stdio lifecycle check

This synthetic local client/server check records a whole MCP SDK 2.3.0 stdio exchange and verifies mcptriage's schema explanations before a list change, after invalidation, and after a fresh listing. It does not connect to a network service or need credentials. No SDK dependency is added to the main package.

Use a separate Python 3.10+ environment (the SDK's requirement):

```sh
python -m venv /tmp/mcp-sdk-check
/tmp/mcp-sdk-check/bin/python -m pip install -r integration/sdk_lifecycle/requirements.txt
/tmp/mcp-sdk-check/bin/python integration/sdk_lifecycle/run.py --head "$PWD" --output /tmp/new-sdk-capture
```

The output directory must not exist. It receives the whole model-serialized transport capture, findings and source fingerprints. Capture and diagnostic subprocesses have 30-second timeouts. A failed assertion or timeout exits nonzero and does not produce a success result.json. Source roots are never edited. Do not run the check with Python optimization enabled, which disables assertions.

For a negative control, add `--baseline /path/to/pre-list-change-source`. That baseline must produce the expected stale-schema explanation on the middle failing call; importing badly or crashing is not a successful negative control. The normal check needs no historical source checkout.

These are local synthetic stdio checks, not raw byte-framing validation, complete MCP conformance, network interoperability, Windows qualification or outside adoption. The main CLI remains Python 3.9+ and standard-library-only.

Run the optional harness checks in that same pinned environment:

```sh
/tmp/mcp-sdk-check/bin/python integration/sdk_lifecycle/checks.py -v
```

They are deliberately outside default pytest discovery, so Python 3.9 and main-package tests do not acquire an SDK dependency. Coverage includes whole-lifecycle capture, missing roots, existing output preservation, optimized-Python rejection, and a silent-server timeout.

Qualified locally on Linux with Python 3.10,3.13 and3.14 for the seven optional checks. Python 3.9-3.14 still pass the unchanged 1322-test core suite without installing MCP. These are distinct claims: the optional SDK does not support Python 3.9.
