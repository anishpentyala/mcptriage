"""Runtime-grounded decoder rejection cases shared by hardening tests."""
import json
import pytest


@pytest.fixture
def rejected_nesting_depth():
    # CPython versions use different JSON recursion limits. Probe both shapes
    # rather than asserting that valid JSON at a fixed depth must be rejected.
    # Keep work bounded and fail, rather than skip, if the probe is insufficient.
    for depth in (1000, 2000, 4000, 8000, 16000, 32000):
        rejected = []
        for start, end in (('[', ']'), ('{"x":', '}')):
            try:
                json.loads(start * depth + '0' + end * depth)
            except RecursionError:
                rejected.append(True)
            else:
                rejected.append(False)
        if all(rejected):
            return depth
    pytest.fail('could not establish a JSON recursion rejection within depth 32000')
