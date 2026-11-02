"""Deterministic decoder rejection for runtime-independent error-path tests."""
import json
import pytest


@pytest.fixture
def rejected_nesting_depth(monkeypatch):
    # Python versions/builds have different (or no practical) JSON recursion
    # boundaries. Simulate rejection for our synthetic deeply nested records
    # at both entry points instead of asserting a fixed runtime limit or
    # constructing increasingly large inputs to find one.
    original_loads = json.loads
    original_decoder = json.JSONDecoder

    def reject_synthetic_depth(text):
        if '[' * 1000 in text or '{"x":' * 1000 in text:
            raise RecursionError('synthetic JSON decoder recursion limit')

    def loads(text, **kwargs):
        reject_synthetic_depth(text)
        return original_loads(text, **kwargs)

    class BoundedDecoder(original_decoder):
        def raw_decode(self, text, *args, **kwargs):
            reject_synthetic_depth(text)
            return super().raw_decode(text, *args, **kwargs)

    monkeypatch.setattr(json, 'loads', loads)
    monkeypatch.setattr(json, 'JSONDecoder', BoundedDecoder)
    return 2000
