# Captured cancellation evidence

Official pages fetched November9,2026. This is a narrow offline notification
rule, not a live cancellation or transport-conformance test.

https://modelcontextprotocol.io/specification/2025-11-25/basic/utilities/cancellation

> Receivers of cancellation notifications SHOULD:
> - Stop processing the cancelled request
> - Free associated resources
> - Not send a response for the cancelled request

The same section says receivers MAY ignore unknown/completed/uncancellable
requests, and says task-augmented requests must use tasks/cancel instead.
Invalid cancellation notifications should be ignored. The initialize request
must not be cancelled. Cancellation references a previously issued request in
the same direction that is believed still in progress.

https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/cancellation

> Servers receiving cancellation notifications SHOULD:
> - Stop processing the cancelled request
> - Free associated resources
> - Not send a response for the cancelled request

The transport section distinguishes stdio notifications from Streamable HTTP
stream closure. Server-sent notifications in this revision are limited to
subscriptions/listen. These differences mean an undirected capture cannot
establish actual sender direction or HTTP cancellation from JSON-RPC alone.

## Test boundary

Synthetic initialized-session capture: list request2, notification referring to
request2, then end of file. Baseline diagnoses HIGH TOOLS_LIST_HANG and states a
backend/proxy cause. Candidate emits MEDIUM TOOLS_LIST_CANCELLATION_OBSERVED and
states receiver acceptance/cause are not proven. Uncancelled requests remain
high. The notification is not a successful list response or catalog evidence.

Controls include exact integer/string/numeric-wire identity, no bool aliasing,
malformed params/envelopes, prior and stale notifications, ID reuse, overlap,
new initialization, recognized bidirectional methods, task augmentation,
response races, unrelated pending lists and reason-payload omission.

No user capture, actual timeout or external adoption is claimed. A cancellation
can itself follow a real hang; this patch avoids inferring the cause from the
absence of a response alone, rather than proving the server was healthy.
