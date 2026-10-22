# UFC3 transport contract

Milestone 2 supplies a bounded reliable ordered stream, independently testable
transport state, and a file adapter. CONGESTION.md defines BBR-inspired control.
SSH.md defines the implemented authenticated copy session and accepted SSH/TCP
fallback. This document retains the legacy UFC3 datagram contract used inside
both adapters; legacy send/recv remain unauthenticated controlled-test commands.

## Wire format

All integers are unsigned big endian. Header: magic `UFC3` (4 bytes), type (1),
reserved zeros (3), session (8), stream offset (8), payload length (2), CRC32 (4).
CRC covers the first 26 header bytes and payload. Maximum datagram is 1,062 bytes.
Other versions are rejected by the decoder and silently discarded by endpoints;
a sender times out when no compatible endpoint responds.

Types: START=1, DATA=2, FINISH=3, ACK=4, PROBE=5.
START offset is zero and payload is stream size (8). Its ACK payload is START (1)
and initial absolute receive limit (8). Repeated START must declare the same size.
DATA payload is attempt number (8), followed by 1-1,024 bytes. Offsets are aligned
to 1,024; lengths must equal min(1,024, stream size minus offset).
FINISH offset is stream size and payload is whole-file CRC32 (4); its ACK payload
is FINISH (1). PROBE has offset zero and no payload; it requests a current DATA
ACK. ACK-only packets never elicit ACKs.

DATA ACK has offset zero and payload: DATA (1), receive limit (8), ACK delay in
microseconds (4), range count (1), then 0-32 inclusive attempt ranges (low/high,
8 bytes each). Ranges are ascending, disjoint, nonadjacent and nonzero. Zero
ranges support credit-only updates and probes. Bad lengths, excessive delay,
and ranges including unsent attempts invalidate the entire ACK atomically.
ACK delay is bounded to 25 ms. RTT uses local elapsed time without subtracting
peer delay. Maximum ACK payload is 526 bytes.

## Bounds and retention

Defaults: a 4,096-chunk sending cap, 4,096 receive chunks (4 MiB), 16 chunks per file queue,
adaptive DATA pacing, a 5 ms ACK timer and an ACK every two accepted DATA packets.
The fixed test baseline (`--cc=fixed`) uses 1 ms DATA pacing.
Sending window and receive capacity are configurable from 1 to 8,192 chunks.
Pacing keeps its own schedule: each DATA send moves the next deadline one interval
past the previous deadline, with at most four intervals of catch-up, so loop overhead
does not lower the rate. The copy loop sends up to 16 due DATA packets and reads up
to 64 datagrams per pass.
The receiver retains the most recent 32,768 accepted attempt numbers for duplicate
checks and coalesces receipts into ranges as they arrive (at most 64 retained), so
each ACK costs O(32), and sends the newest 32 ranges. Dropped older receipt history
is recovered by a new DATA attempt. Duplicate DATA is acknowledged after stream
consumption too. ACK delay is measured from the oldest pending ACK trigger.

The sender retains at most 32,768 attempt records and its configured window of
payload chunks. In-flight attempt records are never evicted. ACKed records are
removed at once, so later ACK ranges only visit unacknowledged attempts; lost records
are retired oldest first when space is needed; losing historical ACK eligibility
never discards an undelivered payload. Every DATA send gets a new number. Each
attempt has independent flight state. ACK or loss releases flight bytes once;
a late ACK can deliver its chunk without releasing flight bytes again. ACKing a
second attempt of that chunk cannot inflate unique delivery. Redundant attempts
remain in flight until ACKed or timed out. Each send, ACK and loss exposes an
event with attempt number, offset, size, send time, event time and whether logical
bytes were newly delivered. The caller drains events each network tick; the
bounded event queue fails explicitly if a caller neglects this contract.

The receive limit is consumed offset plus capacity, capped at stream size. It
only increases. Accepted data remains retained until the consumer confirms its
ordered write. The writer queue holds bounded copies; scheduling a write does
not grant credit. Reader queue and pending payload storage are bounded separately.
The standalone state machine supports zero initial capacity and later capacity
increase; the file command starts with positive configured capacity.

## Recovery and completion

Initial RTO is 200 ms. Per-attempt RTT samples update smoothed RTT (1/8) and
deviation (1/4), with at least 1 ms granularity headroom and RTO clamped to 50-2,000 ms. Distinct attempt numbers make
these samples unambiguous. Chunk retry backoff doubles up to 2 seconds, with at
most ten retries. Gaps alone never imply loss: this milestone uses time-based
loss detection. DATA attempts are paced and constrained by a byte flight budget,
including retransmissions. Explicit PROBE uses a separate backed-off timer
(200 ms to 2 seconds) when feedback or receive credit is absent.

Ten seconds without new receipt or credit feedback fails the sender. Duplicate
ACKs cannot indefinitely extend that deadline. A locally starved producer with
no pending chunks is exempt from network feedback timeout. ACK timers run even
when traffic stops. Consumption triggers immediate credit ACKs. PROBE recovers
lost final credit updates even with no DATA in flight. Receiver idle timeout is
15 seconds; waiting for scheduled disk work does not count as peer silence.
START and FINISH use twenty attempts at 200 ms. Duplicate FINISH is answered for
five seconds after publication. Missing final confirmation reports an unconfirmed
outcome even if output was published.

The adapter verifies stream size and CRC32 before atomic publication by rename,
which replaces an existing destination file (keeping its permissions). It
accepts regular immutable source files and detects size/mtime/ctime changes.
Worker errors fail the session; ordinary receiver failure removes incomplete
output. Blocking file reads/writes run outside the pacing/ACK thread. Queue
cancellation wakes blocked workers; a blocked kernel filesystem operation can
still delay shutdown. Completion does not promise power-loss durability.

## Controller integration

`Sender::budget` supplies the pacing interval and flight-byte budget without
changing reliability. `Sender::events` exposes bounded per-attempt feedback;
`Sender::delivered` counts unique acknowledged stream bytes. The controller and
delivery sampler now use these interfaces; CONGESTION.md defines their rules. The core has no socket/filesystem
calls and all operations take monotonic microsecond timestamps from the caller.
The receiver exposes ordered `peek` and `consume` for other stream consumers.
The current adapter uses a known stream length; indefinite streaming needs a
separate end-of-stream control contract.

AEAD, SSH control, replay protection, SHA-256, and explicit fallback are now
implemented by copy, as specified in SSH.md. MTU discovery and production network
validation remain later work. Conservative datagrams do
not guarantee support for every possible path MTU; EMSGSIZE is reported clearly.
