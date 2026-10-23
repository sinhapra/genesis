# Userspace BBR-inspired controller

`src/congestion.hpp` is an independent C++17 implementation informed by Google's
BBRv3 controller and delivery-rate sampler. It does not copy reference source,
enable kernel BBR, or claim BBRv3 conformance. Conceptual reference revision:
`88aff899355d12fe1053997facec835aecd9f7d6`:

- [BBRv3 controller](https://github.com/google/bbr/blob/88aff899355d12fe1053997facec835aecd9f7d6/net/ipv4/tcp_bbr.c)
- [Delivery sampler](https://github.com/google/bbr/blob/88aff899355d12fe1053997facec835aecd9f7d6/net/ipv4/tcp_rate.c)

The implementation uses caller-supplied monotonic microseconds. The socket loop
feeds validated transport events into the controller, then applies its pacing
interval and flight-byte budget. Reliability, retry numbering, receiver credit,
and ordered consumption remain transport responsibilities. The wire stays UFC3.

## Delivery sampling

Each sent attempt records delivered bytes so far, last delivery time, first send
time of the sampling interval, actual send time, and a limited-sample marker.
ACK processing measures delivery since that snapshot over the larger of elapsed
send time and elapsed ACK time. Batched ACKs select the newest acknowledged send
snapshot after adding all newly acknowledged attempt bytes. This limits inflation
from ACK compression instead of dividing bytes by the latest inter-ACK gap.

Network delivery counts each acknowledged transmission attempt once, including
redundant attempts; file progress still counts unique logical bytes separately.
Loss releases attempt flight accounting once but retains bounded metadata for
late ACKs. The sampler keeps at most 32,768 records, retires non-flight records,
and rejects duplicate send IDs. Duplicate ACK/loss events do not inflate totals.
Idle epochs invalidate old bandwidth samples while preserving flight correctness.

The adapter marks a limited period when no data is eligible under source/retry
availability and receiver credit, with unused congestion-window capacity. The
marker persists until delivered bytes pass its delivery boundary. Samples marked
limited may increase bandwidth estimates but never lower them or declare startup
complete. This is conservative: retry waiting is treated as limited too.

## Model and state rules

All rates and flight counts use DATA payload bytes, not IP/wire overhead. The
initial assumed RTT is 100 ms and initial pacing is 81,920 B/s. Telemetry reports
zero minimum RTT until a real sample exists. Absolute rate bounds are 16,384 to
100,000,000 B/s; the payload window is bounded by `--window` (1-8,192 chunks,
default 4,096).
The congestion window is sized from the bandwidth estimate times max(minimum RTT, 1 ms),
so sub-millisecond LAN paths tolerate OS scheduling and ACK batching instead of
stalling on a window of a few packets; paths above 1 ms are unaffected.
These operating limits and retry/idle timeouts restrict supported paths; the rate
floor is unsuitable for paths below 16 KiB/s without further tuning/validation.

| Mechanism | Implemented rule |
| --- | --- |
| Bandwidth filter | Maximum eligible delivery sample over ten eligible packet-delivery rounds |
| Delivery round | ACK snapshot's prior delivery reaches the previous delivered-plus-flight boundary |
| RTT filter | Smallest positive local send-to-ACK RTT; peer ACK delay is not subtracted |
| Initial window | Eight chunks, capped by the configured maximum |
| Minimum window | Four chunks, capped by the configured maximum |
| Model window | Two estimated BDPs plus two chunks, subject to loss and configured limits |
| Window growth | At most newly acknowledged attempt bytes per feedback batch |
| STARTUP | Pacing gain 2; leave after three eligible rounds without 25% bandwidth growth |
| DRAIN | Pacing gain 0.7; leave when flight is at most one modeled BDP |
| PROBE_BW | Gains 1.2, 0.8, then six phases at 1.0; each phase lasts at least max(minimum RTT, 10 ms) |
| PROBE_RTT | Enter after ten seconds without a lower RTT; reduce window to minimum, wait 200 ms after draining, require a fresh probe-era sample, then refresh RTT upward or downward |
| Loss limits | When running round loss fraction exceeds 2%, reduce pacing cap and flight cap by 30%, at most once per max(minimum RTT, 50 ms); stop bandwidth probing |
| Clean recovery | Each eligible loss-free round relaxes the rate cap by 25% and raises the flight cap by an increment that starts at one chunk and doubles per loss-free round until the next loss, similar to BBRv3's upward inflight probing |
| Feedback silence | After max(three minimum RTTs, 500 ms), halve pacing cap and reduce window to minimum; repeat at the same interval until feedback resumes |
| Idle restart | After no work/flight for max(minimum RTT, 200 ms), start a new sampling epoch, cap rate at initial pacing and window at eight chunks |

Loss does not abort an ongoing RTT probe. The controller's minimum RTT includes
receiver ACK scheduling and any unavoidable host scheduling time. Transport RTO
starts at one second before RTT is known. After feedback, it retains at least
25 ms of headroom above smoothed RTT for bounded ACK delay and host scheduling
jitter. This reduces false timeout losses; genuine loss recovery can take longer. Explicit transport probes remain backed
off control packets; DATA originals and retransmissions share controller budgets.

## CLI and validation

`--cc=bbr-inspired` is the default and selects our userspace controller, never kernel BBR.
`--cc=fixed` retains milestone 2's fixed pacing/window
baseline for controlled comparisons. `--pace-us` requires `--cc=fixed`; it cannot
silently override an adaptive controller. Successful adaptive transfers print a
summary with controller state, estimated bandwidth, pacing, window, RTT and bytes
declared lost. `copy --stats` reports the same quantities once per second on
stderr, plus a final summary. Declared loss can include spurious timeouts; it is
not a direct measurement of dropped datagrams.

`make test` runs sampler/state traces, actual transport/controller simulations,
and loopback file-transfer tests. `controller-test` writes CSV traces to
`tests/controller-stable.csv`, `tests/controller-capacity-rtt.csv`, and
`tests/controller-ack-compression.csv`. The deterministic experiments use a
finite 60 ms bottleneck queue, payload capacity 480,000 B/s, a six-second drop to
120,000 B/s starting at four seconds, recovery, and a propagation RTT change from
40 to 80 ms at fourteen seconds. A variant compresses returning ACKs into 20 ms
batches. Assertions check completion, useful utilization, lower pacing after the
capacity drop, recovery, RTT refresh, bounded history/window and low drop rate.
Two equal-RTT adaptive senders also compete on one 400,000 B/s simulated link.
See VALIDATION.md for measured results and sanitizer commands.

## Deliberate deviations and limits

This is a simplified BBR-inspired model, not a port of BBRv3. It omits BBRv3's
precise loss/ECN machinery, distinct long/short-term bandwidth and flight bounds,
randomized bandwidth-probe scheduling, ACK-aggregation compensation, detailed
recovery/undo rules, offload accounting, and Reno/CUBIC coexistence mechanisms.
It uses a fixed eight-phase cycle and simple loss caps/recovery instead. Loss
detection is the transport's time-based detector; reordering can cause spurious
loss and conservative rate reductions. Timers, gain constants, supported rate
bounds and memory limits are explicit project choices, not copied conformance
parameters. The 4 MiB default window (8 MiB maximum) bounds the supported
bandwidth-delay product. In a userspace emulation of a 75 ms, 40 Mbit/s path with
0.001% loss, copy reached 36.6 Mbit/s steady against 36.9 Mbit/s for kernel TCP;
this is not a substitute for cross-host measurement.

The simulations validate these chosen mechanisms, not Internet fairness or
equivalence to BBRv3. Cross-host/netem experiments, competing TCP traffic, real
MTU behavior, profiling and controller tuning remain system-validation work.
The copy command now supplies SSH authentication/control, encrypted UDP feedback
and payloads, and accepted SSH/TCP fallback; see SSH.md. Tunnel mode bypasses this
controller and DATA retry timers because outer TCP supplies those mechanisms.
Production network/security validation remains. Reference code was studied, not
vendored or adapted; the reference links identify conceptual provenance.
