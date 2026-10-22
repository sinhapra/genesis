# Transport and BBR-inspired controller validation

Environment: Debian WSL, GCC, Linux C++17 and pthreads; validated 2026-10-19.
The build uses `-O2 -Wall -Wextra -Wpedantic` without warnings.

## Reproduce

```sh
make test
g++ -std=c++17 -O1 -g -Wall -Wextra -Wpedantic -pthread \
  -fsanitize=address,undefined -fno-omit-frame-pointer \
  tests/transport.cpp -o transport-test-sanitize -lcrypto
ASAN_OPTIONS=handle_segv=0:detect_leaks=0 UBSAN_OPTIONS=halt_on_error=1 \
  timeout 30s ./transport-test-sanitize
g++ -std=c++17 -O1 -g -Wall -Wextra -Wpedantic -pthread \
  -fsanitize=address,undefined -fno-omit-frame-pointer \
  tests/controller.cpp -o controller-test-sanitize
ASAN_OPTIONS=handle_segv=0:detect_leaks=0 UBSAN_OPTIONS=halt_on_error=1 \
  timeout 30s ./controller-test-sanitize
```

The sanitizer settings avoid recursive AddressSanitizer signal-handler failure
observed in this WSL environment. Address/undefined-behavior instrumentation stays
enabled; leak detection and ASan's SIGSEGV handler are disabled. The deterministic
transport, disk-worker and controller tests pass under these settings. No leak-check claim
is made. Normal `make test` requires no sanitizer environment settings.

## Authenticated sessions and accepted fallback

The SSH/session increment adds OpenSSL libcrypto as a build dependency. `make test`
also runs session-test and sixteen remote-session acceptance groups in
tests/remote.py. Those local exec fixtures validate the binary session protocol;
they do not replace authentication tests. `make ssh-test` separately uses a real
unprivileged loopback OpenSSH server with temporary keys and configuration:

```sh
UFCP_TEST_SSHD=/path/to/sshd make ssh-test
```

Validated using an OpenSSH server extracted into /tmp for testing, without package
installation, an installed service, account-key changes, firewall rules, router
changes, privileged ports, or TUN configuration. All six real-SSH cases pass:
forced SSH/TCP, automatic encrypted direct UDP, automatic fallback, a quoted
helper executable path, rejection of an unauthorized key, and host-key mismatch.

| Area | Session evidence |
| --- | --- |
| Encryption/authentication | OpenSSL ChaCha20-Poly1305; invalid tags, wrong keys and modified nonce headers rejected |
| Replay safety | Duplicate rejection, reordered valid packets, stale-window rejection, forged high counter cannot advance state |
| Session selection | Default CLI, full-size bidirectional probe, direct/tunnel/fallback telemetry, strict UDP refusal |
| Impaired encrypted UDP | End-to-end loss, corrupted authentication tags and replayed datagrams recover with exact output |
| Tunnel semantics | Flow ACKs remain, but no userspace controller, DATA retry/loss timers or UDP probes |
| Bounded framing | Fragmented/coalesced frames, invalid type/length/setup rejection, bounded nonblocking queues |
| File integrity | Known SHA-256 vector, empty/binary files, wrong final SHA-256 rejected before publication |
| File/path policies | Spaces/quotes/shell metacharacters treated as path data, scp-like overwrite keeping permissions, directory destination refused, slow disk queues |
| Failure outcomes | SSH EOF removes incomplete output; published output survives disconnect; missing COMPLETE produces unconfirmed sender outcome |

Sanitized session/helper checks also pass with this WSL-specific non-PIE build:

```sh
g++ -std=c++17 -O1 -g -Wall -Wextra -Wpedantic -pthread \
  -fsanitize=address,undefined -fno-omit-frame-pointer -no-pie \
  tests/session.cpp -o session-test-sanitize -lcrypto
g++ -std=c++17 -O1 -g -Wall -Wextra -Wpedantic -pthread \
  -fsanitize=address,undefined -fno-omit-frame-pointer -no-pie \
  src/ufcp.cpp -o ufcp-sanitize -lcrypto
ASAN_OPTIONS=handle_segv=0:detect_leaks=0 UBSAN_OPTIONS=halt_on_error=1 \
  ./session-test-sanitize
ASAN_OPTIONS=handle_segv=0:detect_leaks=0 UBSAN_OPTIONS=halt_on_error=1 \
  python3 tests/remote.py ./ufcp-sanitize
```

The initial PIE helper sanitizer build intermittently exited with SIGSEGV during
process startup without a code diagnostic; non-PIE removes that observed WSL
startup failure. The existing signal-handler/leak-detection workaround remains
explicit. No leak-check or cross-host production-security claim is made.

## Acceptance evidence

| Area | Evidence |
| --- | --- |
| Attempt accounting | Original timeout, new attempt, late original ACK, duplicate ACK, retry ACK; flight released once per attempt and logical bytes once per chunk |
| Bounded state | Three deterministic 6 MiB simulations (seeds 7, 91, 2026); send history reaches but never exceeds 4,096, payload slots stay within 32, receive buffers within 4, flight within budget |
| Receipt retention | More than 8,000 sparse attempt numbers; receiver history bounded to 4,096, encoded ACK ranges bounded to 32 |
| Flow control | Zero initial capacity, lost updates, explicit probes, monotonic capacity increase, small receive window, delayed consumption |
| ACK validation | Truncated/oversized packets, invalid range order/count, overlapping/unsent ranges, excessive ACK delay; invalid ACKs do not partially update state |
| Wire validation | Version, reserved bytes, CRC, lengths, overflow offsets and malformed DATA |
| Recovery | DATA/ACK loss, 600 ms ACK blackout, burst loss, tail loss, corruption, duplicates, delayed originals and reordered ACKs |
| File workers | Slow producer/consumer integration, `/dev/full` write failure, read failure, queue bound, blocked-producer cancellation |
| Completion | Empty/binary/exact-boundary/4 MiB files, overwrite policy, source mutation, incomplete cleanup, lost final confirmation |
| Controller boundary | Replaceable pacing and byte-flight budget; bounded per-attempt send/ACK/loss events with unique-delivery flags |

The integration suite passes 22 acceptance cases/groups, including the delayed
comparison and CLI bounds. Transfers verify exact output contents and removal of
temporary output after normal success; source-mutation failure also checks cleanup.
Default transfers exercise adaptive control and assert its completion telemetry.
Fixed-mode comparisons remain explicit; an additional delayed transfer uses
the default BBR-inspired controller. Invalid controller selections and attempts
to override adaptive pacing with --pace-us are rejected before starting a session.

## Controller evidence

Independent sampler traces validate send/ACK snapshots, compressed ACK bursts,
application/flow-limited propagation, late redundant ACKs, duplicate loss/ACK
events, bounded history and idle epochs. State traces check startup plateau,
drain, bandwidth probing, upward RTT refresh, loss response, limited samples,
feedback silence and idle restart. Transport regressions maintain at least
25 ms RTO headroom after 100 identical 80 ms RTT samples, accept a subsequent
100 ms ACK without timeout loss, and avoid initial false loss at 205 ms RTT.

The deterministic simulator runs the actual transport and controller over a
finite bottleneck queue. Payload capacity is 480,000 B/s, with a drop to
120,000 B/s from seconds 4-10 and propagation RTT increasing from 40 to 80 ms at
second 14. The compressed-ACK variant batches returns into 20 ms intervals.
Every run verifies full 6 MiB delivery, bounded state and flight windows, loss
fraction below 5%, lower pacing after the capacity drop, capacity recovery and
RTT refresh. The stable case also requires utilization above 75%.

| Scenario | Payload goodput | Max queued delay before drop decision | Dropped DATA attempts |
| --- | --- | --- | --- |
| Stable 480,000 B/s path | 439,800 B/s (91.6% utilization) | 45.08 ms | 0% |
| Capacity drop/recovery and RTT increase | 284,466 B/s | 65.23 ms | 0.44% |
| Same changes with ACK compression | 222,628 B/s | 65.93 ms | 0.61% |

Queue admission is capped at 60 ms; the displayed maximum includes candidates
that were rejected. CSV traces are regenerated under tests/controller-*.csv by
controller-test. A separate two-sender, equal-RTT experiment on a shared
400,000 B/s link completes both 2 MiB transfers in 12.062 s with Jain's fairness
index 0.9828 measured at first completion. This is one deterministic scenario,
not proof of fairness against TCP or across mixed RTTs.

## Delayed-path comparison

Identical 64 KiB payload, proxy adds 10 ms in each direction, same engine and
default fixed pacing, only the sending-window setting changes:

| Sending window | Sender elapsed time |
| --- | --- |
| 1 chunk (stop-and-wait behavior) | 1.463 s |
| 32 chunks | 0.146 s |

Observed speedup: 10.02x. Times include setup and final confirmation but exclude the
receiver's five-second completion linger. This is a reproducible loopback
comparison, not a cross-machine throughput target or Internet fairness result.

Two-host testing, network namespaces, competing flows, path MTU discovery,
real-network controller/security validation remain later milestones. SSH and
authentication are now implemented and covered by the session tests above.


## Timeout performance experiment (2026-10-20)

WSL loopback legacy UDP transfers through the Python relay, adding 100 ms each
way. One run per configuration, 4 MiB payload, BBR-inspired control explicitly
enabled. Sender time includes setup/final confirmation, excludes receiver linger.
Every output passed SHA-256 verification. No relay packet drops were configured.

| Sender window / receiver chunks | Before | After timeout change | After goodput | Declared loss before / after |
| --- | --- | --- | --- | --- |
| 32 / 64 | 49.592 s | 29.131 s | 0.137 MiB/s | 10,240 / 0 bytes |
| 256 / 256 | 37.254 s | 5.244 s | 0.763 MiB/s | 9,216 / 0 bytes |

The initial RTO changes from 200 ms to 1 second. Minimum smoothed-RTT headroom
changes from 1 ms to 25 ms; the variance-based extension and two-second maximum
remain. The initial timeout no longer collides with the configured 200 ms RTT.
The larger-window run is 7.10 times faster than its previous configuration.
The final adaptive window reaches 256 KiB rather than approximately 28 KiB.
These single-run measurements show improvement in this controlled delay test,
not a cross-host throughput guarantee. Longer timeout headroom trades slower
true-loss recovery for fewer spurious loss declarations. Existing impairment
and deterministic controller tests must remain passing.

Raw measurements: `benchmark-results.json` and `benchmark-tuned-results.json`.
Reproduce the updated delayed test with `python3 benchmark-tuned.py` in Linux
from the project root after `make ufcp`.
