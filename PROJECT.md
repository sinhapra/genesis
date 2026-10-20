# Reliable UDP File Transfer for Linux

Status: transport, BBR-inspired control, authenticated SSH sessions, encrypted UDP, SHA-256 completion, and accepted SSH/TCP fallback are implemented and tested. Daemon/UX work and production system validation remain. See README.md, PROTOCOL.md, CONGESTION.md, SSH.md, and VALIDATION.md for contracts and evidence.

## Original problem statement

Design and implement an efficient program in C/C++ that reliably and efficiently transfers files between two machines that are on the same or two different networks, both running Linux. The program can run in both daemon mode and via a simple command, just as scp. The program should be easy to modify to support streaming applications. Make the program as simple as possible. Don't use complicated packages, such as QUIC.

The program should:

1. Use UDP for data transfer.
2. Use BBR (V3) for congestion control; write your own source code instead of turning on the BBR flag in the kernel.
3. Work without requiring changes on either machine's router or firewall configuration. You may assume SSH is running on both machines and port 22 is open on both networks.

Please make your solution as simple and elegant as possible, and of course with data transfer performance in mind. You may use any open-source component and/or AI tool, but you need to own your code, i.e., you know and can explain every piece of the final code so that any modification/improvement can be made quickly by you if needed.

## Working direction

Build a sender-driven reliable transport over UDP, with selective acknowledgements and a small userspace congestion controller inspired by BBRv3. User clarification: a full BBRv3 implementation is not required. Describe the implemented subset and deviations explicitly; do not claim BBRv3 conformance.

Agreed design direction: keep SSH open for authentication, helper startup, metadata, key exchange, errors, and final results. Direct mode keeps file data, ACKs, receive limits, and probes on encrypted UDP. The user subsequently accepted explicit SSH/TCP fallback when native UDP is unavailable. Tunnel mode carries logical datagram records over SSH/TCP and disables userspace congestion control and datagram retransmission. Both use the bounded stream/file engine. Daemon mode and explicit cancellation/progress UX remain future work.

## Milestone 1: simple UDP file transfer

The user requested a simple UDP file-transfer implementation first. The original bootstrap used stop-and-wait DATA/ACK, fixed retries, session IDs, offsets, packet/file CRC32, temporary output, and no-overwrite publication. DATA is now windowed. Legacy send/recv retain UDP START/FINISH for controlled tests; the new copy command uses persistent SSH control, authenticated UDP or SSH/TCP payload, and SHA-256 finalization.

Limitations against the final requirements: no daemon, production streaming feature, IPv6, MTU discovery, or production system validation yet. Copy supports SSH/DNS names and IPv4 direct UDP; legacy send/recv require IPv4 literals. The controller is BBR-inspired, not BBRv3-conformant. Native UDP still requires reachability; accepted fallback carries payload over TCP and does not independently use our congestion controller. Legacy CRC32 alone detects accidental corruption; copy adds SSH, authenticated encryption, replay rejection and SHA-256. Publication is not power-loss durable; metadata checks do not provide source snapshot guarantees. Lost final confirmation can leave published output with an unconfirmed sender outcome.

The receiver uses bounded memory and acknowledges accepted data after buffering it or writing contiguous bytes. Normal errors remove incomplete output; crashes may leave a .part file which is never silently reused. The filesystem must support hard links for no-overwrite publication. Per-attempt history, delivery sampling, and BBR-inspired pacing/flight budgets are implemented.

Validation (2026-10-19): compiled with GCC in Debian WSL using C++17 and warning flags. Integration tests passed for empty/small/binary files, an exact payload boundary, a file larger than 1 MiB, deterministic loss of START/DATA/FINISH and their ACKs, duplicate datagrams, corrupted DATA, existing-destination protection, and unavailable-receiver timeout. These are loopback tests, not cross-machine performance or Internet congestion-control validation.

The sender chooses which file ranges to send, detects losses, schedules retransmissions, and controls transmission speed. The receiver reports receipt and available capacity; it does not request each batch of file chunks.

Keep the code small and explainable. Avoid QUIC and unnecessary transport features, but retain the mechanisms required for correctness.

## Connectivity constraint

An open SSH port normally means TCP/22 is reachable. This does not imply UDP/22 or any other UDP port is reachable. A firewall can allow SSH while blocking all UDP.

Do not assume a usable UDP path. Probe bidirectional authenticated UDP reachability before transferring, and report a clear error when unavailable. A successful probe establishes current reachability, not a guarantee that the path will remain available. SSH availability must also mean actual authenticated reachability, not merely that an SSH daemon is running.

Documented limitation against requirement 3: with only TCP/22 guaranteed, successful UDP transfer cannot be guaranteed without network changes. Standard OpenSSH uses TCP; its ordinary port forwarding does not forward UDP. A helper can encapsulate UDP datagrams through SSH, and OpenSSH tunnel-device forwarding can carry IP traffic, but both use the outer SSH/TCP connection. Tunnel devices also require permissions and server support, which the problem does not grant. Neither approach supplies a native UDP path or independent UDP congestion control across the network.

Whether the statement deliberately tests this contradiction is unknown. Document it explicitly rather than assuming SSH solves UDP traversal. UDP hole punching can improve connectivity but cannot guarantee it across arbitrary networks. Encapsulating data through SSH makes the network data path TCP.

Updated user decision: SSH/TCP fallback is accepted when authenticated direct UDP is unavailable. Auto mode probes then selects UDP or explicitly reported SSH/TCP. Strict --transport=udp preserves UDP-only semantics and fails if no native path exists; --transport=ssh needs only authenticated SSH command execution and skips UDP entirely. This is a documented relaxation of strict UDP-only payload transport, not a claim that SSH creates a native UDP path. No router/firewall changes or privileged tunnel configuration are performed.

## Proposed architecture

```text
Sender                                              Receiver
file reader                                         temporary file writer
    |                                                      ^
range scheduler / retransmission queue                     |
    |                                                range tracking
paced UDP sender -------- authenticated DATA --------> UDP receiver
    ^                                                      |
    +---------------- ACK ranges + receive credit -----------+
    |
packet history --> delivery-rate sampler --> BBRv3-inspired controller

Persistent SSH: setup, metadata, keys, errors, cancellation, final result
```

Separate responsibilities:

| Component | Responsibility |
| --- | --- |
| Reliability | ACK processing, loss detection, retransmission, duplicate suppression |
| Flow control | Keep accepted data within the receiver's advertised capacity |
| BBRv3-inspired controller | Determine pacing rate and congestion window from network feedback |
| File adapter | Produce/consume ordered bytes, track progress, verify integrity, finalize output |
| Session control | Setup, authentication, errors, cancellation, completion |

The stream receiver reassembles out-of-order bytes within a bounded window and delivers contiguous bytes to the consumer. The file adapter writes sequentially and hashes incrementally. Missing bytes can stall ordered delivery; this tradeoff must be measured. Keep blocking file I/O outside the pacing/feedback loop using bounded queues. SSH connection loss ends the session; a lost final result may leave the sender with an unconfirmed outcome.

## Packet and acknowledgement design

Use an explicitly serialized, versioned wire format; do not send native C/C++ structs directly. Validate lengths, offsets, integer arithmetic, and session identity before processing.

Conceptual messages (DATA and ACK use UDP; FINISH, COMPLETE, ERROR, and CANCEL use the persistent SSH control channel):

| Message | Main contents |
| --- | --- |
| DATA | Session ID, unique packet number, file offset, payload, authentication tag |
| ACK | Received packet-number ranges, bounded ACK delay, receiver flow-control limit |
| FINISH | Expected file size and final digest |
| COMPLETE | Authenticated confirmation of successful file finalization |
| ERROR / CANCEL | Bounded reason code and session identity |

Packet numbers identify transmission attempts. File offsets identify application bytes. Retransmitting a byte range uses a new packet number, with a mapping back to the same file range.

UDP has no built-in acknowledgements. Our protocol sends ACKs as UDP datagrams. ACKs are needed for loss recovery, receiver-confirmed progress, and BBR delivery measurements.

Batch ACKs and encode ranges to limit overhead. Use a short ACK timer so feedback arrives even when traffic stops. Repeat relevant receipt information so ACK loss does not immediately cause unnecessary data retransmission. Bound ACK size and processing work.

Do not declare a packet lost merely because an ACK contains a gap: reordering is possible. The current implementation uses RTT-based time thresholds and backed-off probes; PROTOCOL.md defines the tested constants.

Start with conservative datagram sizes that avoid fragmentation on supported paths; handle message-too-large errors and define a path-MTU strategy before broader deployment.

## Sending window and flow control

Send only when all conditions hold:

1. The pacing deadline permits sending.
2. Congestion-window capacity permits the packet's bytes in flight.
3. The data falls within the receiver's advertised flow-control limit.

Retransmissions are paced and congestion-controlled too. Maintain bounded queues and packet history. Network capacity and receiver capacity are separate constraints: a slow disk can limit transfer even on a fast network.

Prefer a monotonic absolute receive limit over ambiguous incremental credits, so duplicated or reordered ACKs cannot accidentally grant extra capacity. Define how the receiver advances this limit as buffers are released.

## Userspace BBRv3-inspired congestion control

Implement the controller in C/C++ without enabling kernel BBR. Normal kernel UDP networking remains in use.

Conceptually:

```text
estimated bandwidth-delay product = estimated bandwidth * minimum RTT
controller outputs = pacing rate and congestion window
```

These equations alone are not BBRv3. The user permits a simplified controller based on its ideas. The following mechanisms are implemented; CONGESTION.md specifies exact rules and deviations:

- Estimate delivered bandwidth from per-packet delivery snapshots and elapsed send/ACK time, with application-limited handling and protection against ACK compression.
- Track a minimum-RTT estimate with an explicit aging and refresh policy.
- Use paced startup, drain excess inflight data, then alternate bounded bandwidth probing with steady sending.
- Set pacing and an inflight budget from bandwidth-delay product, with minimum/maximum bounds.
- Borrow BBRv3's loss-aware bandwidth/inflight constraints: excessive loss must limit probing and reduce the permitted load. A bandwidth estimate alone must not sustain overload after a capacity drop.
- Define feedback-silence probes, recovery behavior, and conservative restart after idle periods.

Do not copy isolated gain constants and call the result BBRv3. State transitions, filter windows, loss thresholds, gains, and omitted mechanisms are documented in CONGESTION.md. Deterministic tests cover utilization, capacity/RTT changes, ACK compression, queue/loss behavior, and two competing equal-RTT flows. Real-network fairness against TCP remains system-validation work. No equivalence to full BBRv3 is promised.

Reference revision 88aff899355d12fe1053997facec835aecd9f7d6 is pinned in CONGESTION.md. The project uses an independent implementation informed by the reference algorithm; no reference source is copied or adapted.

Implemented controller interface:

```cpp
void feedback(const std::vector<Event>& events, Time now);
void tick(Time now, bool active, bool limited);
Budget budget() const;
```

Packet history and the delivery sampler must provide accurate timestamps and delivery snapshots. A naive bytes-per-ACK-interval calculation can be distorted by ACK compression. Receiver ACK delay must not be allowed to arbitrarily alter timing estimates.

Implemented as a separate module in the transfer process, keeping pacing and feedback processing in one event loop. This is independent of kernel congestion control.

A separate operating-system process remains an option if explicitly desired. Send timestamped events over a Unix-domain socket and return rate/window decisions. Keep precise pacing in the transfer process and ensure IPC delays are not counted as network RTT. This adds synchronization, failure handling, and overhead, so defer it initially.

## Progress and completion

```text
progress = unique acknowledged file bytes / total file bytes
```

Do not count retransmissions or duplicate acknowledgements as additional progress. Show confirmed bytes, throughput, and an estimated remaining time. Handle an empty file explicitly.

ACKed means received by the protocol, not necessarily verified or durably saved. Expose completion stages clearly:

1. Receive all expected byte ranges into a temporary file.
2. Verify file size and a cryptographic digest, such as SHA-256.
3. Synchronize storage if durable completion is promised.
4. Rename the temporary file into place; define overwrite policy. Durable finalization also requires appropriate directory synchronization.
5. Send COMPLETE over the authenticated SSH control channel.
6. Sender reports success after receiving COMPLETE.

Make finalization requests idempotent and retain completion state long enough to answer retries. If confirmation is lost and cannot be recovered, the sender must report an unconfirmed outcome rather than claim success. Define source-file mutation behavior, initially requiring the source to remain unchanged during transfer.

## Integrity, security, and resume

Use an established cryptographic library for authenticated encryption; do not implement custom cryptography. Exchange session secrets through SSH, derive separate directional keys, ensure nonce uniqueness, and authenticate ACK/control messages as well as data. Bound replay tracking and reject unauthenticated traffic before allocating significant resources.

Optional later extension: logical file chunks with per-chunk hashes and a persisted completion bitmap. Chunks support integrity checks and resume; they do not determine UDP datagram size.

On reconnection, the receiver reports verified chunks once. The sender schedules missing ranges. Bind resume metadata to file identity/content so stale partial files are not silently reused.

## Command, daemon, and streaming support

Illustrative command:

```sh
ufcp local.bin user@host:/destination/file.bin
```

The command launches a remote helper through SSH. Both command and daemon modes reuse the same session engine. A daemon can expose a permission-protected Unix-domain socket to an SSH-launched helper, avoiding a separate public administration port. Treat remote paths as data and avoid unsafe shell interpolation.

Separate file I/O from transport through producer/consumer interfaces. Reliable ordered streaming can reuse the transport. Live media with deadlines would need additional message boundaries and rules for dropping obsolete data; defer those features.

## Implementation sequence

Planning update (2026-10-19): milestones 1-3 and the SSH/authenticated-session foundation are implemented. Tests include real isolated OpenSSH authentication and accepted fallback. Daemon/UX work and broader cross-host network/security validation remain.

| Milestone | Scope | Exit evidence |
| --- | --- | --- |
| 1. Bootstrap (complete) | Stop-and-wait UDP file transfer | Existing loopback correctness and impairment tests |
| 2. Windowed reliable transport (complete) | UFC3 attempt numbers, bounded history, batched ACK ranges, ordered reassembly, receiver flow control, RTT recovery, bounded disk queues, injected-clock core, configurable test pacing | Deterministic impairment simulations and integration tests; exact output; bounded buffers/history; late/duplicate ACK accounting; zero-credit/probe recovery |
| 3. Delivery sampler and BBR-inspired control (complete) | Delivery snapshots, limited-sample handling, aged minimum RTT, startup/drain/bandwidth and RTT probing, loss caps, idle/silence behavior, default CLI integration | Deterministic sampler/state tests; capacity drop/recovery and RTT changes; compressed ACKs; bounded queue/loss; two competing flows; adaptive file transfers |
| 4. SSH and authenticated sessions (implemented) | Remote helper, bounded persistent control frames, OpenSSL AEAD, directional keys/replay window, full-size UDP probes, SHA-256, accepted explicit SSH/TCP fallback | Real SSH user/host-key rejection; direct/tunnel/fallback; encrypted impairment recovery; digest failure; disconnect cleanup and unconfirmed completion |
| 5. Usable command and daemon | scp-like command, shared session engine, permission-protected local daemon interface, cancellation, progress, resource limits, file-operation policies | Command and daemon run the same transfer tests; disk-full and cleanup behavior verified |
| 6. System validation and tuning | Two Linux hosts, Linux network impairment tests, competing traffic, MTU handling, profiling and justified batching | Reproducible correctness/performance results, documented limitations and controller deviations |

### Milestone 2 implementation record

Implementation update (2026-10-19): UFC3 completes the planned transport foundation.
The core in src/transport.hpp accepts injected monotonic timestamps and exposes
producer/consumer methods, replaceable pacing/flight budgets, and send/ACK/loss
events for the later sampler. src/wire.hpp handles explicit wire encoding and
bounded canonical ACK parsing. src/file_io.hpp owns bounded threaded disk queues.
src/ufcp.cpp handles sockets, bootstrap session control, and file finalization.
See PROTOCOL.md for ACK retention, attempt retirement, flow control and timers.
Congestion control and SSH/authentication were added in subsequent increments;
production validation remains separate from these controlled-test results.

Completed checklist (exact defaults are documented test settings):

1. Separated wire encoding, injected-clock transport state, bounded disk adapters, and socket/session orchestration.
2. Specified UFC3 with per-attempt numbers, logical offsets, bounded canonical ACK ranges, and absolute receive limits.
3. Bounded send/receive state and disk queues; accepted bytes are retained until ordered consumption or session failure.
4. Implemented paced selective retransmission and independent flight accounting for original, retry, late, and duplicate ACKs.
5. Added RTT-based time loss detection, backoff, feedback-silence and zero-credit probes; ACK-only packets never trigger ACKs.
6. Validated reordering, tail/burst loss, late originals, zero credit, slow consumers, malformed ACKs, worker failures, and bounded memory/history under larger transfers.

The fixed baseline requires --cc=fixed; adaptive BBR-inspired control is now default. Windowed versus stop-and-wait comparisons use the same fixed baseline on the same delayed path. Production performance acceptance targets still require workload requirements.

Validation details and reproducible commands are recorded in VALIDATION.md.

Resume, multiple-file transfers, and deadline-sensitive media remain deferred extensions. A producer/consumer transport interface belongs in the core; a production streaming feature requires its own acceptance criteria.

Authentication and integrity are now integrated in copy; production readiness still requires the broader network/security validation plan below. Legacy send/recv remain controlled-test baselines.

## Validation plan

Use Linux network namespaces and traffic impairment tools for controlled experiments. Check:

- Exact output contents for empty, small, and large files.
- Loss, ACK loss, duplication, reordering, delayed packets, and burst loss.
- SSH disconnects before/during/after finalization, unconfirmed outcomes, and cancellation.
- Slow disks, bounded memory, disk-full errors, and malformed packets.
- RTT/bandwidth changes, application-limited periods, and competing TCP traffic.
- LAN, routed UDP paths, and explicit UDP-blocked failure.
- Goodput, retransmitted bytes, RTT, CPU, memory, and fairness against baselines under identical conditions.

UDP alone does not guarantee better throughput than TCP. Performance claims require measurements. Compare controller behavior with pinned BBRv3 reference scenarios without claiming equivalence, and verify end-to-end file correctness.

## Open decisions

- Resolved: probe UDP rather than assume it; user-accepted auto/SSH fallback changes outer payload transport to TCP and is reported explicitly. Strict UDP mode remains available.
- Resolved for the present controller: use an independent implementation with pinned conceptual references; no source adaptation.
- Is a separate BBR process required, or is a userspace module sufficient?
- What throughput, RTT, file-size, concurrency, and memory targets matter?
- Does completion promise durable storage? What is the overwrite policy?
- Are resume, multiple files, and deadline-sensitive streaming initial requirements or later extensions?

## References

- [Google BBRv3 overview](https://github.com/google/bbr/blob/v3/README.md)
- [Pinned Google BBRv3 conceptual reference](https://github.com/google/bbr/blob/88aff899355d12fe1053997facec835aecd9f7d6/net/ipv4/tcp_bbr.c)
- [Pinned delivery-sampler conceptual reference](https://github.com/google/bbr/blob/88aff899355d12fe1053997facec835aecd9f7d6/net/ipv4/tcp_rate.c)
- [RFC 8085: UDP Usage Guidelines](https://datatracker.ietf.org/doc/html/rfc8085)
- [RFC 5128: P2P Communication across NATs](https://www.rfc-editor.org/rfc/rfc5128)
- [OpenSSH command manual](https://man.openbsd.org/ssh.1)
- [OpenSSH server configuration: tunnel permissions](https://man.openbsd.org/sshd_config.5#PermitTunnel)
