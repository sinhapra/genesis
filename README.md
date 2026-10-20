# ufcp: UDP transfer with SSH/TCP fallback

Remote copy authenticates through SSH, uses encrypted direct UDP with our
userspace BBR-inspired controller when reachable, and falls back to SSH/TCP.
Fallback requires no router/firewall changes but its network payload is TCP;
this explicitly relaxes strict UDP-only transfer. See [SSH.md](SSH.md).

## Build and copy

Requires Linux, C++17, pthreads, OpenSSL headers/libcrypto, make and OpenSSH.
Tests also require Python 3. Build/install matching ufcp binaries on both hosts.

```sh
make
make test
./ufcp copy source.bin user@host:/destination/file.bin
./ufcp copy source.bin user@host:/destination/file.bin --transport=ssh
./ufcp copy source.bin user@host:/destination/file.bin --transport=udp
```

`auto` is the default: SSH authentication, a full-size encrypted UDP probe, then
UDP or reported SSH/TCP fallback. `ssh` skips UDP entirely. `udp` requires native
UDP and fails without fallback. Matching remote ufcp must be on PATH, or supplied
with `--remote-program=/path/to/ufcp`. Existing SSH authentication/host-key policy
is honored. `--ssh-config=FILE` selects an SSH config. No privileged tunnel or
forwarding configuration is needed. Source must be regular and unchanged; output
must not exist and its filesystem must support same-directory hard links.

| Option | Default | Meaning |
| --- | --- | --- |
| `--transport=auto\|udp\|ssh` | auto | Copy transport policy |
| `--cc=bbr-inspired\|fixed` | bbr-inspired | Userspace direct-UDP controller or test baseline |
| `--window=N` | 32 chunks | Maximum sending window, 1-256 |
| `--receive-chunks=N` | 64 chunks | Receiver capacity, 1-256 |
| `--pace-us=N` | 1,000 in fixed mode | 1-1,000,000; requires `--cc=fixed` |
| `--io-delay-ms=N` | 0 | Artificial per-chunk disk delay, 0-1,000 |
| `--remote-program=PATH` | ufcp | Literal remote helper executable |
| `--ssh-config=FILE` | OpenSSH default | SSH host/credential/port configuration |
| `--udp-address=HOST` | SSH destination host | Direct-UDP IPv4 address/hostname override |

Options follow the destination. Chunks are 1,024 bytes except the final chunk.
In SSH/TCP mode, outer TCP handles congestion and reliability: our controller,
pacing, bandwidth probes and DATA retransmission timers are disabled. Flow ACKs
and bounded disk queues still apply. Mode is reported before file payload starts.
`--ssh-program=PATH` can select an alternate local SSH client/test fixture.

## Transport and security

The independent transport core provides selective ACK ranges, per-attempt history,
ordered bounded reassembly, receiver credit, RTT recovery and paced retransmission.
File I/O runs in bounded worker queues outside the feedback loop. Direct copy
packets use OpenSSL ChaCha20-Poly1305 with independent directional keys exchanged
through SSH, unique nonce counters and bounded replay rejection. Copy completion
verifies SHA-256 and requires authenticated SSH confirmation after no-overwrite
publication. Errors also use SSH. See [PROTOCOL.md](PROTOCOL.md),
[CONGESTION.md](CONGESTION.md), and [SSH.md](SSH.md) for exact contracts.

The controller is BBR-inspired, not BBRv3-conformant or Internet-validated.
The current mode is fixed once transfer starts; a later UDP failure aborts rather
than silently restarting or switching after partial transfer. Retry explicitly
with `--transport=ssh`. Unknown SSH aliases may fall back because direct UDP
requires an IPv4 address; `--udp-address` can override it.

## Reading the code

C++ formatting uses the checked-in `.clang-format` (LLVM style, four-space
indentation, attached braces and a 100-column target). To reproduce it with
clang-format 18.1.8, run `clang-format -i src/*.hpp src/*.cpp tests/*.cpp`.
Comments remain on a single line.

Start with `main` in `src/ufcp.cpp`, then follow `remote_copy` and `remote_helper`
in `src/remote.hpp`. Both commands share transfer defaults and the same temporary
output lifecycle. The remaining files each own one part of the transfer:

| File | Responsibility |
| --- | --- |
| `transport.hpp` | Logical chunks, transmission attempts, retries, receive credit and ACKs |
| `congestion.hpp` | Delivery-rate sampling and userspace pacing/window decisions |
| `wire.hpp` | UDP packet encoding, validation and CRC |
| `session_io.hpp` | SSH child lifetime and bounded control-message framing |
| `crypto.hpp` | Authenticated UDP encryption, replay rejection and SHA-256 |
| `file_io.hpp` | Bounded disk workers and no-overwrite output publication |

A file chunk keeps its byte offset across retries, while every transmission gets
a new attempt number. The receiver ACKs buffered chunks but releases capacity only
after ordered writes finish. Finally, the helper verifies SHA-256, publishes the
file, and confirms success through SSH. Comments mark these boundaries in the code.

## Controlled UDP baseline

The older unauthenticated interface remains for controlled tests:

```sh
./ufcp recv 127.0.0.1 9000 received.bin
# In another terminal within 15 seconds:
./ufcp send 127.0.0.1 9000 source.bin
```

These legacy commands use CRC32/session IDs without SSH authentication/encryption.
Use only trusted test networks. They retain UDP START/FINISH and report remote
errors by timeout; the copy command uses persistent framed SSH control instead.
Legacy datagrams are at most 1,062 bytes; encrypted copy datagrams at most 1,091.

## Validation and limitations

`make test` runs deterministic transport/controller/crypto tests, impaired loopback
transfers and remote-session fixtures. Coverage includes loss/reordering, malformed
ACKs/control, ACK compression, capacity/RTT changes, zero credit, encrypted packet
corruption/replay, slow disks, source mutation, no-overwrite, SHA-256 verification,
cleanup, and lost completion confirmation. See [VALIDATION.md](VALIDATION.md).

`make ssh-test` additionally uses a temporary unprivileged real OpenSSH server.
Set `UFCP_TEST_SSHD=/path/to/sshd` if needed. All keys/configuration are temporary;
installed SSH services, account keys and firewall/router settings are untouched.

Daemon mode, progress/ETA and explicit cancellation UX, resume, IPv6, PMTU discovery,
automatic mid-transfer failover and production system validation remain. Output
publication is not power-loss durable. Normal failures remove incomplete `.part`;
crashes may leave it, and it is never silently reused. Kernel filesystem I/O may
delay worker shutdown. SHA-256 and metadata checks do not replace source snapshots.
