# Authenticated sessions and SSH/TCP fallback

The accepted policy is direct UDP when reachable, with SSH/TCP fallback when an
authenticated probe fails. The fallback carries logical datagram records over
TCP; this explicitly relaxes the original strict UDP-only network requirement.

## Usage and prerequisites

Build matching ufcp binaries on both Linux hosts with C++17, pthreads, OpenSSL
headers/libcrypto, and an OpenSSH client. The remote binary must be on PATH or
selected with --remote-program. Normal authenticated SSH command execution and
destination file permissions are required; an SFTP-only account is insufficient.

```sh
./ufcp copy source.bin user@host:/destination/file.bin
./ufcp copy source.bin user@host:/destination/file.bin --transport=ssh
./ufcp copy source.bin user@host:/destination/file.bin --transport=udp
./ufcp copy source.bin user@host:/destination/file.bin --remote-program=/home/user/bin/ufcp
./ufcp copy user@host:/source/file.bin local-copy.bin
```

As with scp, the argument with a colon before any `/` is remote: a remote DEST
uploads, a remote SOURCE downloads. The local command is always the SSH client
and UDP prober; the helper always punches. After SELECT the data sender (local
for uploads, helper for downloads) runs pacing, congestion control and
retransmission, and the data receiver ACKs, verifies, publishes and sends COMPLETE.

| Mode | Behavior |
| --- | --- |
| auto (default) | Authenticate through SSH, probe encrypted UDP, fall back to SSH/TCP if unavailable |
| udp | Require authenticated native UDP; fail instead of falling back |
| ssh | Skip UDP sockets/probes entirely; use framed SSH/TCP records |

Chosen mode is reported before payload transfer. Direct UDP uses the configured
BBR-inspired controller or fixed baseline. SSH/TCP disables userspace congestion
control, pacing, loss timers, and DATA retransmission. Outer TCP supplies reliable
ordering and congestion control; application ACKs still enforce receive capacity.
ufcp does not enable kernel BBR in either mode.

Copy options also include --ssh-config=FILE, --remote-program=PATH,
--udp-address=IPv4-or-hostname, and --ssh-program=PATH. Existing window,
receive-chunks, cc, pace-us, and io-delay-ms settings apply; the artificial I/O
delay applies to both workers. pace-us requires cc=fixed and has no effect in
SSH/TCP mode. The default local SSH program is ssh; --ssh-program supports
alternate clients and isolated protocol fixtures.

OpenSSH handles host keys, user authentication, aliases, identity/port/jump-host
configuration, agents, and terminal password prompts. ufcp does not disable host-key
checking or collect passwords. For unattended operation configure key/agent
authentication and BatchMode=yes in the user's SSH configuration. Initial
authentication/helper readiness currently has a thirty-second timeout.

The client executes SSH directly with argv, without a local shell. The only
remote shell command is one quoted executable followed by --helper. Destination
paths, including spaces and shell metacharacters, travel exclusively as framed
data. SSH runs without a pseudo-terminal; stdout is binary protocol, stderr is
diagnostics. Agent, X11 and port forwarding are disabled for the helper session.
No installed SSH service, firewall/router configuration, public
forwarding ports, privileged helper, or TUN device is needed.

The initial target syntax is [user@]host:path, supporting IPv4 addresses, DNS
names and SSH aliases, but not bracketed IPv6. Relative remote paths use the
helper's working directory, normally the remote home directory. UDP resolves
the destination host as IPv4 unless overridden; unresolvable SSH aliases select
SSH/TCP in auto mode. The helper negotiates an ephemeral UDP port. Probe-only
sockets are closed when SSH/TCP is selected.

## Session protocol

SSH frames contain big-endian length (4), type (1), and payload. Length includes
type and is bounded to 1-8,192. Types: INIT=1, READY=2, SELECT=3, SELECTED=4,
PACKET=5, FINISH=6, COMPLETE=7, ERROR=8, CLOSE=9, PROBING=10. Parsing supports fragmentation
and coalescing; output is bounded to 128 KiB plus one partially written frame,
with control-space reservation.

INIT payload fields: UFS4 magic (4), stream size (8; zero for downloads), session ID
(8), requested mode (1; auto=0/udp=1/ssh=2), window chunks (2), receive chunks (2),
worker delay ms (2), independent directional keys (64), remote path length (2),
client UDP port (2; zero when unavailable), flags (1; download=1, stats=2), remote
path bytes (1-4,096; NUL forbidden).
Helpers reject other magic values, so both hosts must run matching builds. Limits are validated before file creation.
READY contains the initial absolute receive limit for uploads or the source size
for downloads (8), then the UDP port (2; zero when unavailable). SELECT/SELECTED contain selected udp=1 or ssh=2. PACKET contains a
validated UFC3 DATA or ACK record. FINISH/COMPLETE contain stream size (8) and
SHA-256 (32). ERROR contains a bounded reason; CLOSE has no payload.

The client sends its first probe and then PROBING (no payload) over SSH. From
then until SELECT the helper punches: every 100 ms it sends an encrypted punch
record to the client UDP port at the client address that sshd reports in
SSH_CONNECTION (the client's public address when it is behind NAT). Waiting for
PROBING guarantees the client's own NAT already maps that port, so an early punch
cannot claim it and force a different external port. A received punch makes the
client probe again at once. Because the helper sends before its side sees probes, stateful firewalls and NAT routers on the
helper side treat the client's probes as replies, so no inbound firewall rule,
port forward or adapter change is needed. This works when both sides may send
outbound UDP and NAT keeps the client's port (as ufw, firewalld, Windows
Firewall, Linux masquerade and most home routers do). It cannot traverse networks
that block outbound UDP, port-randomizing (symmetric) NAT on both sides, or SSH
through a jump host, where SSH_CONNECTION names the jump host; auto mode then
uses SSH/TCP. Without an IPv4 SSH_CONNECTION the helper does not punch.

The client tries six encrypted probes, 200 ms apart over 1.2 seconds. A fresh
16-byte challenge is padded to match maximum DATA datagram size. The helper
authenticates and echoes it; the client validates peer, tag and complete challenge.
The verified path carries data in either direction.
Local UDP denial, missing remote UDP socket, unresolved address or failed replies
select SSH/TCP in auto mode. Strict udp mode fails clearly. Mode is fixed once
payload begins: mid-transfer switching/resume is not implemented. A successful
probe establishes current reachability, not permanent availability.

## Direct UDP cryptography

Session ID and two random 256-bit directional keys use OpenSSL RAND_bytes and
travel only over SSH. OpenSSL ChaCha20-Poly1305 protects every direct DATA, ACK,
and probe. Envelope: UFE1 magic (4), unique nonzero directional counter (8),
ciphertext, tag (16). The header is authenticated additional data. Nonce is
four zero bytes followed by counter (8); distinct keys separate directions and
fresh session keys prevent cross-session nonce reuse. Exhaustion fails safely.

Plaintext starts with kind: probe=1, UFC3 packet=2 or punch=3 (no body; the
client ignores it). Maximum plaintext is 1,063
bytes; maximum encrypted datagram is 1,091. A 1,024-counter replay window permits
reordering. Invalid tags never advance the window. Wrong keys, wrong sessions,
wrong peers, malformed packets, stale counters and replays are rejected. Very
late packets recover through new transport attempts. Independent packet and
transport attempt counters let retransmissions use fresh nonces.

SSH/TCP records rely on SSH encryption/authentication, with no extra packet cipher
or nested network congestion controller. Legacy send/recv are unchanged trusted
test interfaces and cannot inject accepted packets into these encrypted sessions.

## Completion and failure

File workers calculate SHA-256 alongside legacy CRC32. After all data is ACKed,
the data sender checks source metadata and sends size/digest over SSH. The data
receiver waits for ordered worker-confirmed writes, verifies SHA-256, atomically renames
the temporary file over the destination (replacing an existing file like scp,
keeping its permission bits; directories are refused) and sends COMPLETE. Upload
success requires an exact authenticated size/digest match; a download succeeds
after local verification and publication. CLOSE lets the helper exit; the client
checks SSH exit status. Late flow-control ACKs are harmless.

ERROR immediately reports setup/disk/integrity failures over SSH. EOF or normal
failure removes the incomplete temporary file, a hidden `.DEST.XXXXXXXX.part` with
a random suffix created exclusively per copy; crashes may leave one, which is never
reused and never blocks later copies. Published output survives later disconnects. Missing COMPLETE
after FINISH reports completion unconfirmed. An error after validated COMPLETE
reports a confirmed destination with an SSH shutdown error, not uncertain data.

Flow-feedback timeout is ten seconds, receiver idle timeout fifteen seconds,
completion wait fifteen seconds, and published-state close wait five seconds.
Scheduled disk work does not count as peer silence. Bounded queue cancellation
wakes workers, but a blocked kernel filesystem operation may delay shutdown.
Completion does not promise power-loss durability. Existing immutable regular
source and same-directory rename policies remain in effect.

## Tests and remaining scope

make test includes crypto tampering/wrong keys/replay, SHA-256 vectors, framing,
direct/tunnel/fallback transfer, encrypted loss/corruption/replay recovery, special
paths, empty files, slow queues, strict UDP failure, overwrite, malformed
control, bad digest, disconnect cleanup and lost final confirmation. Local exec
fixtures validate protocol plumbing, not SSH authentication.

make netns-test runs client and helper in separate unprivileged network
namespaces on different subnets joined by a router namespace. It checks strict
UDP uploads and downloads through stateful firewalls on either or both hosts and
with the client behind NAT, auto-mode fallback and strict failure when UDP is
fully blocked. It needs user
namespaces, iproute2, iptables and nsenter, skips otherwise, and changes nothing
outside its namespaces.

make ssh-test additionally launches an unprivileged loopback OpenSSH server with
temporary keys/configuration, testing direct/tunnel/fallback, quoted helper paths,
wrong user keys and host-key mismatch. Set UFCP_TEST_SSHD to an available sshd
executable when needed. No existing service or account configuration is edited.

Daemon mode, explicit cancellation/progress UX, resume, durable completion, IPv6,
PMTU discovery, automatic mid-transfer failover, and cross-host production
network/security validation remain later work.

API references: [OpenSSH](https://man.openbsd.org/ssh.1),
[OpenSSL EVP authenticated encryption](https://docs.openssl.org/3.0/man3/EVP_EncryptInit/),
[OpenSSL randomness](https://docs.openssl.org/3.0/man3/RAND_bytes/).
