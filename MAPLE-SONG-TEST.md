# Maple–Song transfer test

This procedure sends Song's existing `~/test/pi-500m.txt` to Maple at
`192.168.0.107`. Run the shell commands in bash. The checkout is assumed to be
`~/genesis` on both machines; change that path if necessary. Use the same source
file without modifying it during any test. Legacy UDP is for this trusted test
network; SSH authentication is not involved in `send`/`recv`.

## 1. Build the same revision on both machines

On **both Maple and Song**:

```sh
cd ~/genesis
git pull --ff-only origin main
make ufcp
git rev-parse HEAD
sha256sum ./ufcp
```

The commit IDs must match. Binary hashes may differ across build environments.
Run `make test` on either Linux host to repeat the complete local test suite.

On **Song**, check the input:

```sh
stat -c '%s bytes' ~/test/pi-500m.txt
sha256sum ~/test/pi-500m.txt
```

The reported file in the original test was 524288000 bytes (500 MiB).

## 2. Establish a run name on Maple

On **Maple**, keep this terminal open for all receiver commands:

```sh
cd ~/genesis
RUN=$(date +%Y%m%d-%H%M%S)
mkdir -p ~/test/ufcp-results
BASE="$HOME/test/ufcp-results/$RUN"
printf 'Results prefix: %s\n' "$BASE"
```

All output names below are new. Do not reuse an existing destination; ufcp
intentionally refuses to overwrite it.

## 3. Test the default window

On **Maple**:

```sh
./ufcp recv 192.168.0.107 8888 "$BASE.default.ufcp" \
  --receive-chunks=64 2>&1 | tee "$BASE.default.receiver.log"
```

Once it prints `Listening`, run on **Song within 15 seconds**:

```sh
cd ~/genesis
set -o pipefail
/usr/bin/time -p ./ufcp send 192.168.0.107 8888 ~/test/pi-500m.txt \
  --cc=bbr-inspired --window=32 2>&1 | tee ~/test/ufcp-default.sender.log
```

Wait for Maple's receiver to exit before starting the next receiver.

## 4. Test the larger window

On **Maple**:

```sh
./ufcp recv 192.168.0.107 8888 "$BASE.window256.ufcp" \
  --receive-chunks=256 2>&1 | tee "$BASE.window256.receiver.log"
```

Once it prints `Listening`, run on **Song within 15 seconds**:

```sh
cd ~/genesis
set -o pipefail
/usr/bin/time -p ./ufcp send 192.168.0.107 8888 ~/test/pi-500m.txt \
  --cc=bbr-inspired --window=256 2>&1 | tee ~/test/ufcp-window256.sender.log
```

Use the sender's `real` time for both UDP comparisons. Receiver timing includes
waiting for the sender plus a completion linger, so it is not comparable.
Both sender logs must contain `Complete` and `Controller: bbr-inspired`.
Keep the full controller summary: bandwidth, pacing, cwnd, min-rtt and lost.
`lost` counts declared losses, which can include false timeouts.

## 5. Compare scp in the same direction

On **Maple**, prime SSH authentication, then time the same Song-to-Maple copy:

```sh
ssh song true
set -o pipefail
/usr/bin/time -p scp song:test/pi-500m.txt "$BASE.scp" \
  2>&1 | tee "$BASE.scp.log"
sha256sum "$BASE.default.ufcp" "$BASE.window256.ufcp" "$BASE.scp"
```

All three hashes must equal the source hash recorded on Song. Calculate goodput
as `source_bytes / sender_real_seconds / 1048576` for MiB/s. Repeat steps 2–5
three times with new run names and compare median times to reduce run-to-run
noise; keep the source, direction and network conditions constant.

## Interpreting results

The timeout update avoids the previous 200 ms initial timeout and adds at least
25 ms of smoothed-RTT headroom. It does not disable congestion control or promise
UDP will beat TCP. A larger maximum window helps only when the controller and
receiver allow more data in flight. At 200 ms RTT, 256 KiB in flight bounds useful
throughput to roughly 1.25 MiB/s before overhead; higher targets need a larger
supported flight budget and further validation. If the larger-window run stays
slow, collect both sender logs and the RTT/loss summaries before changing rates.

The local 4 MiB/200 ms-delay benchmark improved from 37.254 s to 5.244 s with
256-chunk limits. It is a single-run local result, not a Maple–Song prediction.
