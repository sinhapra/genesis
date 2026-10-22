"""WAN emulation test with live transfer statistics.

Runs `ufcp copy --stats` across an emulated wide-area link and streams the per-second
stats lines, then copies the same amount with kernel TCP over the same link for comparison.
Sender and "song" live in unprivileged network namespaces joined by a userspace link
emulator (TUN devices) that applies one-way delay, a rate limit, a drop-tail router buffer
and random loss in each direction, so netem and root are not needed. Nothing outside the
namespaces changes. Fails only if the copy fails or the output differs; speeds are reported.

usage: wan.py UFCP [RTT_MS=75] [RATE_MBIT=40] [LOSS_PERCENT=0.001] [SIZE_MB=100] [BUFFER_KB=256]
              [DIRECTION=upload|download]
For downloads the remote helper sends, and its --stats lines arrive through SSH stderr.
"""
import collections
import ctypes
import fcntl
import os
import pathlib
import random
import select
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import time

os.environ['PATH'] += os.pathsep + '/usr/sbin' + os.pathsep + '/sbin'
SENDER, SONG = '10.8.0.1', '10.9.0.2'


def setns(fd):
    if hasattr(os, 'setns'):
        os.setns(fd, 0x40000000)
    elif ctypes.CDLL(None, use_errno=True).setns(fd, 0x40000000) != 0:
        raise OSError(ctypes.get_errno(), 'setns failed')


def emulator(rtt, rate, loss, buffer_bytes):
    """Create sender/song namespaces with TUN devices and forward packets between them."""
    os.makedirs('/run/netns', exist_ok=True)
    subprocess.run(['mount', '-t', 'tmpfs', 'none', '/run/netns'], check=True)

    def tun(ns, name, address, peer_net):
        open('/run/netns/' + ns, 'w').close()
        subprocess.run(['unshare', '--net=/run/netns/' + ns, 'true'], check=True)
        home = os.open('/proc/self/ns/net', os.O_RDONLY)
        setns(os.open('/run/netns/' + ns, os.O_RDONLY))
        fd = os.open('/dev/net/tun', os.O_RDWR)
        fcntl.ioctl(fd, 0x400454ca, struct.pack('16sH', name.encode(), 0x0001 | 0x1000))
        for command in (['ip', 'link', 'set', 'lo', 'up'],
                        ['ip', 'addr', 'add', address + '/32', 'dev', name],
                        ['ip', 'link', 'set', name, 'up', 'mtu', '1500'],
                        ['ip', 'route', 'add', peer_net, 'dev', name]):
            subprocess.run(command, check=True)
        setns(home)
        os.set_blocking(fd, False)
        return fd

    a, b = tun('sender', 'tun0', SENDER, '10.9.0.0/24'), tun('song', 'tun1', SONG, '10.8.0.0/24')

    class Direction:
        def __init__(self, out):
            self.out, self.queue, self.free_at = out, collections.deque(), 0.0
            self.forwarded = self.buffer_drops = self.random_drops = 0

        def push(self, packet, now):
            if random.random() < loss:
                self.random_drops += 1
                return
            start = max(now, self.free_at)
            if (start - now) * rate / 8 > buffer_bytes:
                self.buffer_drops += 1
                return
            self.free_at = start + len(packet) * 8 / rate
            self.queue.append((self.free_at + rtt / 2, packet))

        def flush(self, now):
            while self.queue and self.queue[0][0] <= now:
                os.write(self.out, self.queue.popleft()[1])
                self.forwarded += 1

    directions = {a: Direction(b), b: Direction(a)}

    def finish(*_):
        for name, fd in (('sender->song', a), ('song->sender', b)):
            d = directions[fd]
            print('link %s: forwarded=%d router-buffer-drops=%d random-drops=%d'
                  % (name, d.forwarded, d.buffer_drops, d.random_drops), flush=True)
        os._exit(0)

    signal.signal(signal.SIGTERM, finish)
    print('ready', flush=True)
    while True:
        now = time.monotonic()
        due = min([d.queue[0][0] for d in directions.values() if d.queue] or [now + 0.05])
        readable, _, _ = select.select([a, b], [], [], max(0.0, due - now))
        now = time.monotonic()
        for fd in readable:
            for _ in range(64):
                try:
                    packet = os.read(fd, 65535)
                except BlockingIOError:
                    break
                directions[fd].push(packet, now)
        for direction in directions.values():
            direction.flush(now)


def in_ns(ns, args, **kwargs):
    return subprocess.run(['nsenter', '--net=/run/netns/' + ns] + args, **kwargs)


def tcp_copy(size, download):
    # The TCP comparison moves data in the same direction as the ufcp copy.
    sink_ns, source_ns, sink = ('sender', 'song', SENDER) if download else ('song', 'sender', SONG)
    receiver = subprocess.Popen(['nsenter', '--net=/run/netns/' + sink_ns, sys.executable, '-c', '''
import socket
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("%s", 5001)); s.listen(1); print("ready", flush=True)
c, _ = s.accept(); n = 0
while True:
    d = c.recv(1 << 20)
    if not d: break
    n += len(d)
c.sendall(b"x"); print(n, flush=True)''' % sink], stdout=subprocess.PIPE, text=True)
    receiver.stdout.readline()
    started = time.monotonic()
    in_ns(source_ns, [sys.executable, '-c', '''
import socket
c = socket.create_connection(("%s", 5001)); block = bytes(1 << 20); left = %d
while left:
    n = min(left, len(block)); c.sendall(block[:n]); left -= n
c.shutdown(socket.SHUT_WR); c.recv(1)''' % (sink, size)], check=True)
    elapsed = time.monotonic() - started
    assert int(receiver.stdout.readline()) == size
    return elapsed


def inner(binary, rtt_ms, rate_mbit, loss_percent, size_mb, buffer_kb, direction):
    link = subprocess.Popen([sys.executable, __file__, '--emulator', str(rtt_ms / 1000),
                             str(rate_mbit * 1e6), str(loss_percent / 100), str(buffer_kb * 1024)],
                            stdout=subprocess.PIPE, text=True)
    assert link.stdout.readline().strip() == 'ready', 'link emulator failed to start'
    with tempfile.TemporaryDirectory() as directory:
        root = pathlib.Path(directory)
        hosts = root / 'hosts'
        hosts.write_text('127.0.0.1 localhost\n%s song\n' % SONG)
        subprocess.run(['mount', '--bind', str(hosts), '/etc/hosts'], check=True)
        fixture = root / 'ssh-song'
        fixture.write_text('#!/bin/sh\nfor last; do :; done\ncd "%s" || exit 1\n'
                           'SSH_CONNECTION="%s 51000 %s 22" exec nsenter --net=/run/netns/song sh -c "$last"\n'
                           % (root, SENDER, SONG))
        fixture.chmod(0o700)
        size = int(size_mb * 1e6)
        source, target = root / 'wan.in', root / 'wan.out'
        with open(source, 'wb') as output:
            left = size
            while left:
                chunk = os.urandom(min(left, 1 << 20))
                output.write(chunk)
                left -= len(chunk)
        print('== ufcp copy --stats (%s): %.0f MB over %g ms RTT, %g Mbit/s, %g%% loss, %d KB router '
              'buffer' % (direction, size_mb, rtt_ms, rate_mbit, loss_percent, buffer_kb), flush=True)
        # Both namespaces share the filesystem; "song:" marks the remote side of the copy.
        endpoints = (['song:' + str(source), str(target)] if direction == 'download'
                     else [str(source), 'song:' + str(target)])
        started = time.monotonic()
        result = in_ns('sender', [binary, 'copy', *endpoints, '--stats',
                                  '--ssh-program=' + str(fixture), '--remote-program=' + binary])
        ufcp_seconds = time.monotonic() - started
        assert result.returncode == 0, 'ufcp copy failed'
        assert target.read_bytes() == source.read_bytes(), 'ufcp output differs from source'
        print('PASS ufcp output identical', flush=True)
        print('== kernel TCP, same link and size (scp stand-in without SSH encryption)', flush=True)
        tcp_seconds = tcp_copy(size, direction == 'download')
    link.send_signal(signal.SIGTERM)
    print(link.stdout.read().strip())
    ufcp_rate, tcp_rate = size * 8 / ufcp_seconds / 1e6, size * 8 / tcp_seconds / 1e6
    print('ufcp %6.1fs %6.1f Mbit/s (including SSH setup)' % (ufcp_seconds, ufcp_rate))
    print('TCP  %6.1fs %6.1f Mbit/s  ufcp/TCP = %.0f%%'
          % (tcp_seconds, tcp_rate, 100 * ufcp_rate / tcp_rate))
    return 0


def outer(binary, values):
    missing = [tool for tool in ('unshare', 'nsenter', 'ip') if not shutil.which(tool)]
    if missing or not os.path.exists('/dev/net/tun'):
        print('SKIP wan test: missing ' + ', '.join(missing or ['/dev/net/tun']))
        return 0
    probe = subprocess.run(['unshare', '-rmn', 'true'], capture_output=True, text=True)
    if probe.returncode:
        print('SKIP wan test: unprivileged user namespaces unavailable: ' + probe.stderr.strip())
        return 0
    return subprocess.run(['unshare', '-rmn', '--propagation', 'private', sys.executable, __file__,
                           '--inner', binary] + values).returncode


if __name__ == '__main__':
    if sys.argv[1] == '--emulator':
        emulator(*map(float, sys.argv[2:6]))
    elif sys.argv[1] == '--inner':
        defaults = ['75', '40', '0.001', '100', '256', 'upload']
        values = sys.argv[3:] + defaults[len(sys.argv[3:]):]
        assert values[5] in ('upload', 'download'), 'direction must be upload or download'
        sys.exit(inner(sys.argv[2], *map(float, values[:4]), int(values[4]), values[5]))
    else:
        sys.exit(outer(str(pathlib.Path(sys.argv[1]).resolve()), sys.argv[2:]))
