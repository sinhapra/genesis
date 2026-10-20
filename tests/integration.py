"""Linux loopback acceptance tests with reproducible UDP impairment and worker delays."""
import heapq
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import threading
import time
import zlib

binary = str(pathlib.Path(sys.argv[1]).resolve())


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def reseal(packet):
    packet = bytearray(packet)
    packet[26:30] = (zlib.crc32(packet[:26] + packet[30:]) & 0xffffffff).to_bytes(4, 'big')
    return bytes(packet)


class Relay:
    def __init__(self, port, mode, size, delay=0):
        self.port, self.mode, self.size, self.delay = port, mode, size, delay
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(('127.0.0.1', 0))
        self.socket.settimeout(0.001)
        self.stop = threading.Event()
        self.error = None
        self.attempts = set()
        self.probes = 0
        self.held = set()
        self.thread = threading.Thread(target=self.run)
        self.thread.start()

    def run(self):
        client, dropped, scheduled, serial = None, set(), [], 0
        first_ack = None
        try:
            while not self.stop.is_set():
                now = time.monotonic()
                while scheduled and scheduled[0][0] <= now:
                    _, _, packet, destination = heapq.heappop(scheduled)
                    self.socket.sendto(packet, destination)
                try:
                    packet, address = self.socket.recvfrom(4096)
                except socket.timeout:
                    continue
                reply = address[1] == self.port
                if not reply:
                    client = address
                destination = client if reply else ('127.0.0.1', self.port)
                kind = packet[30] if reply else packet[4]
                position = int.from_bytes(packet[16:24], 'big')
                wait = self.delay
                if self.mode == 'unconfirmed' and reply and kind == 3:
                    continue
                if not reply and kind == 5:
                    self.probes += 1
                if not reply and kind == 2:
                    attempt = int.from_bytes(packet[30:38], 'big')
                    assert attempt not in self.attempts, 'sender reused an attempt number'
                    self.attempts.add(attempt)
                if self.mode == 'credit' and reply and kind == 1:
                    altered = bytearray(packet)
                    altered[31:39] = (0).to_bytes(8, 'big')
                    packet = reseal(altered)
                if self.mode == 'credit' and reply and kind == 2 and self.probes < 2:
                    continue
                if self.mode == 'blackout' and reply and kind == 2:
                    first_ack = first_ack or now
                    if now - first_ack < 0.6:
                        continue
                if self.mode in ('impaired', 'reorder', 'burst', 'tail', 'malformed'):
                    key = (reply, kind)
                    if key not in dropped:
                        dropped.add(key)
                        continue
                    if self.mode == 'tail' and not reply and kind == 2 and position + len(packet) - 38 == self.size:
                        if ('tail', position) not in dropped:
                            dropped.add(('tail', position))
                            continue
                    if self.mode == 'burst' and not reply and kind == 2 and 8192 <= position < 24576:
                        if ('burst', position) not in dropped:
                            dropped.add(('burst', position))
                            continue
                    if self.mode == 'reorder' and kind == 2:
                        key = (reply, position if not reply else packet)
                        if key not in self.held and (reply or position % 4096 == 0):
                            self.held.add(key)
                            wait += 0.18
                    if self.mode == 'impaired' and not reply and kind == 2 and 'corrupt' not in dropped:
                        dropped.add('corrupt')
                        altered = bytearray(packet)
                        altered[-1] ^= 1
                        self.socket.sendto(altered, destination)
                        continue
                    if self.mode == 'malformed' and reply and kind == 2:
                        altered = bytearray(packet)
                        altered[43] = 33
                        self.socket.sendto(reseal(altered), destination)
                        altered = bytearray(packet)
                        altered[43] = 1
                        altered = altered[:60]
                        altered[24:26] = (30).to_bytes(2, 'big')
                        altered[44:52] = (1).to_bytes(8, 'big')
                        altered[52:60] = (2**64 - 1).to_bytes(8, 'big')
                        self.socket.sendto(reseal(altered), destination)
                    if self.mode == 'malformed' and not reply and kind == 2:
                        altered = bytearray(packet)
                        altered[16:24] = (2**64 - 1).to_bytes(8, 'big')
                        self.socket.sendto(reseal(altered), destination)
                        self.socket.sendto(packet + bytes(2000), destination)
                    if not wait:
                        self.socket.sendto(packet, destination)
                if wait:
                    serial += 1
                    heapq.heappush(scheduled, (now + wait, serial, packet, destination))
                else:
                    self.socket.sendto(packet, destination)
        except Exception as error:
            self.error = error

    def close(self):
        self.stop.set()
        self.thread.join(timeout=2)
        assert not self.thread.is_alive()
        self.socket.close()
        if self.error:
            raise self.error


def transfer(root, name, data, mode=None, sender_options=(), receiver_options=(), delay=0):
    source, target = root / (name + '.in'), root / (name + '.out')
    source.write_bytes(data)
    port = free_port()
    receiver = subprocess.Popen([binary, 'recv', '127.0.0.1', str(port), str(target), *receiver_options],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    relay = None
    try:
        assert receiver.stdout.readline().startswith('Listening'), receiver.stderr.read()
        send_port = port
        if mode or delay:
            relay = Relay(port, mode, len(data), delay)
            send_port = relay.socket.getsockname()[1]
        started = time.monotonic()
        sender = subprocess.run([binary, 'send', '127.0.0.1', str(send_port), str(source), *sender_options],
                                capture_output=True, text=True, timeout=45)
        elapsed = time.monotonic() - started
        if mode == 'unconfirmed':
            assert sender.returncode != 0 and 'completion unconfirmed' in sender.stderr, sender.stderr
        else:
            assert sender.returncode == 0, sender.stderr
            if '--cc=fixed' not in sender_options:
                assert 'Controller: bbr-inspired' in sender.stdout
        out, err = receiver.communicate(timeout=10)
        assert receiver.returncode == 0, (out, err)
        assert target.read_bytes() == data
        assert not pathlib.Path(str(target) + '.part').exists()
        if mode == 'credit':
            assert relay.probes >= 2, 'credit recovery did not exercise probes'
        print('PASS', name, flush=True)
        return elapsed
    finally:
        if relay:
            relay.close()
        if receiver.poll() is None:
            receiver.kill()
            receiver.communicate()


def source_mutation(root):
    source, target = root / 'changing.in', root / 'changing.out'
    source.write_bytes(os.urandom(128 * 1024))
    port = free_port()
    receiver = subprocess.Popen([binary, 'recv', '127.0.0.1', str(port), str(target)],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    sender = None
    try:
        assert receiver.stdout.readline().startswith('Listening')
        sender = subprocess.Popen([binary, 'send', '127.0.0.1', str(port), str(source), '--io-delay-ms=5'],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        time.sleep(0.1)
        with source.open('ab') as stream:
            stream.write(b'changed')
        out, err = sender.communicate(timeout=10)
        assert sender.returncode != 0 and 'source changed' in err, (out, err)
        out, err = receiver.communicate(timeout=20)
        assert receiver.returncode != 0 and not target.exists(), (out, err)
        assert not pathlib.Path(str(target) + '.part').exists()
        print('PASS source mutation and incomplete-output cleanup', flush=True)
    finally:
        for process in (sender, receiver):
            if process is not None and process.poll() is None:
                process.kill()
                process.communicate()


with tempfile.TemporaryDirectory() as folder:
    root = pathlib.Path(folder)
    for name, data in [('empty', b''), ('small', b'hello UDP\x00\xff'),
                       ('boundary', os.urandom(1024)), ('large', os.urandom(4 * 1024 * 1024 + 37))]:
        transfer(root, name, data)
    for mode in ('impaired', 'reorder', 'burst', 'tail', 'malformed', 'credit', 'blackout'):
        transfer(root, mode, os.urandom(128 * 1024 + 13), mode)
    transfer(root, 'slow-consumer', os.urandom(64 * 1024 + 3),
             receiver_options=('--receive-chunks=2', '--io-delay-ms=10'))
    transfer(root, 'slow-producer', os.urandom(64 * 1024), sender_options=('--io-delay-ms=3', '--window=4'))
    transfer(root, 'unconfirmed', os.urandom(8193), 'unconfirmed')
    source_mutation(root)
    data = os.urandom(64 * 1024)
    baseline = transfer(root, 'delayed-window-1', data, delay=0.01, sender_options=('--window=1', '--cc=fixed'))
    windowed = transfer(root, 'delayed-window-32', data, delay=0.01, sender_options=('--cc=fixed',))
    transfer(root, 'bbr-delayed', data, delay=0.01, sender_options=('--cc=bbr-inspired',))
    assert windowed < baseline * 0.75, (baseline, windowed)
    print(f'PASS delayed-path comparison: window=1 {baseline:.3f}s; window=32 {windowed:.3f}s; {baseline/windowed:.2f}x', flush=True)
    existing = root / 'existing'
    existing.write_bytes(b'keep me')
    result = subprocess.run([binary, 'recv', '127.0.0.1', str(free_port()), str(existing)], capture_output=True, timeout=3)
    assert result.returncode != 0 and existing.read_bytes() == b'keep me'
    print('PASS no overwrite', flush=True)
    result = subprocess.run([binary, 'send', '127.0.0.1', str(free_port()), str(existing)], capture_output=True, timeout=8)
    assert result.returncode != 0 and b'timeout' in result.stderr
    print('PASS unavailable receiver', flush=True)
    for option in ('--window=0', '--window=257', '--receive-chunks=0', '--receive-chunks=257', '--pace-us=0', '--cc=invalid', '--cc=bbr', '--pace-us=100'):
        result = subprocess.run([binary, 'send', '127.0.0.1', '9000', str(existing), option], capture_output=True, timeout=3)
        assert result.returncode != 0
    print('PASS configuration bounds', flush=True)
