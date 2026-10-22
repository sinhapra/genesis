"""SSH-session plumbing tests using a local exec fixture, not a substitute for real SSH authentication tests."""
import os
import pathlib
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time
import zlib

binary = str(pathlib.Path(sys.argv[1]).resolve())


def invoke(root, name, mode='auto', options=(), data=None, environment=None):
    source = root / (name + '.in')
    target = root / (name + " ' ; $(printf injection) .out")
    data = os.urandom(65539) if data is None else data
    source.write_bytes(data)
    args = [binary, 'copy', str(source), '127.0.0.1:' + str(target),
            '--ssh-program=' + str(root / 'ssh-fixture'), '--remote-program=' + binary,
            '--transport=' + mode, *options]
    result = subprocess.run(args, capture_output=True, text=True, timeout=30, env=environment)
    assert result.returncode == 0, (name, result.returncode, result.stdout, result.stderr)
    assert target.read_bytes() == data and not pathlib.Path(str(target) + '.part').exists()
    assert 'verified with SHA-256' in result.stdout
    if mode == 'ssh' or '--udp-address=127.0.0.2' in options:
        assert 'Transport: SSH/TCP' in result.stdout and 'Controller: bbr-inspired' not in result.stdout
    else:
        assert 'Transport: direct UDP' in result.stdout and 'Controller: bbr-inspired' in result.stdout
    print('PASS', name, flush=True)
    return args, target


def download(root, name, mode='auto', options=(), data=None, environment=None):
    remote = root / (name + " ' ; $(printf injection) .remote")
    local = root / (name + '.download')
    data = os.urandom(65539) if data is None else data
    remote.write_bytes(data)
    args = [binary, 'copy', '127.0.0.1:' + str(remote), str(local),
            '--ssh-program=' + str(root / 'ssh-fixture'), '--remote-program=' + binary,
            '--transport=' + mode, *options]
    result = subprocess.run(args, capture_output=True, text=True, timeout=30, env=environment)
    assert result.returncode == 0, (name, result.returncode, result.stdout, result.stderr)
    assert local.read_bytes() == data and not pathlib.Path(str(local) + '.part').exists()
    assert 'received, verified with SHA-256' in result.stdout
    tunneled = mode == 'ssh' or '--udp-address=127.0.0.2' in options
    assert ('Transport: SSH/TCP' if tunneled else 'Transport: direct UDP') in result.stdout, result.stdout
    print('PASS download', name, flush=True)
    return result, local


def frame(kind, data=b''):
    return struct.pack('!I', len(data) + 1) + bytes([kind]) + data


def read_frame(stream):
    def exact(n):
        data = b''
        while len(data) < n:
            chunk = stream.read(n - len(data))
            assert chunk, 'unexpected helper EOF'
            data += chunk
        return data
    size = struct.unpack('!I', exact(4))[0]
    assert 1 <= size <= 8192
    return exact(size)


def raw_helper(root, name, bad_hash=False, drop_after_publish=False):
    target = root / (name + '.out')
    payload = b'hello authenticated session'
    path = str(target).encode()
    init = struct.pack('!IQQBHHH', 0x55465333, len(payload), 123, 2, 32, 64, 0) + os.urandom(64) + struct.pack('!HHB', len(path), 0, 0) + path
    process = subprocess.Popen([binary, '--helper'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        process.stdin.write(frame(1, init)); process.stdin.flush()
        assert read_frame(process.stdout)[0] == 2
        process.stdin.write(frame(3, b'\x02')); process.stdin.flush()
        assert read_frame(process.stdout)[0] == 4
        if not bad_hash and not drop_after_publish:
            process.stdin.close(); process.stdin = None
            process.communicate(timeout=5)
            assert process.returncode != 0 and not target.exists() and not pathlib.Path(str(target) + '.part').exists()
            print('PASS helper disconnect cleanup', flush=True)
            return
        body = struct.pack('!Q', 1) + payload
        header = struct.pack('!IB3xQQH', 0x55464333, 2, 123, 0, len(body))
        packet = header + struct.pack('!I', zlib.crc32(header + body)) + body
        process.stdin.write(frame(5, packet)); process.stdin.flush()
        assert read_frame(process.stdout)[0] == 5
        import hashlib
        digest = bytes(32) if bad_hash else hashlib.sha256(payload).digest()
        process.stdin.write(frame(6, struct.pack('!Q', len(payload)) + digest)); process.stdin.flush()
        outcome = read_frame(process.stdout)
        while outcome[0] == 5:
            outcome = read_frame(process.stdout)
        if bad_hash:
            assert outcome[0] == 8 and b'SHA-256' in outcome
        else:
            assert outcome[0] == 7 and target.read_bytes() == payload
        process.stdin.close(); process.stdin = None
        process.communicate(timeout=5)
        assert not pathlib.Path(str(target) + '.part').exists()
        assert target.exists() == (not bad_hash)
        print('PASS', 'bad SHA-256 rejection' if bad_hash else 'published output survives lost close confirmation', flush=True)
    finally:
        if process.poll() is None:
            process.kill(); process.communicate()


with tempfile.TemporaryDirectory() as directory:
    root = pathlib.Path(directory)
    fixture = root / 'ssh-fixture'
    fixture.write_text('''#!/usr/bin/python3
import os, sys, subprocess, threading, struct, socket
drop_complete = bool(os.environ.get('UFCP_TEST_DROP_COMPLETE'))
impair = bool(os.environ.get('UFCP_TEST_IMPAIR_UDP'))
if not drop_complete and not impair:
    os.execv('/bin/sh', ['sh', '-c', sys.argv[-1]])
helper = subprocess.Popen(['/bin/sh', '-c', sys.argv[-1]], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
selected = threading.Event()
proxy = None
def relay(real_port):
    client = None
    count = 0
    while True:
        data, address = proxy.recvfrom(4096)
        reply = address[1] == real_port
        if not reply:
            client = address
        destination = client if reply else ('127.0.0.1', real_port)
        if selected.is_set():
            count += 1
            if count % 9 == 0:
                continue
            if count % 13 == 0:
                damaged = bytearray(data)
                damaged[-1] ^= 1
                proxy.sendto(damaged, destination)
                continue
        proxy.sendto(data, destination)
        if selected.is_set() and count % 5 == 0:
            proxy.sendto(data, destination)
def forward():
    try:
        while True:
            data = os.read(0, 4096)
            if not data:
                helper.stdin.close()
                return
            helper.stdin.write(data)
            helper.stdin.flush()
    except (OSError, ValueError):
        return
threading.Thread(target=forward, daemon=True).start()
def exact(n):
    result = b''
    while len(result) < n:
        data = helper.stdout.read(n - len(result))
        if not data:
            if result:
                os._exit(1)
            return None
        result += data
    return result
while True:
    prefix = exact(4)
    if prefix is None:
        sys.exit(helper.wait())
    data = exact(struct.unpack('!I', prefix)[0])
    if data is None:
        os._exit(1)
    if impair and data[0] == 2:
        real_port = int.from_bytes(data[-2:], 'big')
        proxy = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        proxy.bind(('127.0.0.1', 0))
        data = data[:-2] + proxy.getsockname()[1].to_bytes(2, 'big')
        threading.Thread(target=relay, args=(real_port,), daemon=True).start()
    if impair and data[0] == 4:
        selected.set()
    if data[0] == 7 and drop_complete:
        os._exit(0)
    os.write(1, prefix + data)
''')
    fixture.chmod(0o700)
    (root / 'ssh').symlink_to(fixture)
    (root / 'ufcp').symlink_to(binary)
    source, target = root / 'default.in', root / 'default.out'
    source.write_bytes(b'default remote CLI')
    environment = dict(os.environ, PATH=str(root) + os.pathsep + os.environ['PATH'])
    result = subprocess.run([binary, 'copy', str(source), '127.0.0.1:' + str(target)],
                            capture_output=True, text=True, timeout=10, env=environment)
    assert result.returncode == 0 and target.read_bytes() == source.read_bytes(), result.stderr
    print('PASS default copy CLI without options', flush=True)
    invoke(root, 'direct')
    invoke(root, 'ssh', 'ssh')
    invoke(root, 'fallback', options=('--udp-address=127.0.0.2',))
    invoke(root, 'encrypted-impairments', 'udp', environment=dict(os.environ, UFCP_TEST_IMPAIR_UDP='1'))
    invoke(root, 'empty', 'ssh', data=b'')
    invoke(root, 'empty-udp', data=b'')
    invoke(root, 'slow-disk', 'ssh', ('--receive-chunks=2', '--io-delay-ms=3'))
    args, target = invoke(root, 'overwrite', 'ssh')
    target.chmod(0o644)
    for mode in ('ssh', 'auto'):
        args, target = invoke(root, 'overwrite', mode)
        assert stat.S_IMODE(target.stat().st_mode) == 0o644, oct(target.stat().st_mode)
    print('PASS remote overwrite keeps destination permissions like scp', flush=True)
    folder = root / 'folder-target'
    folder.mkdir()
    source = root / 'folder.in'
    source.write_bytes(b'data')
    result = subprocess.run([binary, 'copy', str(source), '127.0.0.1:' + str(folder), '--transport=ssh',
                             '--ssh-program=' + str(root / 'ssh-fixture'), '--remote-program=' + binary],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode != 0 and 'destination is a directory' in result.stderr and not any(folder.iterdir())
    print('PASS remote directory destination refused', flush=True)
    download(root, 'direct')
    download(root, 'ssh', 'ssh')
    download(root, 'fallback', options=('--udp-address=127.0.0.2',))
    download(root, 'encrypted-impairments', 'udp', environment=dict(os.environ, UFCP_TEST_IMPAIR_UDP='1'))
    download(root, 'empty', 'ssh', data=b'')
    download(root, 'empty-udp', data=b'')
    download(root, 'slow-disk', 'ssh', ('--receive-chunks=2', '--io-delay-ms=3'))
    result, _ = download(root, 'stats', options=('--stats',))
    assert 'Stats:' in result.stderr, result.stderr
    print('PASS download --stats summary relayed from the remote sender', flush=True)
    _, local = download(root, 'overwrite', 'ssh')
    local.chmod(0o640)
    _, local = download(root, 'overwrite')
    assert stat.S_IMODE(local.stat().st_mode) == 0o640
    print('PASS download overwrite keeps local permissions', flush=True)
    local = root / 'missing.download'
    result = subprocess.run([binary, 'copy', '127.0.0.1:' + str(root / 'no-such-file'), str(local),
                             '--ssh-program=' + str(root / 'ssh-fixture'), '--remote-program=' + binary],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode != 0 and 'remote source must be a readable regular file' in result.stderr
    assert not local.exists() and not pathlib.Path(str(local) + '.part').exists()
    print('PASS download of missing remote file fails cleanly', flush=True)
    for args, message in ((['a:x', 'b:y'], 'two remote hosts'), (['x', 'y'], 'must be [user@]host:path')):
        result = subprocess.run([binary, 'copy', *args], capture_output=True, text=True, timeout=10)
        assert result.returncode != 0 and message in result.stderr, result.stderr
    print('PASS copy direction validation', flush=True)
    source, target = root / 'strict.in', root / 'strict.out'
    source.write_bytes(b'test')
    args = [binary, 'copy', str(source), '127.0.0.1:' + str(target), '--transport=udp',
            '--udp-address=127.0.0.2', '--ssh-program=' + str(fixture), '--remote-program=' + binary]
    result = subprocess.run(args, capture_output=True, text=True, timeout=10)
    assert result.returncode != 0 and 'strict UDP mode' in result.stderr and not target.exists()
    for i in range(200):
        if not pathlib.Path(str(target) + '.part').exists():
            break
        time.sleep(0.01)
    assert not pathlib.Path(str(target) + '.part').exists()
    print('PASS strict UDP failure without fallback', flush=True)
    raw_helper(root, 'disconnect')
    raw_helper(root, 'bad-hash', bad_hash=True)
    raw_helper(root, 'lost-close', drop_after_publish=True)
    target = root / 'unconfirmed.out'
    args = [binary, 'copy', str(source), '127.0.0.1:' + str(target), '--transport=ssh',
            '--ssh-program=' + str(fixture), '--remote-program=' + binary]
    environment = dict(os.environ, UFCP_TEST_DROP_COMPLETE='1')
    result = subprocess.run(args, capture_output=True, text=True, timeout=10, env=environment)
    assert result.returncode != 0 and 'completion unconfirmed' in result.stderr
    assert target.read_bytes() == source.read_bytes() and not pathlib.Path(str(target) + '.part').exists()
    print('PASS sender reports unconfirmed when COMPLETE is lost after publication', flush=True)
    for bad in (bytes(4), struct.pack('!I', 8193), frame(255), frame(1, b'bad init')):
        result = subprocess.run([binary, '--helper'], input=bad, capture_output=True, timeout=3)
        assert result.returncode != 0
    print('PASS malformed control framing', flush=True)
