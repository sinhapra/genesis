"""Optional real OpenSSH loopback acceptance tests; all keys/configuration live in a temporary directory."""
import getpass
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import tempfile
import time

binary = str(pathlib.Path(sys.argv[1]).resolve())
sshd = os.environ.get('UFCP_TEST_SSHD') or shutil.which('sshd')
assert sshd, 'set UFCP_TEST_SSHD to an available sshd executable'


def run(args):
    return subprocess.run(args, capture_output=True, text=True, timeout=30)


with tempfile.TemporaryDirectory(prefix='ufcp-real-ssh-') as directory:
    root = pathlib.Path(directory)
    for name in ('host', 'client', 'wrong'):
        result = run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(root / name)])
        assert result.returncode == 0, result.stderr
    (root / 'authorized_keys').write_bytes((root / 'client.pub').read_bytes())
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    (root / 'sshd_config').write_text(f'''Port {port}
ListenAddress 127.0.0.1
HostKey {root / 'host'}
PidFile {root / 'pid'}
AuthorizedKeysFile {root / 'authorized_keys'}
StrictModes no
UsePAM no
PasswordAuthentication no
ChallengeResponseAuthentication no
PubkeyAuthentication yes
AllowUsers {getpass.getuser()}
LogLevel ERROR
''')
    public = (root / 'host.pub').read_text().split()
    (root / 'known_hosts').write_text(f'[127.0.0.1]:{port} {public[0]} {public[1]}\n')
    (root / 'config').write_text(f'''Host ufcp-fixture
    HostName 127.0.0.1
    User {getpass.getuser()}
    Port {port}
    IdentityFile {root / 'client'}
    UserKnownHostsFile {root / 'known_hosts'}
    StrictHostKeyChecking yes
    IdentitiesOnly yes
''')
    server = subprocess.Popen([str(pathlib.Path(sshd).resolve()), '-D', '-e', '-f', str(root / 'sshd_config')],
                              stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    try:
        for _ in range(100):
            if server.poll() is not None:
                raise AssertionError(server.stderr.read())
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=0.1):
                    break
            except OSError:
                time.sleep(0.02)
        else:
            raise AssertionError('isolated sshd did not start')
        source = root / 'input'
        source.write_bytes(os.urandom(256 * 1024 + 19))
        base = [binary, 'copy', str(source)]
        options = ['--ssh-config=' + str(root / 'config'), '--remote-program=' + binary]
        for name, extra, expected in [('tunnel', ['--transport=ssh'], 'SSH/TCP'),
                                      ('auto-direct', ['--udp-address=127.0.0.1'], 'direct UDP'),
                                      ('auto-fallback', ['--udp-address=127.0.0.2'], 'SSH/TCP')]:
            target = root / (name + " ' ; $(printf ignored)")
            result = run(base + ['ufcp-fixture:' + str(target)] + options + extra)
            assert result.returncode == 0, (result.stdout, result.stderr)
            assert 'Transport: ' + expected in result.stdout and target.read_bytes() == source.read_bytes()
            assert not pathlib.Path(str(target) + '.part').exists()
            print('PASS real OpenSSH', name, flush=True)
        helper_path = root / "helper ' with spaces"
        helper_path.symlink_to(binary)
        target = root / 'quoted-program.out'
        result = run(base + ['ufcp-fixture:' + str(target), '--ssh-config=' + str(root / 'config'),
                             '--remote-program=' + str(helper_path), '--transport=ssh'])
        assert result.returncode == 0 and target.read_bytes() == source.read_bytes(), result.stderr
        print('PASS real SSH quoted helper program path', flush=True)
        wrong_config = root / 'wrong-config'
        wrong_config.write_text((root / 'config').read_text().replace(str(root / 'client'), str(root / 'wrong')))
        target = root / 'unauthorized'
        result = run(base + ['ufcp-fixture:' + str(target), '--ssh-config=' + str(wrong_config), '--remote-program=' + binary])
        assert result.returncode != 0 and not target.exists()
        print('PASS real SSH authentication rejection', flush=True)
        bad_hosts = root / 'bad-hosts'
        wrong_public = (root / 'wrong.pub').read_text().split()
        bad_hosts.write_text(f'[127.0.0.1]:{port} {wrong_public[0]} {wrong_public[1]}\n')
        wrong_config.write_text((root / 'config').read_text().replace(str(root / 'known_hosts'), str(bad_hosts)))
        result = run(base + ['ufcp-fixture:' + str(target), '--ssh-config=' + str(wrong_config), '--remote-program=' + binary])
        assert result.returncode != 0 and not target.exists()
        print('PASS real SSH host-key mismatch rejection', flush=True)
    finally:
        server.terminate()
        try:
            server.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill(); server.communicate()
