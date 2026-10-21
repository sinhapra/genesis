"""Two-host UDP traversal test: sender and "song" run in separate unprivileged network namespaces on
different subnets joined by a router namespace. Each host can sit behind a stateful firewall (drop new
inbound, allow replies) and the router can masquerade the sender like a home NAT router.
Requires Linux user namespaces, iproute2, iptables and nsenter; nothing outside the namespaces changes."""
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

binary = str(pathlib.Path(sys.argv[1]).resolve())
SENDER, ROUTER_LAN, ROUTER_WAN, SONG = '10.8.0.1', '10.8.0.254', '10.9.0.1', '10.9.0.2'


def run(*args, ns=None, check=True):
    prefix = ['nsenter', '--net=/run/netns/' + ns] if ns else []
    return subprocess.run(prefix + list(args), check=check, capture_output=True, text=True)


def outer():
    missing = [tool for tool in ('unshare', 'nsenter', 'ip', 'iptables') if not shutil.which(tool)]
    if missing:
        print('SKIP netns test: missing ' + ', '.join(missing))
        return 0
    probe = subprocess.run(['unshare', '-rmn', 'true'], capture_output=True, text=True)
    if probe.returncode:
        print('SKIP netns test: unprivileged user namespaces unavailable: ' + probe.stderr.strip())
        return 0
    environment = dict(os.environ, UFCP_NETNS_INNER='1')
    return subprocess.run(['unshare', '-rmn', '--propagation', 'private', sys.executable,
                           __file__, binary], env=environment).returncode


def setup(root):
    os.makedirs('/run/netns', exist_ok=True)
    run('mount', '-t', 'tmpfs', 'none', '/run/netns')
    for name in ('sender', 'router', 'song'):
        open('/run/netns/' + name, 'w').close()
        run('unshare', '--net=/run/netns/' + name, 'true')
        run('ip', 'link', 'set', 'lo', 'up', ns=name)
    for host, address, port, gateway in (('sender', SENDER, 'lan', ROUTER_LAN),
                                         ('song', SONG, 'wan', ROUTER_WAN)):
        run('ip', 'link', 'add', 'v-' + host, 'type', 'veth', 'peer', 'name', 'v-' + port)
        run('ip', 'link', 'set', 'v-' + host, 'netns', host)
        run('ip', 'link', 'set', 'v-' + port, 'netns', 'router')
        run('ip', 'addr', 'add', address + '/24', 'dev', 'v-' + host, ns=host)
        run('ip', 'addr', 'add', gateway + '/24', 'dev', 'v-' + port, ns='router')
        run('ip', 'link', 'set', 'v-' + host, 'up', ns=host)
        run('ip', 'link', 'set', 'v-' + port, 'up', ns='router')
        run('ip', 'route', 'add', 'default', 'via', gateway, ns=host)
    run('sh', '-c', 'echo 1 > /proc/sys/net/ipv4/ip_forward', ns='router')
    hosts = root / 'hosts'
    hosts.write_text('127.0.0.1 localhost\n%s song\n' % SONG)
    run('mount', '--bind', str(hosts), '/etc/hosts')
    fixture = root / 'ssh-song'
    # Like sshd on song: run the remote command in song's namespace; SSH_CONNECTION names the client
    # address song observes (the router's address when the sender is behind NAT).
    fixture.write_text('#!/bin/sh\nfor last; do :; done\ncd "%s" || exit 1\n'
                       'SSH_CONNECTION="$(cat client) 51000 %s 22" exec nsenter --net=/run/netns/song sh -c "$last"\n'
                       % (root, SONG))
    fixture.chmod(0o700)
    return fixture


def firewall(name, rules):
    run('iptables', '-F', 'INPUT', ns=name)
    run('iptables', '-F', 'OUTPUT', ns=name)
    run('iptables', '-P', 'INPUT', 'ACCEPT', ns=name)
    if rules == 'stateful':
        run('iptables', '-A', 'INPUT', '-i', 'lo', '-j', 'ACCEPT', ns=name)
        run('iptables', '-A', 'INPUT', '-m', 'conntrack', '--ctstate', 'ESTABLISHED,RELATED',
            '-j', 'ACCEPT', ns=name)
        run('iptables', '-P', 'INPUT', 'DROP', ns=name)
    elif rules == 'no-udp':
        run('iptables', '-A', 'INPUT', '-p', 'udp', '-j', 'DROP', ns=name)
        run('iptables', '-A', 'OUTPUT', '-p', 'udp', '-j', 'DROP', ns=name)


def copy(root, fixture, name, mode, song_rules, sender_rules, expect, nat=False):
    firewall('song', song_rules)
    firewall('sender', sender_rules)
    run('iptables', '-t', 'nat', '-F', 'POSTROUTING', ns='router')
    if nat:
        run('iptables', '-t', 'nat', '-A', 'POSTROUTING', '-o', 'v-wan', '-j', 'MASQUERADE', ns='router')
    (root / 'client').write_text(ROUTER_WAN if nat else SENDER)
    source, target = root / (name + '.in'), root / (name + '.out')
    source.write_bytes(os.urandom(300000))
    result = run(binary, 'copy', str(source), 'song:' + str(target), '--transport=' + mode,
                 '--ssh-program=' + str(fixture), '--remote-program=' + binary,
                 ns='sender', check=False)
    if expect == 'fail':
        assert result.returncode and 'strict UDP mode' in result.stderr and not target.exists(), \
            (name, result.returncode, result.stdout, result.stderr)
    else:
        assert result.returncode == 0 and expect in result.stdout, (name, result.stdout, result.stderr)
        assert target.read_bytes() == source.read_bytes(), name
    print('PASS', name, flush=True)


def inner():
    with tempfile.TemporaryDirectory() as directory:
        root = pathlib.Path(directory)
        fixture = setup(root)
        direct, tunnel = 'Transport: direct UDP', 'Transport: SSH/TCP (fallback'
        for song_rules in ('open', 'stateful'):
            for sender_rules in ('open', 'stateful'):
                name = 'strict-udp song=%s sender=%s' % (song_rules, sender_rules)
                copy(root, fixture, name, 'udp', song_rules, sender_rules, direct)
        copy(root, fixture, 'strict UDP with sender behind NAT and both firewalls', 'udp', 'stateful',
             'stateful', direct, nat=True)
        copy(root, fixture, 'auto through stateful firewalls', 'auto', 'stateful', 'stateful', direct)
        copy(root, fixture, 'auto falls back when song blocks all UDP', 'auto', 'no-udp', 'open', tunnel)
        copy(root, fixture, 'strict UDP fails when song blocks all UDP', 'udp', 'no-udp', 'open', 'fail')
    print('All two-host namespace tests passed')
    return 0


sys.exit(inner() if os.environ.get('UFCP_NETNS_INNER') == '1' else outer())
