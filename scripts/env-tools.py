#!/usr/bin/env python3
"""Configuration is parsed as data, never sourced as shell code."""
import argparse
import datetime
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import stat
import sys

MARKER = '# RizenVuln managed S3'

def read_env(path):
    values = {}
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        key, sep, value = line.partition('=')
        if not sep or not re.fullmatch(r'[A-Z][A-Z0-9_]*', key):
            raise ValueError('Invalid environment file syntax')
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key] = value
    return values

def validate(host, ip):
    if len(host) > 253 or '.' not in host or host.endswith('.') or not all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', p) for p in host.split('.')):
        raise ValueError('Invalid S3 hostname')
    addr = ipaddress.ip_address(ip)
    if addr.is_unspecified or addr.is_loopback or addr.is_link_local or addr.is_multicast:
        raise ValueError('Invalid S3 address: unspecified, loopback, link-local, multicast denied')
    return host.lower(), str(addr)

def managed_hosts(text, host, ip):
    lines = text.splitlines(keepends=True)
    # An unmanaged mapping is not ours to silently replace.
    for line in lines:
        if line.rstrip().endswith(MARKER):
            continue
        fields = line.split('#', 1)[0].split()
        if host.lower() in [f.lower() for f in fields[1:]]:
            if fields[0] == ip:
                return ''.join(x for x in lines if not x.rstrip().endswith(MARKER))
            raise ValueError('Hostname already has an unmanaged mapping; resolve conflict manually')
    kept = [x for x in lines if not x.rstrip().endswith(MARKER)]
    prefix = ''.join(kept)
    if prefix and not prefix.endswith('\n'):
        prefix += '\n'
    return prefix + f'{ip}\t{host}\t{MARKER}\n'

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['init', 'hosts', 'compose'])
    parser.add_argument('--env', default='.env')
    parser.add_argument('--email')
    parser.add_argument('--hostname')
    parser.add_argument('--ip')
    parser.add_argument('--hosts-file', default='/etc/hosts', help='Alternate file for tests')
    args = parser.parse_args()
    if args.command == 'init':
        if not args.email or not re.fullmatch(r'[^\s@]+@[^\s@]+', args.email) or any(c in args.email for c in "'\"$#\\"):
            parser.error('--email must contain your administrator email')
        values = {'ADMIN_EMAIL': args.email, 'ADMIN_PASSWORD': secrets.token_hex(24),
                  'SESSION_SECRET': secrets.token_hex(48), 'POSTGRES_PASSWORD': secrets.token_hex(32),
                  'METRICS_TOKEN': secrets.token_hex(32)}
        values['DATABASE_URL'] = f"postgres://rizenvuln:{values['POSTGRES_PASSWORD']}@rizenvuln-postgres:5432/rizenvuln"
        template = Path('.env.example').read_text()
        for key, value in values.items():
            template = re.sub(rf'^{key}=.*$', f'{key}={value}', template, flags=re.M)
        fd = os.open(args.env, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as stream:
            stream.write(template)
        print(f'Created {args.env} (0600). Credentials are only in this file.')
        return
    values = read_env(args.env) if Path(args.env).exists() else {}
    host, ip = args.hostname or values.get('S3_HOSTNAME'), args.ip or values.get('S3_HOST_IP')
    if not host or not ip:
        print('S3 hostname/IP missing; no changes made.')
        return
    host, ip = validate(host, ip)
    if args.command == 'compose':
        content = {'services': {name: {'extra_hosts': [f'{host}={ip}']} for name in ['rizenvuln-api', 'rizenvuln-worker']}}
        output = Path('docker-compose.s3.yml')
        output.write_text(json.dumps(content, indent=2) + '\n')
        output.chmod(0o600)
        print('Generated docker-compose.s3.yml; use -f docker-compose.yml -f docker-compose.s3.yml')
        return
    target = Path(args.hosts_file)
    if target.is_symlink():
        raise ValueError('Refusing symlink hosts file')
    # Lock the same inode; /etc/hosts can be a mount and cannot always be renamed.
    import fcntl
    with target.open('r+') as stream:
        fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
        original = stream.read()
        updated = managed_hosts(original, host, ip)
        if original != updated:
            stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
            backup = target.with_name(target.name + '.rizenvuln.' + stamp + '.bak')
            fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'w') as copy:
                copy.write(original)
            stream.seek(0)
            stream.write(updated)
            stream.truncate()
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), 0o644)
            print(f'Managed record updated; backup: {backup}')
        else:
            print('Managed record already correct.')
    if target.resolve() == Path('/etc/hosts'):
        addresses = {str(ipaddress.ip_address(x[4][0])) for x in socket.getaddrinfo(host, None)}
        if ip not in addresses:
            raise ValueError('Record written but hostname resolution verification failed')
        print('Hostname resolution verified.')
    else:
        print('Alternate hosts file updated; system resolver was not changed.')

if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError) as exc:
        print(f'Configuration operation failed: {exc}', file=sys.stderr)
        sys.exit(1)
