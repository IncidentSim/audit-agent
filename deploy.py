#!/usr/bin/env python3
"""Bundle this directory or install it on a Linux machine over standard SSH."""
import argparse
import io
import json
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tarfile

FILES = (
    'install.py', 'incident-audit.py', 'incident_audit_capture.py', 'incidentsim-audit.sh',
    'incidentsim-json.conf', '50-incidentsim.rules',
    'test_audit.py', 'test_capture.py', 'test_deploy.py', 'verify.py', 'README.md', 'deploy.py',
)

# No remote shell interpolation of destination paths, VM labels or credentials.
# Extract only plain files with known names into a private temporary directory.
BOOTSTRAP = r'''
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile

options = json.loads(sys.argv[1])
allowed = set(options['files'])
with tempfile.TemporaryDirectory(prefix='incident-audit-') as directory:
    stage = Path(directory)
    with tarfile.open(fileobj=sys.stdin.buffer, mode='r|gz') as archive:
        for entry in archive:
            if entry.name not in allowed or not entry.isfile():
                raise RuntimeError('unexpected entry in audit-agent bundle')
            with archive.extractfile(entry) as reader, (stage / entry.name).open('xb') as writer:
                while True:
                    block = reader.read(1024 * 1024)
                    if not block:
                        break
                    writer.write(block)
    if not all((stage / name).is_file() for name in allowed):
        raise RuntimeError('incomplete audit-agent bundle')
    prefix = ['sudo', '-n'] if options['sudo'] else []
    command = prefix + [sys.executable, '-B', str(stage / 'install.py')]
    if options['vm_id'] is not None:
        command += ['--vm-id', options['vm_id']]
    if options['skip_packages']:
        command.append('--skip-packages')
    subprocess.run(command, check=True)
    if options['verify']:
        subprocess.run(prefix + [sys.executable, '-B', '-m', 'unittest', '-v',
                                 'test_audit.py', 'test_capture.py', 'test_deploy.py'], cwd=stage, check=True)
        subprocess.run(prefix + [sys.executable, '-B', str(stage / 'verify.py')], check=True)
'''


def build_bundle(source):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w:gz') as archive:
        for name in FILES:
            path = source / name
            if path.is_symlink() or not path.is_file():
                raise RuntimeError(f'missing regular package file: {name}')
            archive.add(path, arcname=name, recursive=False)
    return buffer.getvalue()


def make_command(args):
    if (not args.target or args.target.startswith('-') or
            any(c.isspace() or ord(c) < 32 for c in args.target)):
        raise ValueError('specify an SSH destination such as admin@vm.example.com')
    command = ['ssh', '-T', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=15',
               '-o', 'StrictHostKeyChecking=accept-new']
    if args.port is not None:
        if not 1 <= args.port <= 65535:
            raise ValueError('SSH port must be between 1 and 65535')
        command += ['-p', str(args.port)]
    if args.identity is not None:
        command += ['-i', str(Path(args.identity).expanduser())]
    for option in args.ssh_option:
        command += ['-o', option]
    options = {'sudo': args.sudo, 'vm_id': args.vm_id,
               'skip_packages': args.skip_packages, 'verify': args.verify,
               'files': list(FILES)}
    remote = shlex.join([args.python, '-c', BOOTSTRAP, json.dumps(options)])
    return command + [args.target, remote]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('target', nargs='?', help='SSH destination or an alias from ~/.ssh/config')
    parser.add_argument('--sudo', action='store_true', help='use passwordless sudo on the target')
    parser.add_argument('--vm-id', help='optional VM/session label, generated if omitted')
    parser.add_argument('--identity', help='local SSH private key path (never bundled)')
    parser.add_argument('--port', type=int)
    parser.add_argument('--ssh-option', action='append', default=[],
                        help='OpenSSH -o option, e.g. ProxyJump=bastion')
    parser.add_argument('--python', default='/usr/bin/python3',
                        help='target system Python interpreter')
    parser.add_argument('--skip-packages', action='store_true')
    parser.add_argument('--verify', action='store_true', help='run unit tests and a real collection check')
    parser.add_argument('--bundle-only', type=Path, help='write a transferable tar.gz instead of connecting')
    args = parser.parse_args()
    if args.bundle_only and args.target:
        parser.error('use either an SSH target or --bundle-only')
    source = Path(__file__).resolve().parent
    bundle = build_bundle(source)
    if args.bundle_only:
        args.bundle_only.parent.mkdir(parents=True, exist_ok=True)
        with args.bundle_only.open('xb') as stream:
            stream.write(bundle)
        print(f'Created {args.bundle_only} ({len(bundle)} bytes)')
        return
    command = make_command(args)
    if shutil.which('ssh') is None:
        parser.error('install an OpenSSH client on the machine running deploy.py')
    # Subprocess argv protects the local shell; shlex.join protects the remote shell.
    subprocess.run(command, input=bundle, check=True)


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f'Deployment failed: {error}', file=sys.stderr)
        sys.exit(1)
