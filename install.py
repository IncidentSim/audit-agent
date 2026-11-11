#!/usr/bin/python3
"""Install standalone audit collection on an Ubuntu/Debian x86_64 machine."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import subprocess
import sys
import time
import uuid


def backup(path):
    target = path.with_name(path.name + '.before-incidentsim')
    if path.exists() and not target.exists():
        shutil.copyfile(path, target)
        target.chmod(0o600)


def select_vm_id(requested, context_path):
    """Reuse an installation's identity; a new machine needs no external VM API."""
    if requested is not None and (not requested.strip() or
                                 any(c in requested for c in '\r\n\0')):
        raise RuntimeError('invalid VM identity')
    if context_path.exists():
        existing = json.loads(context_path.read_text(encoding='utf-8'))['vm_id']
        if requested is not None and existing != requested:
            raise RuntimeError('existing audit context belongs to another VM')
        return existing
    return requested if requested is not None else f'{socket.gethostname()}-{uuid.uuid4().hex[:12]}'


def preflight(skip_packages):
    if sys.platform != 'linux' or platform.machine().lower() not in ('x86_64', 'amd64'):
        raise RuntimeError('this installer supports Linux x86_64')
    if sys.version_info < (3, 10):
        raise RuntimeError('Python 3.10 or newer is required')
    if os.geteuid() != 0:
        raise RuntimeError('run as root or use sudo')
    if not Path('/run/systemd/system').is_dir():
        raise RuntimeError('systemd must be running on the target machine')
    if {'audit=0', 'audit=off'} & set(Path('/proc/cmdline').read_text().split()):
        raise RuntimeError('kernel command line disables audit; enable it before installing')
    try:
        with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 9):
            pass
    except OSError as error:
        raise RuntimeError('the target kernel does not provide accessible Linux Audit') from error
    required = ['systemctl']
    if not skip_packages:
        required.append('apt-get')
    for command in required:
        if shutil.which(command) is None:
            raise RuntimeError(f'missing {command}; Ubuntu/Debian with apt and systemd is required')


def check_audit_policy():
    result = subprocess.run(['auditctl', '-s'], capture_output=True, text=True, check=True)
    if any(line.split() == ['enabled', '2'] for line in result.stdout.splitlines()):
        raise RuntimeError('audit policy is immutable; reboot with a mutable policy before installing')
    rules = subprocess.run(['auditctl', '-l'], capture_output=True, text=True, check=True)
    if '-a never,task' in rules.stdout:
        raise RuntimeError('an existing never,task audit rule disables syscall collection; review that policy first')
    subprocess.run(['/usr/bin/python3', '-c', 'import auparse'], check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--vm-id', help='session/VM label; generated once if omitted')
    parser.add_argument('--skip-packages', action='store_true')
    args = parser.parse_args()
    preflight(args.skip_packages)
    source = Path(__file__).resolve().parent
    for filename in ('incident-audit.py', 'incident_audit_capture.py',
                     'incident_audit_compact.py', '50-incidentsim.rules',
                     'incidentsim-json.conf', 'incidentsim-audit.sh'):
        if not (source / filename).is_file():
            raise RuntimeError(f'incomplete distribution: missing {filename}')
    context = Path('/etc/incidentsim/audit-context.json')
    vm_id = select_vm_id(args.vm_id, context)
    os.umask(0o077)
    if not args.skip_packages:
        subprocess.run(['apt-get', 'update', '-qq'], check=True)
        subprocess.run(['apt-get', 'install', '-y', '--no-install-recommends',
                        'auditd', 'python3-audit'], check=True,
                       env={**os.environ, 'DEBIAN_FRONTEND': 'noninteractive'})
    check_audit_policy()
    logs = Path('/var/log/incidentsim')
    logs.mkdir(parents=True, exist_ok=True)
    logs.chmod(0o700)
    audit_logs = Path('/var/log/audit')
    audit_logs.mkdir(parents=True, exist_ok=True)
    audit_logs.chmod(0o700)
    cfg_dir = Path('/etc/incidentsim')
    cfg_dir.mkdir(mode=0o700, exist_ok=True)
    if not context.exists():
        context.write_text(json.dumps({
            'schema_version': 1, 'vm_id': vm_id,
            'installed_at': datetime.now(timezone.utc).isoformat()}, indent=2) + '\n',
            encoding='utf-8')
        context.chmod(0o600)
    for src, dst, mode in [
        ('incident-audit.py', '/usr/local/sbin/incident-audit', 0o755),
        ('incident_audit_capture.py', '/usr/local/sbin/incident_audit_capture.py', 0o644),
        ('incident_audit_compact.py', '/usr/local/sbin/incident_audit_compact.py', 0o644),
        ('50-incidentsim.rules', '/etc/audit/rules.d/50-incidentsim.rules', 0o600),
        ('incidentsim-json.conf', '/etc/audit/plugins.d/incidentsim-json.conf', 0o640),
        ('incidentsim-audit.sh', '/etc/profile.d/incidentsim-audit.sh', 0o644),
    ]:
        destination = Path(dst)
        destination.parent.mkdir(parents=True, exist_ok=True)
        # Install LF even if a Windows checkout or archive contains CRLF.
        with destination.open('w', encoding='utf-8', newline='\n') as stream:
            stream.write((source / src).read_text(encoding='utf-8'))
        destination.chmod(mode)
    config_path = Path('/etc/audit/auditd.conf')
    backup(config_path)
    overrides = {'log_group': 'root', 'max_log_file': '16', 'num_logs': '8',
                 'max_log_file_action': 'ROTATE', 'freq': '10', 'q_depth': '8192'}
    lines = []
    for line in config_path.read_text(encoding='utf-8').splitlines():
        key = line.partition('=')[0].strip()
        lines.append(f'{key} = {overrides.pop(key)}' if key in overrides else line)
    lines.extend(f'{key} = {value}' for key, value in overrides.items())
    config_path.write_text('\n'.join(lines) + '\n', encoding='utf-8')
    bashrc = Path('/etc/bash.bashrc')
    include = 'source /etc/profile.d/incidentsim-audit.sh'
    if include not in bashrc.read_text(encoding='utf-8'):
        backup(bashrc)
        with bashrc.open('a') as stream:
            stream.write('\n# IncidentSim: log interactive root Bash commands.\n' + include + '\n')
    subprocess.run(['systemctl', 'enable', 'auditd.service'], check=True)
    started = time.time()
    subprocess.run(['systemctl', 'restart', 'auditd.service'], check=True)
    subprocess.run(['augenrules', '--load'], check=True)
    health = logs / 'collector-health.json'
    for _ in range(30):
        if health.exists() and health.stat().st_mtime >= started:
            state = json.loads(health.read_text())
            if not state.get('stopped_at') and state['conversion_errors'] == 0:
                break
        time.sleep(0.25)
    else:
        raise RuntimeError('JSONL dispatcher did not become ready; inspect journalctl -u auditd')
    kernel_rules = subprocess.run(['auditctl', '-l'], capture_output=True, text=True, check=True)
    if 'incsim_exec' not in kernel_rules.stdout:
        raise RuntimeError('audit rules were not loaded')
    subprocess.run(['/usr/local/sbin/incident-audit', 'status'], check=True)
    print('Audit configured. Call incident-audit start after infrastructure preparation.')


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f'Installation failed: {error}', file=sys.stderr)
        sys.exit(1)
