#!/usr/bin/python3
"""Local audit dispatcher, Bash command logger and JSONL snapshot exporter."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import selectors
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
import uuid

import auparse
from incident_audit_capture import CaptureStore, atomic_json, boot_id, in_window, locked

ROOT = Path('/var/log/incidentsim')
CONTEXT = Path('/etc/incidentsim/audit-context.json')
MAX_BYTES = 16 * 1024 * 1024
BACKUPS = 3


def now():
    return datetime.now(timezone.utc).isoformat(timespec='milliseconds')


def encode(value):
    return json.dumps(value, ensure_ascii=True, separators=(',', ':'))


def context():
    return json.loads(CONTEXT.read_text())


def append(event, path=None):
    """One lock covers rotation and writes from dispatcher and Bash processes."""
    path = Path(path) if path is not None else ROOT / 'events.jsonl'
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    line = (encode(event) + '\n').encode()
    with locked(path.parent / '.events.lock'):
        if path.exists() and path.stat().st_size + len(line) > MAX_BYTES:
            for index in range(BACKUPS, 0, -1):
                old = path if index == 1 else Path(str(path) + f'.{index - 1}')
                if old.exists():
                    os.replace(old, Path(str(path) + f'.{index}'))
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(descriptor, 'ab') as stream:
            stream.write(line)


def captures():
    return CaptureStore(ROOT, append)


def audit_boundary():
    """Wait until the dispatcher has processed the kernel marker and its queue."""
    token = uuid.uuid4().hex
    subprocess.run(['auditctl', '-m', 'incsim_boundary=' + token],
                   check=True, capture_output=True, text=True)
    deadline = time.monotonic() + 15
    path = ROOT / 'boundary-ack.json'
    while time.monotonic() < deadline:
        if path.exists():
            ack = json.loads(path.read_text())
            if ack['token'] == token:
                return {k: ack[k] for k in ('timestamp', 'serial', 'boot_id')}
        time.sleep(0.05)
    raise RuntimeError('audit dispatcher did not acknowledge the boundary; inspect auditd and retry')


def boundary_in_event(parser):
    parser.first_record()
    while True:
        # An EXECVE argument also contains the token: only the kernel USER
        # message emitted by auditctl is an authoritative boundary.
        if parser.get_type_name() == 'USER':
            match = re.search(r'\bincsim_boundary=([a-f0-9]{32})\b', parser.get_record_text())
            if match:
                stamp = parser.get_timestamp()
                return {'token': match[1], 'serial': stamp.serial, 'boot_id': boot_id(),
                        'timestamp': datetime.fromtimestamp(
                            stamp.sec + stamp.milli / 1000, timezone.utc
                        ).isoformat(timespec='milliseconds')}
        if not parser.next_record():
            return None


def number(value):
    try:
        result = int(value)
        return None if result in (-1, 4294967295) else result
    except (ValueError, TypeError):
        return None


def audit_bytes(value):
    if len(value) >= 2 and value.startswith('"') and value.endswith('"'):
        return value[1:-1].encode('utf-8')
    if re.fullmatch(r'(?:[0-9a-fA-F]{2})+', value):
        return bytes.fromhex(value)
    return value.encode('utf-8')


def normalize(parser, vm_id):
    """Use libauparse for event grouping, hex decoding and syscall names."""
    # JSON performs its own escaping; preserve actual argument bytes/characters.
    parser.set_escape_mode(auparse.AUPARSE_ESC_RAW)
    stamp = parser.get_timestamp()
    timestamp = datetime.fromtimestamp(
        stamp.sec + stamp.milli / 1000, timezone.utc).isoformat(timespec='milliseconds')
    records, decoding_warnings = [], []
    parser.first_record()
    while True:
        values, raw = {}, {}
        kind = parser.get_type_name()
        if parser.first_field():
            while True:
                name = parser.get_field_name()
                raw[name] = parser.get_field_str()
                if kind == 'EXECVE' and re.fullmatch(r'a\d+(?:\[\d+\])?', name):
                    # A UTF-8 character may span multiple kernel argument records.
                    values[name] = raw[name]
                else:
                    try:
                        values[name] = parser.interpret_field()
                    except UnicodeDecodeError:
                        values[name] = audit_bytes(raw[name]).decode('utf-8', 'backslashreplace')
                        decoding_warnings.append({'record_type': kind, 'field': name,
                                                  'raw': raw[name]})
                if not parser.next_field():
                    break
        records.append((kind, values, raw))
        if not parser.next_record():
            break
    syscall = next((r for r in records if r[0] == 'SYSCALL'), None)
    values, raw = syscall[1:] if syscall else ({}, {})
    actor_raw = raw or next((r[2] for r in records if 'auid' in r[2]), {})
    actor = {key: number(actor_raw.get(field)) for key, field in
             [('login_uid', 'auid'), ('uid', 'uid'), ('effective_uid', 'euid'),
              ('session_id', 'ses')]}
    actor['user'] = values.get('uid')
    process = {key: number(raw.get(key)) for key in ('pid', 'ppid')}
    process.update(executable=values.get('exe'), name=values.get('comm'),
                   tty=values.get('tty'))
    process['cwd'] = next((v.get('cwd') for t, v, _ in records if t == 'CWD'), None)
    argv, argc, pieces = [], None, {}
    for record_type, decoded, original in records:
        if record_type != 'EXECVE':
            continue
        if 'argc' in original:
            argc = int(original['argc'])
        for name, value in decoded.items():
            match = re.fullmatch(r'a(\d+)(?:\[(\d+)\])?', name)
            if match:
                index, fragment = int(match[1]), int(match[2] or 0)
                pieces.setdefault(index, {})[fragment] = audit_bytes(original[name])
    if argc is not None:
        argv = [b''.join(pieces[index][part] for part in sorted(pieces[index])).decode(
                    'utf-8', 'backslashreplace')
                if index in pieces else None for index in range(argc)]
    proctitle = next((r.get('proctitle') for t, _, r in records if t == 'PROCTITLE'), None)
    process_argv = []
    if proctitle and re.fullmatch(r'[0-9a-fA-F]+', proctitle) and len(proctitle) % 2 == 0:
        process_argv = bytes.fromhex(proctitle).decode('utf-8', 'replace').rstrip('\0').split('\0')
    process['argv'] = argv or process_argv
    paths = [{key: value for key, value in fields.items()
              if key not in ('type', 'msg')} for kind, fields, _ in records if kind == 'PATH']
    name = values.get('syscall')
    key = values.get('key')
    if name in ('execve', 'execveat'):
        kind = 'exec'
    elif key == 'incsim_connect':
        kind = 'connect'
    elif key == 'incsim_chdir':
        kind = 'chdir'
    elif key and key.startswith('incsim_'):
        kind = 'file'
    elif any(t.startswith(('USER_', 'CRED_', 'LOGIN')) for t, _, _ in records):
        kind = 'authentication'
    else:
        kind = 'audit'
    arguments = process['argv']
    boundary_command = (len(arguments) == 3 and Path(arguments[0]).name == 'auditctl' and
                        arguments[1] == '-m' and
                        re.fullmatch(r'incsim_boundary=[a-f0-9]{32}', arguments[2]) is not None)
    origin = ('instrumentation' if '/usr/local/sbin/incident-audit' in
              arguments[:2] or boundary_command else 'session')
    event = {
        'schema_version': 1, 'event_id': f'{vm_id}:audit:{stamp.sec}.{stamp.milli:03}:{stamp.serial}',
        'timestamp': timestamp, 'vm_id': vm_id, 'source': 'auditd', 'kind': kind,
        'audit_serial': stamp.serial,
        'origin': origin, 'actor': actor, 'process': process,
        'syscall': name, 'syscall_success': raw.get('success') == 'yes' if syscall else None,
        # execve success is NOT the eventual exit status of the launched command.
        'syscall_return': int(raw['exit']) if syscall and 'exit' in raw else None,
        'audit_key': key, 'paths': paths,
    }
    if not syscall:
        event['details'] = [{'type': t, 'fields': {k: v for k, v in fields.items()
                             if k not in ('type', 'msg')}} for t, fields, _ in records]
    addresses = [v.get('saddr') for t, v, _ in records if t == 'SOCKADDR']
    if addresses:
        event['socket_addresses'] = addresses
    if decoding_warnings:
        event['decoding_warnings'] = decoding_warnings
    return event


def stream_events():
    cfg = context()
    parser = auparse.AuParser(auparse.AUSOURCE_FEED, None)
    total = 0
    errors = 0
    pending_boundaries = []

    def ready(au, reason, _):
        nonlocal total, errors
        if reason == auparse.AUPARSE_CB_EVENT_READY:
            try:
                boundary = boundary_in_event(au)
                if boundary is not None:
                    pending_boundaries.append((time.monotonic(), boundary))
                elif captures().record(normalize(au, cfg['vm_id'])):
                    total += 1
            except Exception as error:
                errors += 1
                print(f'JSONL conversion failed: {type(error).__name__}; raw audit log retained',
                      file=sys.stderr, flush=True)

    parser.add_callback(ready, None)
    selector = selectors.DefaultSelector()
    selector.register(sys.stdin.fileno(), selectors.EVENT_READ)
    running = True

    def stop(*_):
        nonlocal running
        running = False

    signal.signal(signal.SIGTERM, stop)
    last_health = 0
    try:
        while running:
            if selector.select(timeout=1):
                data = os.read(sys.stdin.fileno(), 65536)
                if not data:
                    break
                parser.feed(data.decode('utf-8', 'replace'))
            parser.feed_age_events()
            # Allow the parser's 2-second EOE timeout to release events that
            # preceded the marker before acknowledging a start/stop operation.
            while pending_boundaries and time.monotonic() - pending_boundaries[0][0] >= 2.1:
                _, boundary = pending_boundaries.pop(0)
                atomic_json(ROOT / 'boundary-ack.json', boundary)
            if time.monotonic() - last_health >= 5:
                atomic_json(ROOT / 'collector-health.json',
                            {'updated_at': now(), 'pid': os.getpid(),
                             'events_written': total, 'conversion_errors': errors})
                last_health = time.monotonic()
    finally:
        parser.flush_feed()
        selector.close()
        atomic_json(ROOT / 'collector-health.json',
                    {'updated_at': now(), 'stopped_at': now(), 'pid': os.getpid(),
                     'events_written': total, 'conversion_errors': errors})


def shell_event(args):
    match = re.match(r'\s*(\d+)\s+(.*)', args.history, re.DOTALL)
    if not match:
        return
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    identity = f'{boot}:{args.shell_pid}:{match[1]}'
    actor = {'uid': os.getuid(), 'effective_uid': os.geteuid()}
    for key, filename in [('login_uid', 'loginuid'), ('session_id', 'sessionid')]:
        try:
            actor[key] = number(Path(f'/proc/{args.shell_pid}/{filename}').read_text())
        except OSError:
            actor[key] = None
    captures().record({'schema_version': 1, 'event_id': f'shell:{identity}:{args.phase}',
            'command_id': identity, 'timestamp': now(), 'vm_id': context()['vm_id'],
            'source': 'bash', 'kind': f'command_{args.phase}', 'origin': 'session',
            'actor': actor, 'shell_pid': args.shell_pid, 'tty': args.tty,
            'cwd': args.cwd, 'command': match[2],
            'exit_status': args.status if args.phase == 'finish' else None})


def status():
    result = subprocess.run(['auditctl', '-s'], capture_output=True, text=True)
    kernel = {}
    for line in result.stdout.splitlines():
        name, _, value = line.partition(' ')
        kernel[name] = int(value) if value.isdigit() else value
    health = ROOT / 'collector-health.json'
    return {'vm_id': context()['vm_id'], 'checked_at': now(), 'audit': kernel,
            'capture': captures().current(),
            'collector': json.loads(health.read_text()) if health.exists() else None,
            'retention': {'jsonl_file_mib': 16, 'jsonl_files': BACKUPS + 1,
                          'raw_file_mib': 16, 'raw_files': 8}}


def snapshot_file(source, target):
    """Copy only the original size: do not chase logs written by this export."""
    with source.open('rb') as reader, target.open('xb') as writer:
        remaining = os.fstat(reader.fileno()).st_size
        while remaining:
            block = reader.read(min(remaining, 1024 * 1024))
            if not block:
                break
            writer.write(block)
            remaining -= len(block)


def export_events(args, window=None, emit=True):
    cfg = context()
    if window is None and not args.all_events:
        window = captures().get(args.session_id)
        if window['phase'] != 'stopped':
            raise RuntimeError('stop the recording session before exporting its final snapshot')
    source = captures().directory(window['session_id']) if window else ROOT
    output = Path(args.output) if args.output else source / 'actions.jsonl'
    output.parent.mkdir(parents=True, exist_ok=True)
    with locked(ROOT / '.export.lock'), tempfile.TemporaryDirectory(
            prefix='.export-', dir=ROOT) as directory:
        temporary = Path(directory)
        database = sqlite3.connect(temporary / 'events.sqlite')
        database.execute('CREATE TABLE events (id TEXT PRIMARY KEY, ts TEXT, body TEXT)')
        count_bad_lines = 0

        def insert(event, replace=False):
            if window is not None:
                if not in_window(event, window):
                    return
                event = {**event, 'capture_session_id': window['session_id']}
            if event.get('origin') == 'instrumentation' and not args.include_instrumentation:
                return
            operation = 'REPLACE' if replace else 'IGNORE'
            database.execute(f'INSERT OR {operation} INTO events VALUES (?, ?, ?)',
                             (event['event_id'], event['timestamp'], encode(event)))

        sources = [source] if window else [ROOT, *sorted((ROOT / 'sessions').glob('*'))]
        index = 0
        for source_directory in sources:
            if not source_directory.is_dir():
                continue
            with locked(source_directory / '.events.lock'):
                for path in sorted(source_directory.glob('events.jsonl*')):
                    frozen = temporary / f'json-{index}'
                    snapshot_file(path, frozen)
                    index += 1
        for frozen in temporary.glob('json-*'):
            with frozen.open() as reader:
                for line in reader:
                    try:
                        insert(json.loads(line))
                    except (ValueError, KeyError):
                        count_bad_lines += 1
        raw_files = []
        raw_paths = sorted(Path('/var/log/audit').glob('audit.log*'),
                           key=lambda p: int(p.name.split('.')[-1])
                           if p.name.split('.')[-1].isdigit() else 0, reverse=True)
        for index, path in enumerate(raw_paths):
            frozen = temporary / f'raw-{index}'
            snapshot_file(path, frozen)
            raw_files.append(str(frozen))
        if raw_files:
            parser = auparse.AuParser(auparse.AUSOURCE_FILE_ARRAY, raw_files)
            while parser.parse_next_event():
                insert(normalize(parser, cfg['vm_id']), replace=True)
        if window:
            # Durable state is also the source of boundary annotations if a
            # dispatcher/process restart interrupted writing a marker line.
            for label, field in [('recording_started', 'start_boundary'),
                                 ('recording_stopped', 'stop_boundary')]:
                boundary = window[field]
                insert({'schema_version': 1,
                        'event_id': f"{cfg['vm_id']}:capture:{window['session_id']}:{label}",
                        'timestamp': boundary['timestamp'], 'vm_id': cfg['vm_id'],
                        'source': 'control', 'kind': 'marker', 'origin': 'control',
                        'capture_session_id': window['session_id'], 'label': label,
                        'audit_serial': boundary['serial']})
        database.commit()
        staged = temporary / 'actions.jsonl'
        count = 0
        with staged.open('w') as writer:
            for (body,) in database.execute('SELECT body FROM events ORDER BY ts, id'):
                writer.write(body + '\n')
                count += 1
        limits = database.execute('SELECT MIN(ts), MAX(ts) FROM events').fetchone()
        database.close()
        # Temp and output must share a filesystem for an atomic snapshot.
        descriptor, external = tempfile.mkstemp(prefix='.actions-', dir=output.parent)
        try:
            with os.fdopen(descriptor, 'wb') as writer, staged.open('rb') as reader:
                while block := reader.read(1024 * 1024):
                    writer.write(block)
                writer.flush()
                os.fsync(writer.fileno())
            os.replace(external, output)
        finally:
            if os.path.exists(external):
                os.unlink(external)
        manifest = status()
        manifest['capture'] = ({k: v for k, v in window.items() if k != 'artifacts'}
                               if window else None)
        manifest.update(schema_version=1, events=count, first_event=limits[0],
                        last_event=limits[1], invalid_jsonl_lines=count_bad_lines,
                        raw_logs_reparsed=len(raw_files), output=str(output),
                        limitations=['Retention is bounded; older rotated logs may be absent.',
                                     'Audit does not capture stdout, stderr or file contents.',
                                     'Root can disable or alter this guest-local telemetry.',
                                     'Bash hooks apply to new interactive Bash shells.'])
        atomic_json(output.with_suffix('.manifest.json'), manifest)
    result = {'output': str(output), 'events': count,
              'manifest': str(output.with_suffix('.manifest.json'))}
    if emit:
        print(encode(result))
    return result


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='operation', required=True)
    commands.add_parser('stream')
    commands.add_parser('status')
    start = commands.add_parser('start', help='call after infrastructure preparation, before sharing access')
    start.add_argument('--session-id', required=True)
    stop = commands.add_parser('stop', help='seal recording before running validation')
    stop.add_argument('--session-id', required=True)
    export = commands.add_parser('export')
    export.add_argument('--output')
    selection = export.add_mutually_exclusive_group()
    selection.add_argument('--session-id')
    selection.add_argument('--all', dest='all_events', action='store_true',
                           help='unfiltered diagnostic export, including legacy/raw logs')
    export.add_argument('--include-instrumentation', action='store_true')
    marker = commands.add_parser('mark')
    marker.add_argument('label')
    shell = commands.add_parser('shell')
    shell.add_argument('--phase', choices=['start', 'finish'], required=True)
    shell.add_argument('--history', required=True)
    shell.add_argument('--shell-pid', type=int, required=True)
    shell.add_argument('--cwd', required=True)
    shell.add_argument('--tty', default='')
    shell.add_argument('--status', type=int)
    args = parser.parse_args()
    if args.operation == 'stream':
        stream_events()
    elif args.operation == 'shell':
        shell_event(args)
    elif args.operation == 'status':
        print(encode(status()))
    elif args.operation == 'export':
        export_events(args)
    elif args.operation == 'start':
        print(encode(captures().start(args.session_id, context()['vm_id'], audit_boundary)))
    elif args.operation == 'stop':
        export_args = argparse.Namespace(output=None, all_events=False,
                                         session_id=args.session_id, include_instrumentation=False)
        state = captures().stop(
            args.session_id, audit_boundary,
            lambda window: export_events(export_args, window=window, emit=False))
        print(encode({**state, **state['artifacts']}))
    elif args.operation == 'mark':
        event = {'schema_version': 1, 'event_id': str(uuid.uuid4()), 'timestamp': now(),
                'vm_id': context()['vm_id'], 'source': 'control', 'kind': 'marker',
                'origin': 'control', 'label': args.label}
        if not captures().record(event):
            raise RuntimeError('annotations require an active recording session')
        print(encode({'label': args.label, 'capture_session_id': captures().current()['session_id']}))


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, ValueError, OSError, subprocess.CalledProcessError) as error:
        print(f'incident-audit: {error}', file=sys.stderr)
        sys.exit(1)
