"""Durable, externally controlled recording windows; no audit or VM API dependency."""
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
from functools import lru_cache
import json
import os
from pathlib import Path
import re
import tempfile


def encode(value):
    return json.dumps(value, ensure_ascii=True, separators=(',', ':'))


def now():
    return datetime.now(timezone.utc).isoformat(timespec='milliseconds')


@lru_cache(maxsize=1)
def boot_id():
    return Path('/proc/sys/kernel/random/boot_id').read_text().strip()


def atomic_json(path, value):
    descriptor, temporary = tempfile.mkstemp(prefix='.' + path.name, dir=path.parent)
    try:
        with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
            stream.write(encode(value) + '\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


@contextmanager
def locked(path):
    descriptor = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        os.close(descriptor)


def valid_session_id(value):
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,95}', value):
        raise ValueError('session ID must be 1-96 ASCII letters, digits, dots, underscores or hyphens')
    return value


def in_window(event, window):
    """Audit serials disambiguate events sharing a millisecond at a boundary."""
    if event.get('vm_id') != window['vm_id']:
        return False
    if event.get('source') != 'auditd':
        return event.get('capture_session_id') == window['session_id']
    start = window.get('start_boundary')
    if not start:
        return False
    serial = event.get('audit_serial')
    if serial is None:
        serial = int(event['event_id'].rsplit(':', 1)[1])
    if serial <= start['serial'] or event['timestamp'] < start['timestamp']:
        return False
    end = window.get('stop_boundary')
    return end is None or (serial < end['serial'] and event['timestamp'] <= end['timestamp'])


class CaptureStore:
    def __init__(self, root, writer):
        self.root = Path(root)
        self.writer = writer

    def directory(self, session_id):
        return self.root / 'sessions' / valid_session_id(session_id)

    def current(self):
        path = self.root / 'capture.json'
        return json.loads(path.read_text()) if path.exists() else None

    def get(self, session_id=None):
        current = self.current()
        if session_id is None:
            if current is None:
                raise RuntimeError('no recording session; call incident-audit start first')
            return current
        valid_session_id(session_id)
        if current and current['session_id'] == session_id:
            return current
        path = self.directory(session_id) / 'session.json'
        if not path.exists():
            raise RuntimeError('unknown recording session')
        return json.loads(path.read_text())

    def save(self, state):
        atomic_json(self.root / 'capture.json', state)
        atomic_json(self.directory(state['session_id']) / 'session.json', state)

    def marker(self, state, kind, boundary):
        event = {'schema_version': 1,
                 'event_id': f"{state['vm_id']}:capture:{state['session_id']}:{kind}",
                 'timestamp': boundary['timestamp'], 'vm_id': state['vm_id'],
                 'source': 'control', 'kind': 'marker', 'origin': 'control',
                 'capture_session_id': state['session_id'], 'label': kind,
                 'audit_serial': boundary['serial']}
        self.writer(event, self.directory(state['session_id']) / 'events.jsonl')

    def start(self, session_id, vm_id, boundary):
        valid_session_id(session_id)
        self.root.mkdir(parents=True, mode=0o700, exist_ok=True)
        with locked(self.root / '.lifecycle.lock'):
            with locked(self.root / '.capture.lock'):
                current = self.current()
                if current and current['phase'] != 'stopped':
                    if current['session_id'] != session_id:
                        raise RuntimeError('another recording session is already active')
                    if current['boot_id'] != boot_id():
                        raise RuntimeError('machine rebooted during recording; manual recovery is required')
                    if current['phase'] == 'recording':
                        return current
                    if current['phase'] != 'starting':
                        raise RuntimeError('session is stopping; retry stop before starting another')
                    state = current
                else:
                    directory = self.directory(session_id)
                    if directory.exists() and any(directory.iterdir()):
                        raise RuntimeError('session ID has already been used; choose a new ID')
                    directory.mkdir(parents=True, mode=0o700, exist_ok=True)
                    state = {'schema_version': 1, 'session_id': session_id, 'vm_id': vm_id,
                             'boot_id': boot_id(), 'phase': 'starting', 'requested_at': now()}
                    self.save(state)
            start = boundary()
            with locked(self.root / '.capture.lock'):
                state = {**state, 'phase': 'recording', 'started_at': start['timestamp'],
                         'start_boundary': start}
                self.save(state)
                self.marker(state, 'recording_started', start)
            return state

    def record(self, event):
        """No capture file is created while idle or after stop."""
        with locked(self.root / '.capture.lock'):
            state = self.current()
            if (not state or state['phase'] not in ('recording', 'stopping') or
                    state['boot_id'] != boot_id()):
                return False
            if event.get('source') != 'auditd' and state['phase'] != 'recording':
                return False
            tagged = {**event, 'capture_session_id': state['session_id']}
            if not in_window(tagged, state):
                return False
            self.writer(tagged, self.directory(state['session_id']) / 'events.jsonl')
            return True

    def stop(self, session_id, boundary, finalize):
        valid_session_id(session_id)
        with locked(self.root / '.lifecycle.lock'):
            with locked(self.root / '.capture.lock'):
                state = self.get(session_id)
                if state['phase'] == 'stopped':
                    current = self.current()
                    if (current and current['session_id'] != session_id and
                            current['phase'] != 'stopped'):
                        raise RuntimeError('another session is active; validation of the old attempt is blocked')
                    return state
                current = self.current()
                if not current or current['session_id'] != session_id:
                    raise RuntimeError('requested session is not the active session')
                if state['phase'] not in ('recording', 'stopping'):
                    raise RuntimeError('recording has not started successfully')
                if state['boot_id'] != boot_id():
                    raise RuntimeError('machine rebooted during recording; manual recovery is required')
                if state['phase'] == 'recording':
                    state = {**state, 'phase': 'stopping', 'stop_requested_at': now()}
                    self.save(state)
            if 'stop_boundary' not in state:
                end = boundary()
                with locked(self.root / '.capture.lock'):
                    state = {**state, 'stopped_at': end['timestamp'], 'stop_boundary': end}
                    self.save(state)
                    self.marker(state, 'recording_stopped', end)
            # A failed export keeps the original cutoff and can safely be retried.
            sealed = {**state, 'phase': 'stopped', 'sealed_at': now()}
            result = finalize(sealed)
            with locked(self.root / '.capture.lock'):
                state = {**sealed, 'artifacts': result}
                self.save(state)
            return state
