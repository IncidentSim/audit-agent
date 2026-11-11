#!/usr/bin/python3
"""Exercise installed collection without printing any participant commands."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import uuid

tool = '/usr/local/sbin/incident-audit'
login_uid = int(Path('/proc/self/loginuid').read_text())
if login_uid == 4294967295:
    # A root provisioning process may have no PAM login session. Set only this
    # test process's identity so its children exercise the session audit rules.
    Path('/proc/self/loginuid').write_text(str(os.getuid()))
    login_uid = os.getuid()
initial = json.loads(subprocess.run(
    [tool, 'status'], check=True, capture_output=True, text=True).stdout)
initial_lost = initial['audit']['lost']
if initial.get('capture') and initial['capture']['phase'] != 'stopped':
    raise RuntimeError('verification requires an idle collector; active user recording was left untouched')
marker = 'incsim-smoke-' + uuid.uuid4().hex[:12]
argument = marker + ' words\nпривет'
before_argument = marker + '-before'
after_argument = marker + '-validator'
tail_argument = marker + '-last-before-stop'
subprocess.run(['/usr/bin/printf', '%s', before_argument], stdout=subprocess.DEVNULL, check=True)
started = json.loads(subprocess.run(
    [tool, 'start', '--session-id', marker], check=True, capture_output=True, text=True).stdout)
live_path = Path('/var/log/incidentsim/sessions') / marker / 'events.jsonl'
with tempfile.TemporaryDirectory(prefix=marker + '-') as directory:
    root = Path(directory)
    subprocess.run(['/usr/bin/printf', '%s', argument], stdout=subprocess.DEVNULL, check=True)
    source = root / (marker + '-source')
    target = root / (marker + '-renamed')
    subprocess.run(['/usr/bin/touch', str(source)], check=True)
    subprocess.run(['/usr/bin/mv', str(source), str(target)], check=True)
    subprocess.run(['/usr/bin/chmod', '600', str(target)], check=True)
    subprocess.run(['/usr/bin/rm', str(target)], check=True)
    script = (f'cd {directory}\n'
              f'false # {marker}-false\n'
              f'printf builtin > {marker}-builtin\n'
              f'exit # {marker}-exit\n')
    shell = subprocess.run(
        ['/bin/bash', '--noprofile', '--rcfile', '/etc/profile.d/incidentsim-audit.sh', '-i'],
        input=script, text=True, capture_output=True,
        env={**os.environ, 'HISTFILE': '/dev/null', 'PS1': '', 'PS2': ''}, timeout=20)
    assert shell.returncode == 0, 'interactive test shell failed'
    assert (root / (marker + '-builtin')).read_text() == 'builtin'
    subprocess.run([tool, 'mark', marker], check=True)

    def read_events():
        return [json.loads(line) for line in
                live_path.read_text().splitlines()]

    for _ in range(40):
        events = read_events()
        external = [e for e in events if e['kind'] == 'exec' and
                    argument in e.get('process', {}).get('argv', [])]
        completed = [e for e in events if e['source'] == 'bash' and
                     e['kind'] == 'command_finish' and
                     e['command'] == f'false # {marker}-false']
        exited = [e for e in events if e['source'] == 'bash' and
                  e['kind'] == 'command_start' and e['command'] == f'exit # {marker}-exit']
        if external and completed and exited:
            break
        time.sleep(0.25)
    else:
        raise AssertionError('missing real-time exec, Bash completion or exit-command input')
    assert completed[0]['exit_status'] == 1, 'false must retain its actual shell status'
    assert external[0]['actor']['login_uid'] == login_uid, 'login identity must survive sudo'
    assert any(e['kind'] == 'file' and any(marker in p.get('name', '') for p in e['paths'])
               for e in events if e['source'] == 'auditd'), 'missing file-change events'
    # Stop immediately after an exec: its records may still be in the audit queue.
    subprocess.run(['/usr/bin/printf', '%s', tail_argument], stdout=subprocess.DEVNULL, check=True)
    result = subprocess.run([tool, 'stop', '--session-id', marker],
                            check=True, capture_output=True, text=True)
    exported = json.loads(result.stdout)
    recorded_size = live_path.stat().st_size
    subprocess.run(['/usr/bin/printf', '%s', after_argument], stdout=subprocess.DEVNULL, check=True)
    result = subprocess.run([tool, 'export', '--session-id', marker],
                            check=True, capture_output=True, text=True)
    exported = json.loads(result.stdout)
    actions = [json.loads(line) for line in Path(exported['output']).read_text().splitlines()]
    assert len({e['event_id'] for e in actions}) == len(actions), 'duplicate event IDs'
    assert [e['timestamp'] for e in actions] == sorted(e['timestamp'] for e in actions)
    assert any(e['kind'] == 'exec' and argument in e.get('process', {}).get('argv', [])
               for e in actions), 'export lost an executed command'
    assert any(e['kind'] == 'exec' and tail_argument in e.get('process', {}).get('argv', [])
               for e in actions), 'stop lost events still buffered at the boundary'
    assert not any(a in e.get('process', {}).get('argv', [])
                   for e in actions for a in (before_argument, after_argument)), 'capture boundaries leaked'
    assert all(e['capture_session_id'] == marker for e in actions)
    assert live_path.stat().st_size == recorded_size, 'JSONL kept growing after stop'
    manifest = json.loads(Path(exported['manifest']).read_text())
    assert manifest['audit']['enabled'] == 1
    assert manifest['audit']['lost'] == initial_lost, 'audit lost events during the test'
    assert manifest['invalid_jsonl_lines'] == 0
    assert manifest['collector']['conversion_errors'] == 0
    assert manifest['capture']['phase'] == 'stopped'
    assert manifest['capture']['start_boundary']['serial'] < manifest['capture']['stop_boundary']['serial']
    for path in (Path(exported['output']), Path(exported['manifest'])):
        assert path.stat().st_mode & 0o777 == 0o600, 'private export permissions required'
    print(json.dumps({'result': 'PASS', 'events_in_export': len(actions),
                      'audit_lost': manifest['audit']['lost'],
                      'checks': ['exec arguments with Unicode/newlines', 'root identity',
                                 'file changes', 'Bash builtins', 'failed command status',
                                 'exit command input', 'ordered deduplicated JSONL',
                                 'raw-log recovery', 'private file permissions',
                                 'start/stop window', 'validation excluded', 'recording frozen']}))
