#!/usr/bin/env python3
"""Connect to a prepared demo, or stop, validate and display its LLM report."""
import argparse
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from analyze import analyze, AnalysisError
from incident_audit_compact import atomic_text, compact_file


def remote(settings, arguments, source=None):
    result = subprocess.run(settings['ssh_command'] + [settings['target'], shlex.join(arguments)],
                            input=source, capture_output=True, timeout=90)
    if result.returncode:
        raise RuntimeError('SSH operation failed; check VM reachability and session ID')
    return result.stdout


def finish(run_dir, config, dry_run=False):
    run_dir = Path(run_dir).resolve()
    settings = json.loads((run_dir / 'session.json').read_text(encoding='utf-8'))
    identity = settings['session_id']
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,95}', identity):
        raise ValueError('invalid demo session ID')
    artifacts = run_dir / 'artifacts'
    artifacts.mkdir(exist_ok=True, mode=0o700)
    print('Stopping recording...', flush=True)
    state = json.loads(remote(settings, ['incident-audit', 'stop', '--session-id', identity]))
    if state['phase'] != 'stopped':
        raise RuntimeError('recording is not stopped; validation was not started')
    for name in ('llm.json', 'llm.stats.json', 'llm.sources.json', 'actions.jsonl',
                 'actions.manifest.json'):
        data = remote(settings, ['cat', f'/var/log/incidentsim/sessions/{identity}/{name}'])
        atomic_text(artifacts / name, data.decode('utf-8'))
    # Apply the host's current filtering, including to exports from an older guest.
    compact_file(artifacts / 'actions.jsonl')
    print('Logs collected. Running validation outside the recording window...', flush=True)
    validation = json.loads(remote(settings, ['python3', '-'],
                           (ROOT / 'examples/http-service/validate.py').read_bytes()))
    validation_path = run_dir / 'validation.json'
    atomic_text(validation_path, json.dumps(validation, ensure_ascii=False) + '\n')
    print('Validation: ' + ('PASS' if validation['passed'] else 'FAIL'), flush=True)
    print('Checking request...' if dry_run else 'Calling LLM...', flush=True)
    result = analyze(config, artifacts / 'llm.json', ROOT / 'examples/http-service/task.md',
                     run_dir / 'report', validation_path, dry_run=dry_run)
    print(json.dumps(result, ensure_ascii=False), flush=True)
    if not dry_run:
        print('\n' + Path(result['output']).read_text(encoding='utf-8'))
    return result


def main():
    os.umask(0o077)
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('connect', 'finish'))
    parser.add_argument('--run-dir', type=Path, required=True)
    parser.add_argument('--config', type=Path, default=ROOT / 'config/llm.local.json')
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args()
    if args.operation == 'connect':
        settings = json.loads((args.run_dir / 'session.json').read_text(encoding='utf-8'))
        sys.exit(subprocess.run(settings['ssh_command'] + ['-tt', settings['target']]).returncode)
    else:
        finish(args.run_dir, args.config, args.dry_run)


if __name__ == '__main__':
    try:
        main()
    except (AnalysisError, RuntimeError, OSError, ValueError, KeyError,
            subprocess.TimeoutExpired) as error:
        print('demo: ' + str(error), file=sys.stderr)
        sys.exit(1)
