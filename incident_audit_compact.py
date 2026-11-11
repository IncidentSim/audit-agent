"""Offline, deterministic action-level export; no LLM calls and no auparse dependency."""
import argparse
from bisect import bisect_right
from collections import Counter, defaultdict
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import sys
import tempfile


def dumps(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'))


def timestamp(value):
    return datetime.fromisoformat(value).timestamp()


def read_events(path):
    with Path(path).open(encoding='utf-8') as stream:
        for number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                yield json.loads(line)
            except ValueError as error:
                raise ValueError(f'invalid JSONL at line {number}') from error


def redact(text):
    """Known secret patterns only; this is not a guarantee of secret-free text."""
    text = re.sub(r'(?i)(https?://)[^/\s:@]+:[^@\s/]+@', r'\1<credentials>@', text)
    text = re.sub(r'(?i)(Authorization:\s*(?:Bearer|Basic)\s+)[^\s\'"]+',
                  r'\1<secret>', text)
    value = r"""('[^']*'|"[^"]*"|[^\s;&|]+)"""
    text = re.sub(
        r'(?i)(--(?:password|passwd|token|api-key|secret|access-key)(?:=|\s+))' + value,
        r'\1<secret>', text)
    text = re.sub(
        r'(?i)(\b(?:[A-Z_]*PASSWORD|[A-Z_]*TOKEN|[A-Z_]*API_KEY|[A-Z_]*SECRET)=)' + value,
        r'\1<secret>', text)
    return text


def safe_argv(arguments):
    result = []
    secret_next = False
    for argument in arguments:
        value = '<missing-argument>' if argument is None else str(argument)
        if secret_next:
            result.append('<secret>')
            secret_next = False
            continue
        result.append(redact(value))
        if value.lower() in ('--password', '--passwd', '--token', '--api-key',
                             '--secret', '--access-key'):
            secret_next = True
    return result


def actor_key(event):
    actor = event.get('actor') or {}
    tty = event.get('tty') or (event.get('process') or {}).get('tty') or ''
    tty = tty.removeprefix('/dev/')
    if tty in ('(none)', 'none', '?'):
        tty = ''
    tty = re.sub(r'^pts(\d+)$', r'pts/\1', tty)
    return (actor.get('login_uid'), actor.get('effective_uid', actor.get('uid')),
            actor.get('session_id'), tty)


def same_session(left, right):
    return all(a is None or b is None or a == b
               for a, b in zip(left[:3], right[:3]))


def argv_visible_in_command(arguments, command):
    if not arguments or any(a is None for a in arguments):
        return False
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=';&|()<>')
        lexer.whitespace_split = True
        tokens = list(lexer)
    except ValueError:
        return False
    for index in range(len(tokens) - len(arguments) + 1):
        if (Path(tokens[index]).name == Path(arguments[0]).name and
                tokens[index + 1:index + len(arguments)] == arguments[1:]):
            return True
    return False


def collector_event(event):
    process = event.get('process') or {}
    return (event.get('origin') == 'instrumentation' or
            (process.get('name') == 'incident-audit' and
             Path(process.get('executable') or '').name.startswith('python')))


class Action:
    def __init__(self, key, moment, event, kind):
        self.key, self.start, self.end = key, moment, None
        self.kind, self.actor = kind, actor_key(event)
        self.cmd, self.rc = None, None
        self.cwd = event.get('cwd') or (event.get('process') or {}).get('cwd')
        self.cwd_after = None
        self.shell_pid = event.get('shell_pid')
        self.refs, self.ref_set, self.effects, self.execs = [], set(), [], []
        self.parent, self.note = None, None
        self.missing_start, self.exec_failed = False, None
        self.process = (event.get('process') or {}).get('name')
        self.add_ref(event)

    def add_ref(self, event):
        identifier = event['event_id']
        if identifier not in self.ref_set:
            self.refs.append(identifier)
            self.ref_set.add(identifier)

    def effect(self, detail):
        if self.effects and self.effects[-1][0] == detail:
            self.effects[-1][1] += 1
        else:
            self.effects.append([detail, 1])

    def executed(self, arguments, result):
        detail = {'argv': safe_argv(arguments)}
        if result is not None:
            detail['sysrc'] = result
        if self.execs and self.execs[-1][0] == detail:
            self.execs[-1][1] += 1
        else:
            self.execs.append([detail, 1])


def file_detail(event, owner):
    syscall = event.get('syscall') or 'file'
    operation = ('write_open' if syscall in ('open', 'openat', 'creat') else
                 'open' if syscall == 'openat2' else syscall)
    detail = {'op': operation}
    names = []
    for path in event.get('paths', []):
        name = path.get('name')
        if path.get('nametype') != 'PARENT' and name and name != '(null)' and name not in names:
            names.append(name)
    if names:
        detail['p'] = names[0] if len(names) == 1 else names
    else:
        detail['p'] = None
    result = event.get('syscall_return')
    if result is not None and result < 0:
        detail['sysrc'] = result
    elif event.get('syscall_success') is None:
        detail['result_unknown'] = True
    cwd = (event.get('process') or {}).get('cwd')
    if cwd and cwd != owner.cwd and any(not p.startswith('/') for p in names):
        detail['cwd'] = cwd
    return detail


def limited_details(groups, limit):
    """Keep failures and meaningful mutations before low-level opens; retain order."""
    if len(groups) <= limit:
        chosen = set(range(len(groups)))
    else:
        priority = sorted(range(len(groups)), key=lambda i: (
            0 if 'sysrc' in groups[i][0] else
            2 if groups[i][0].get('op') in ('open', 'write_open') else 1, i))
        chosen = set(priority[:limit])
    result = []
    omitted = 0
    for index, (detail, count) in enumerate(groups):
        if index in chosen:
            result.append({**detail, **({'n': count} if count > 1 else {})})
        else:
            omitted += count
    return result, omitted


def build_packet(source, manifest, effects_limit=24, exec_limit=12):
    window = manifest.get('capture')
    if not window or window.get('phase') != 'stopped':
        raise ValueError('a manifest with a stopped recording window is required')
    baseline = timestamp(window['started_at'])
    end = timestamp(window['stopped_at'])
    actions, shell_actions = [], {}
    input_counts = Counter()
    for event in read_events(source):
        input_counts[event.get('source', 'unknown')] += 1
        if event.get('capture_session_id') != window['session_id']:
            raise ValueError('event belongs to another recording window')
        if event.get('source') != 'bash':
            continue
        identity = event['command_id']
        moment = timestamp(event['timestamp'])
        if identity not in shell_actions:
            action = Action(identity, moment, event, 'command')
            action.missing_start = event['kind'] != 'command_start'
            shell_actions[identity] = action
            actions.append(action)
        action = shell_actions[identity]
        action.add_ref(event)
        action.cmd = event['command']
        if event['kind'] == 'command_start':
            action.start, action.cwd, action.missing_start = moment, event.get('cwd'), False
        else:
            action.end, action.rc = moment, event.get('exit_status')
            action.cwd_after = event.get('cwd')
    by_shell = defaultdict(list)
    for action in shell_actions.values():
        if not action.missing_start:
            by_shell[action.shell_pid].append(action)
    for group in by_shell.values():
        group.sort(key=lambda a: a.start)
    starts = {pid: [a.start for a in group] for pid, group in by_shell.items()}

    def shell_at(pid, moment, actor):
        group = by_shell.get(pid, [])
        index = bisect_right(starts.get(pid, []), moment) - 1
        if index < 0:
            return None
        action = group[index]
        until = action.end if action.end is not None else (
            group[index + 1].start if index + 1 < len(group) else end)
        if moment <= until and same_session(actor, action.actor):
            return action
        return None

    process_owners = {}
    discarded = Counter()
    unattributed = 0
    for event in read_events(source):
        source_type, kind = event.get('source'), event.get('kind')
        if source_type == 'bash':
            continue
        if collector_event(event):
            discarded['instrumentation'] += 1
            continue
        if (kind == 'file' and event.get('syscall') in ('open', 'openat') and
                event.get('syscall_success') is True):
            names = [p.get('name') for p in event.get('paths', [])
                     if p.get('nametype') != 'PARENT' and p.get('name') != '(null)']
            if names and all(name in ('/dev/null', '/dev/tty') for name in names):
                discarded['terminal_device_opens'] += 1
                continue
        moment = timestamp(event['timestamp'])
        if source_type == 'control':
            if event.get('label') in ('recording_started', 'recording_stopped'):
                discarded['boundary_markers'] += 1
                continue
            action = Action(event['event_id'], moment, event, 'note')
            action.note = event.get('label')
            actions.append(action)
            continue
        if source_type != 'auditd' or kind not in ('exec', 'file', 'connect', 'chdir'):
            important = [d for d in event.get('details', [])
                         if d.get('type', '').startswith(('AVC', 'USER_AVC', 'SECCOMP', 'ANOM_'))]
            if important:
                action = Action(event['event_id'], moment, event, 'system')
                action.note = important
                actions.append(action)
            else:
                discarded[kind or 'unknown'] += 1
            continue
        process = event.get('process') or {}
        pid, ppid, actor = process.get('pid'), process.get('ppid'), actor_key(event)
        owner = shell_at(pid, moment, actor) or shell_at(ppid, moment, actor)
        cached = process_owners.get(pid)
        if owner is None and cached and cached[0] == ppid:
            candidate = cached[1]
            if (same_session(actor, candidate.actor) and
                    (candidate.end is None or moment <= candidate.end)):
                owner = candidate
        parent = process_owners.get(ppid)
        if owner is None and parent:
            candidate = parent[1]
            if (same_session(actor, candidate.actor) and
                    (candidate.end is None or moment <= candidate.end)):
                owner = candidate
        if kind == 'exec':
            arguments = process.get('argv') or []
            # A fresh exec can represent PID reuse; do not inherit an old PID owner.
            if owner is not None and cached and owner is cached[1] and owner.kind == 'exec':
                owner = shell_at(ppid, moment, actor)
                if (owner is None and parent and same_session(actor, parent[1].actor) and
                        (parent[1].end is None or moment <= parent[1].end)):
                    owner = parent[1]
            if owner is None:
                owner = Action(event['event_id'], moment, event, 'exec')
                owner.cmd = shlex.join(safe_argv(arguments)) if arguments else None
                owner.exec_failed = (event.get('syscall_return')
                                     if event.get('syscall_success') is False else None)
                if parent:
                    owner.parent = parent[1]
                actions.append(owner)
            elif (event.get('syscall_success') is False or
                  not argv_visible_in_command(arguments, owner.cmd or '')):
                owner.executed(arguments, event.get('syscall_return')
                               if event.get('syscall_success') is False else None)
            owner.add_ref(event)
            if pid is not None and pid not in by_shell:
                process_owners[pid] = (ppid, owner)
            continue
        if owner is None:
            owner = Action(event['event_id'], moment, event, 'effect')
            if parent:
                owner.parent = parent[1]
            actions.append(owner)
            unattributed += 1
        owner.add_ref(event)
        if kind == 'file':
            owner.effect(file_detail(event, owner))
        elif kind == 'connect':
            detail = {'op': 'connect', 'to': event.get('socket_addresses') or None}
            if event.get('syscall_return') is not None and event['syscall_return'] < 0:
                detail['sysrc'] = event['syscall_return']
            owner.effect(detail)
        elif owner.kind != 'command':
            owner.effect(file_detail(event, owner))

    actions.sort(key=lambda a: (a.start, a.key))
    identifiers = {a.key: index for index, a in enumerate(actions, 1)}
    actor_ids, actor_context, common_cwd = {}, {}, {}
    for action in actions:
        if action.actor not in actor_ids:
            identity = str(len(actor_ids) + 1)
            actor_ids[action.actor] = identity
            login, effective, session, tty = action.actor
            actor_context[identity] = {k: v for k, v in
                [('login_uid', login), ('uid', effective), ('audit_session', session), ('tty', tty)]
                if v is not None and v != ''}
    for actor in actor_ids:
        known = [a.cwd for a in actions if a.actor == actor and a.cwd is not None]
        if known:
            common_cwd[actor] = Counter(known).most_common(1)[0][0]
            actor_context[actor_ids[actor]]['cwd'] = common_cwd[actor]
    timeline, references = [], {}
    omitted_details, redactions = 0, 0
    for action in actions:
        identifier = identifiers[action.key]
        row = {'id': identifier, 't': round(action.start - baseline, 3),
               's': int(actor_ids[action.actor])}
        if action.cmd is not None:
            row['cmd'] = redact(action.cmd)
            redactions += row['cmd'] != action.cmd
            row['rc'] = action.rc
        if action.kind != 'command':
            row['via'] = action.kind
        if action.end is not None and not action.missing_start:
            row['dt'] = round(action.end - action.start, 3)
        if action.cwd != common_cwd.get(action.actor) or action.cwd is None:
            row['cwd'] = action.cwd
        if action.cwd_after and action.cwd_after != action.cwd:
            row['cwd_after'] = action.cwd_after
        if action.missing_start:
            row['missing_start'] = True
        if action.exec_failed is not None:
            row['exec_sysrc'] = action.exec_failed
        if action.parent and action.parent.key in identifiers:
            row['parent'] = identifiers[action.parent.key]
        if action.note is not None:
            row['note'] = action.note
        for field, groups, limit in [('effects', action.effects, effects_limit),
                                     ('exec', action.execs, exec_limit)]:
            details, omitted = limited_details(groups, limit)
            if details:
                row[field] = details
            if omitted:
                row[field + '_omitted'] = omitted
                omitted_details += omitted
        timeline.append(row)
        references[str(identifier)] = action.refs
    packet = {
        'v': 1, 'session': window['session_id'], 'duration_s': round(end - baseline, 3),
        'actors': actor_context,
        'coverage': {
            'stdout': False, 'file_contents': False, 'exit_status': 'bash_only',
            'audit_lost_total': manifest.get('audit', {}).get('lost'),
            'dispatcher_errors': (manifest.get('collector') or {}).get('conversion_errors'),
            'unattributed_effects': unattributed, 'omitted_details': omitted_details,
            'attribution': 'best_effort_pid_parent_and_shell_interval',
            'redaction': 'known_secret_patterns_only',
        },
        'legend': {'t': 'seconds since recording start', 's': 'actor ID',
                   'dt': 'observed command duration in seconds',
                   'rc': 'observed Bash status; null is unknown',
                   'cwd': 'actor cwd is the default; null is unknown',
                   'sysrc': 'syscall return, not program status; -115 means connect in progress',
                   'effects': 'observed operations, not file diffs; order is preserved',
                   'via': 'exec lacks a Bash command; effect has uncertain attribution'},
        'actions': timeline,
    }
    stats = {'input_events': sum(input_counts.values()), 'actions': len(timeline),
             'shell_commands': len(shell_actions), 'discarded': dict(discarded),
             'omitted_details': omitted_details, 'redacted_command_rows': redactions}
    return packet, references, stats


def atomic_text(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix='.' + path.name, dir=path.parent)
    try:
        with os.fdopen(descriptor, 'w', encoding='utf-8', newline='\n') as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def redact_tree(value):
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, list):
        return [redact_tree(item) for item in value]
    if isinstance(value, dict):
        return {key: redact_tree(item) for key, item in value.items()}
    return value


def compact_file(source, manifest_path=None, output=None, effects_limit=24, exec_limit=12,
                 max_bytes=None, tokenizer_path=None):
    source = Path(source)
    manifest_path = Path(manifest_path) if manifest_path else source.with_suffix('.manifest.json')
    output = Path(output) if output else source.with_name('llm.json')
    sources_path = output.with_name(output.stem + '.sources.json')
    stats_path = output.with_name(output.stem + '.stats.json')
    if any(path.resolve() in (source.resolve(), manifest_path.resolve())
           for path in (output, sources_path, stats_path)):
        raise ValueError('compact output must not overwrite full source data or manifest')
    if min(effects_limit, exec_limit) < 0:
        raise ValueError('detail limits must be nonnegative')
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    packet, references, stats = build_packet(source, manifest, effects_limit, exec_limit)
    text = dumps(redact_tree(packet)) + '\n'
    size = len(text.encode('utf-8'))
    if max_bytes is not None and size > max_bytes:
        raise ValueError(f'compact packet is {size} bytes, above {max_bytes}; no commands were silently dropped')
    source_hash = hashlib.sha256()
    with source.open('rb') as reader:
        while block := reader.read(1024 * 1024):
            source_hash.update(block)
    stats.update(source_bytes=source.stat().st_size, compact_bytes=size,
                 byte_reduction_pct=round(100 * (1 - size / max(1, source.stat().st_size)), 2),
                 token_counts=None)
    if tokenizer_path:
        try:
            from tokenizers import Tokenizer
        except ImportError as error:
            raise RuntimeError('token counting requires the optional tokenizers package') from error
        tokenizer = Tokenizer.from_file(str(tokenizer_path))
        stats['token_counts'] = {
            'source': len(tokenizer.encode(source.read_text(encoding='utf-8'),
                                          add_special_tokens=False).ids),
            'compact': len(tokenizer.encode(text, add_special_tokens=False).ids),
            'tokenizer_sha256': hashlib.sha256(Path(tokenizer_path).read_bytes()).hexdigest(),
        }
    atomic_text(sources_path, dumps({'source': str(source), 'sha256': source_hash.hexdigest(),
                                    'actions': references}) + '\n')
    atomic_text(stats_path, dumps(stats) + '\n')
    atomic_text(output, text)
    return {'llm': str(output), 'llm_sources': str(sources_path), 'llm_stats': str(stats_path),
            **stats}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', required=True, type=Path)
    parser.add_argument('--manifest', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--effects-limit', type=int, default=24)
    parser.add_argument('--exec-limit', type=int, default=12)
    parser.add_argument('--max-bytes', type=int)
    parser.add_argument('--tokenizer', type=Path, help='optional local Hugging Face tokenizer.json')
    args = parser.parse_args()
    print(dumps(compact_file(args.input, args.manifest, args.output, args.effects_limit,
                            args.exec_limit, args.max_bytes, args.tokenizer)))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, RuntimeError, OSError) as error:
        print(f'compact export: {error}', file=sys.stderr)
        sys.exit(1)
