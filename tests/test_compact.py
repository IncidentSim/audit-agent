"""Check that compact exports save space without inventing command outcomes."""
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from incident_audit_compact import compact_file


BASE = datetime(2026, 11, 11, tzinfo=timezone.utc)
ACTOR = {'login_uid': 0, 'uid': 0, 'effective_uid': 0, 'session_id': 3}


def event(moment, **values):
    result = {'event_id': 'event-' + str(moment),
              'timestamp': (BASE + timedelta(seconds=moment)).isoformat(),
              'capture_session_id': 'attempt-001', 'source': 'auditd',
              'kind': 'exec', 'origin': 'session', 'actor': dict(ACTOR),
              'syscall': 'execve', 'syscall_success': True, 'syscall_return': 0,
              'process': {'pid': 11, 'ppid': 10, 'tty': 'pts0', 'cwd': '/root',
                          'argv': ['true']}}
    result.update(values)
    return result


def shell(moment, command='touch /tmp/a', phase='start', command_id='cmd-1',
          shell_pid=10, cwd='/root', rc=None, **values):
    return event(moment, source='bash', kind='command_' + phase, command_id=command_id,
                 shell_pid=shell_pid, tty='/dev/pts/0', command=command, cwd=cwd,
                 exit_status=rc, **values)


def executed(moment, argv, pid=11, ppid=10, **values):
    return event(moment, process={'pid': pid, 'ppid': ppid, 'argv': argv,
                                 'tty': 'pts0', 'cwd': '/root'}, **values)


def file_event(moment, syscall='openat', path='/tmp/a', pid=11, ppid=10, **values):
    return event(moment, kind='file', syscall=syscall,
                 process={'pid': pid, 'ppid': ppid, 'tty': 'pts0', 'cwd': '/root'},
                 paths=[{'name': '/tmp', 'nametype': 'PARENT'},
                        {'name': path, 'nametype': 'NORMAL'}], **values)


class CompactTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.source = Path(self.directory.name) / 'actions.jsonl'
        self.manifest_path = self.source.with_suffix('.manifest.json')
        self.manifest = {'capture': {'phase': 'stopped', 'session_id': 'attempt-001',
                                    'started_at': BASE.isoformat(),
                                    'stopped_at': (BASE + timedelta(seconds=100)).isoformat()},
                         'audit': {'lost': 0}, 'collector': {'conversion_errors': 0}}

    def export(self, events, **options):
        self.source.write_text(''.join(json.dumps(e, ensure_ascii=True) + '\n'
                                       for e in sorted(events, key=lambda e: e['timestamp'])),
                               encoding='utf-8')
        self.manifest_path.write_text(json.dumps(self.manifest), encoding='utf-8')
        result = compact_file(self.source, **options)
        self.packet = json.loads(Path(result['llm']).read_text(encoding='utf-8'))
        self.refs = json.loads(Path(result['llm_sources']).read_text(encoding='utf-8'))
        return result

    def test_join_command_exec_and_file_without_duplicate_command(self):
        events = [shell(1), executed(1.1, ['/usr/bin/touch', '/tmp/a']),
                  file_event(1.2), shell(2, phase='finish', rc=0)]
        result = self.export(events)
        row, = self.packet['actions']
        self.assertEqual((row['cmd'], row['rc'], row['dt']), ('touch /tmp/a', 0, 1))
        self.assertEqual(row['effects'], [{'op': 'write_open', 'p': '/tmp/a'}])
        self.assertNotIn('exec', row)
        self.assertEqual(set(self.refs['actions']['1']), {e['event_id'] for e in events})
        self.assertLess(result['compact_bytes'], result['source_bytes'])
        self.assertIsNone(result['token_counts'])

    def test_execve_success_is_not_program_success(self):
        self.export([executed(1, ['false']), executed(2, ['missing'], pid=12,
                     syscall_success=False, syscall_return=-2)])
        first, second = self.packet['context']
        self.assertIsNone(first['rc'])
        self.assertIsNone(second['rc'])
        self.assertEqual(second['exec_sysrc'], -2)

    def test_failed_exec_is_retained_when_command_text_matches(self):
        self.export([shell(1, command='missing'),
                     executed(1.1, ['missing'], syscall_success=False, syscall_return=-2),
                     shell(2, command='missing', phase='finish', rc=127)])
        row, = self.packet['actions']
        self.assertEqual(row['rc'], 127)
        self.assertEqual(row['exec'], [{'argv': ['missing'], 'sysrc': -2}])

    def test_repeated_successful_commands_remain_separate(self):
        events = []
        for index in range(3):
            events += [shell(index * 3 + 1, command='curl http://localhost', command_id=str(index)),
                       shell(index * 3 + 2, command='curl http://localhost', command_id=str(index),
                             phase='finish', rc=0)]
        self.export(events)
        self.assertEqual(len(self.packet['actions']), 3)
        self.assertTrue(all(a['rc'] == 0 for a in self.packet['actions']))

    def test_parallel_shells_use_pid_and_session_identity(self):
        other = {**ACTOR, 'session_id': 4}
        self.export([shell(1, command='one'), shell(1.1, command='two', command_id='two',
                     shell_pid=20, actor=other),
                     executed(1.2, ['one'], pid=11),
                     executed(1.3, ['two'], pid=21, ppid=20, actor=other),
                     file_event(1.4, path='/one', pid=31, ppid=11),
                     file_event(1.5, path='/two', pid=41, ppid=21, actor=other),
                     file_event(1.6, path='/unknown', pid=91, ppid=90),
                     shell(2, command='one', phase='finish', rc=0),
                     shell(2.1, command='two', command_id='two', shell_pid=20,
                           actor=other, phase='finish', rc=1)])
        first, second = self.packet['actions']
        unknown, = self.packet['context']
        self.assertEqual(first['effects'][0]['p'], '/one')
        self.assertEqual(second['effects'][0]['p'], '/two')
        self.assertNotEqual(first['s'], second['s'])
        self.assertEqual(unknown['via'], 'effect')
        self.assertEqual(self.packet['coverage']['unattributed_effects'], 1)

    def test_background_effect_after_finish_is_not_attributed_to_foreground(self):
        self.export([shell(1, command='sleep 1 &'), executed(1.1, ['sleep', '1']),
                     shell(1.2, command='sleep 1 &', phase='finish', rc=0),
                     file_event(2)])
        foreground, = self.packet['actions']
        background, = self.packet['context']
        self.assertNotIn('effects', foreground)
        self.assertEqual(background['via'], 'effect')

    def test_pid_reuse_creates_a_new_unknown_status_action(self):
        self.export([executed(1, ['one'], ppid=99), executed(2, ['two'], ppid=99)])
        self.assertEqual([a['cmd'] for a in self.packet['context']], ['one', 'two'])
        self.assertTrue(all(a['rc'] is None for a in self.packet['context']))
        self.assertEqual(self.packet['actions'], [])

    def test_cd_and_unfinished_commands_preserve_unknowns(self):
        self.export([shell(1, command='cd /tmp'),
                     shell(2, command='cd /tmp', phase='finish', cwd='/tmp', rc=0),
                     shell(3, command='exit', command_id='exit', cwd='/tmp'),
                     shell(4, command='orphan', command_id='orphan', phase='finish', rc=1)])
        cd, exiting, orphan = self.packet['actions']
        self.assertEqual(cd['cwd_after'], '/tmp')
        self.assertIsNone(exiting['rc'])
        self.assertTrue(orphan['missing_start'])
        self.assertNotIn('dt', orphan)

    def test_pipeline_and_expanded_arguments_remain_observable(self):
        command = 'll | head -n 2'
        self.export([shell(1, command=command),
                     executed(1.1, ['ls', '-al']), executed(1.2, ['head', '-n', '2'], pid=12),
                     shell(2, command=command, phase='finish', rc=0)])
        row, = self.packet['actions']
        self.assertEqual(row['cmd'], command)
        self.assertEqual(row['exec'], [{'argv': ['ls', '-al']}])

    def test_unicode_and_newlines_are_preserved_as_utf8(self):
        command = "printf 'привет\nмир'"
        result = self.export([shell(1, command=command)])
        raw = Path(result['llm']).read_text(encoding='utf-8')
        self.assertIn('привет', raw)
        self.assertNotIn('\\u043f', raw)
        self.assertEqual(self.packet['actions'][0]['cmd'], command)

    def test_known_secrets_are_removed_from_packet_but_source_is_untouched(self):
        command = ('API_TOKEN=envsecret curl --password "flag secret" '
                   '-H "Authorization: Bearer headersecret" https://user:urlsecret@example.org')
        self.export([shell(1, command=command),
                     executed(1.1, ['wrapper', '--token', 'argvsecret']),
                     event(2, source='control', kind='marker', label='--secret notesecret')])
        raw = json.dumps(self.packet)
        for secret in ('envsecret', 'flag secret', 'headersecret', 'urlsecret', 'argvsecret',
                       'notesecret'):
            self.assertNotIn(secret, raw)
        original = self.source.read_text(encoding='utf-8')
        self.assertIn('envsecret', original)
        self.assertIn('argvsecret', original)

    def test_file_sequence_and_adjacent_repeat_counts_are_retained(self):
        self.export([shell(1), file_event(1.1), file_event(1.2),
                     file_event(1.3, syscall='unlink'), file_event(1.4),
                     shell(2, phase='finish', rc=0)])
        effects = self.packet['actions'][0]['effects']
        self.assertEqual([d['op'] for d in effects], ['write_open', 'unlink', 'write_open'])
        self.assertEqual(effects[0]['n'], 2)

    def test_detail_budget_is_explicit_and_keeps_failures(self):
        events = [shell(1), *[file_event(1 + i / 10, path=f'/tmp/{i}') for i in range(1, 5)],
                  file_event(1.6, syscall='unlink', syscall_success=False, syscall_return=-13),
                  shell(2, phase='finish', rc=1)]
        result = self.export(events, effects_limit=1, exec_limit=0)
        row, = self.packet['actions']
        self.assertEqual(row['effects'][0]['sysrc'], -13)
        self.assertEqual(row['effects_omitted'], 4)
        self.assertEqual(result['omitted_details'], 4)
        self.assertEqual(len(self.refs['actions']['1']), len(events))

    def test_connect_in_progress_is_a_syscall_return_not_command_failure(self):
        self.export([shell(1, command='curl url'), event(1.2, kind='connect',
                     syscall='connect', syscall_success=False, syscall_return=-115,
                     socket_addresses=['inet host:80']),
                     shell(2, command='curl url', phase='finish', rc=0)])
        row, = self.packet['actions']
        self.assertEqual(row['rc'], 0)
        self.assertEqual(row['effects'][0]['sysrc'], -115)

    def test_noise_is_removed_but_security_signals_and_user_notes_are_kept(self):
        self.export([event(1, source='control', kind='marker', label='recording_started'),
                     event(2, source='control', kind='marker', label='checkpoint'),
                     event(3, kind='authentication'),
                     event(4, kind='audit', details=[{'type': 'AVC', 'fields': {'denied': 'write'}}]),
                     executed(5, ['internal'], origin='instrumentation')])
        self.assertEqual([a['via'] for a in self.packet['actions']], ['note', 'system'])

    def test_collector_noise_and_successful_terminal_opens_are_removed(self):
        logger = file_event(1)
        logger['process'].update(name='incident-audit', executable='/usr/bin/python3.12')
        result = self.export([logger, file_event(2, path='/dev/null'),
                              file_event(3, path='/dev/tty', syscall_success=False,
                                         syscall_return=-6),
                              file_event(4, syscall='unlink', path='/dev/null')])
        self.assertEqual(len(self.packet['context']), 2)
        self.assertEqual(result['discarded']['instrumentation'], 1)
        self.assertEqual(result['discarded']['terminal_device_opens'], 1)
        self.assertEqual(self.packet['context'][0]['effects'][0]['sysrc'], -6)

    def test_ssh_startup_and_separate_stop_connection_are_not_user_actions(self):
        other = {**ACTOR, 'session_id': 4}
        ssh = event(.1, kind='connect', process={'pid': 9, 'ppid': 1,
                    'name': 'sshd', 'executable': '/usr/sbin/sshd'})
        control_ssh = event(5, kind='connect', actor=other, process={'pid': 90, 'ppid': 1,
                            'name': 'sshd', 'executable': '/usr/sbin/sshd'})
        events = [ssh, executed(.2, ['run-parts', '/etc/update-motd.d'], ppid=9),
                  file_event(.3, path='/run/motd.dynamic.new'),
                  shell(1, command='curl url'), shell(2, command='curl url', phase='finish', rc=7),
                  shell(3, command='ls -al', command_id='two'),
                  shell(4, command='ls -al', command_id='two', phase='finish', rc=0),
                  control_ssh, executed(5.1, ['run-parts', '/etc/update-motd.d'], actor=other),
                  executed(5.2, ['bash', '-c', 'incident-audit stop --session-id attempt-001'],
                           actor=other)]
        result = self.export(events)
        self.assertEqual([a['cmd'] for a in self.packet['actions']], ['curl url', 'ls -al'])
        self.assertEqual(self.packet['context'], [])
        self.assertEqual(result['discarded']['ssh_initialization'], 3)
        self.assertEqual(result['discarded']['control_connection'], 3)
        self.assertEqual(self.packet['coverage']['user_commands'], 2)

    def test_explicit_user_motd_command_is_preserved(self):
        self.export([shell(1, command='run-parts /etc/update-motd.d'),
                     executed(1.1, ['run-parts', '/etc/update-motd.d']),
                     shell(2, command='run-parts /etc/update-motd.d', phase='finish', rc=0)])
        row, = self.packet['actions']
        self.assertEqual(row['cmd'], 'run-parts /etc/update-motd.d')

    def test_remote_command_without_bash_hook_is_context_not_deleted(self):
        self.export([executed(1, ['curl', 'url'])])
        self.assertEqual(self.packet['actions'], [])
        self.assertEqual(self.packet['context'][0]['cmd'], 'curl url')

    def test_unrelated_sshd_transport_is_discarded_but_user_sshd_command_survives(self):
        automatic = event(.1, kind='connect', actor={**ACTOR, 'session_id': 9},
                          process={'pid': 99, 'ppid': 1,
                          'executable': '/usr/sbin/sshd'})
        explicit = executed(1.1, ['/usr/sbin/sshd', '-t'])
        explicit['process']['executable'] = '/usr/sbin/sshd'
        result = self.export([automatic, shell(1, command='sshd -t'), explicit,
                              shell(2, command='sshd -t', phase='finish', rc=0)])
        self.assertEqual([a['cmd'] for a in self.packet['actions']], ['sshd -t'])
        self.assertEqual(result['discarded']['ssh_transport'], 1)

    def test_compound_remote_script_is_not_misclassified_as_control_connection(self):
        ssh = event(.1, kind='connect', process={'executable': '/usr/sbin/sshd'})
        self.export([ssh, executed(1, ['bash', '-c', 'incident-audit status; curl url'])])
        self.assertEqual(len(self.packet['context']), 1)

    def test_explicit_collector_command_is_not_a_repair_step(self):
        result = self.export([shell(1, command='incident-audit status')])
        self.assertEqual(self.packet['actions'], [])
        self.assertEqual(result['discarded']['instrumentation'], 1)

    def test_budget_failure_does_not_publish_or_replace_existing_packet(self):
        self.export([shell(1)])
        destination = self.source.with_name('llm.json')
        previous = destination.read_bytes()
        source_bytes = self.source.read_bytes()
        with self.assertRaisesRegex(ValueError, 'no commands were silently dropped'):
            compact_file(self.source, max_bytes=1)
        self.assertEqual(destination.read_bytes(), previous)
        self.assertEqual(self.source.read_bytes(), source_bytes)

    def test_source_and_manifest_cannot_be_overwritten(self):
        self.export([shell(1)])
        for path in (self.source, self.manifest_path):
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, 'overwrite'):
                compact_file(self.source, output=path)

    def test_mixed_session_or_active_recording_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'another recording window'):
            self.export([event(1, capture_session_id='other')])
        self.manifest['capture']['phase'] = 'recording'
        with self.assertRaisesRegex(ValueError, 'stopped recording'):
            self.export([shell(1)])

    def test_provenance_is_bound_to_the_full_source(self):
        result = self.export([shell(1), shell(2, phase='finish', rc=0)])
        self.assertEqual(self.refs['sha256'], hashlib.sha256(self.source.read_bytes()).hexdigest())
        self.assertEqual(self.refs['actions']['1'], ['event-1', 'event-2'])
        self.assertEqual(json.loads(Path(result['llm_stats']).read_text())['input_events'], 2)


if __name__ == '__main__':
    unittest.main()
