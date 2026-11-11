"""Behavioral checks against the real libauparse supplied by python3-audit."""
import importlib.util
import json
import multiprocessing
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location(
    'incident_audit', Path(__file__).with_name('incident-audit.py'))
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)


def event_records(serial=42, result=0):
    stamp = f'msg=audit(1730000000.123:{serial}):'
    return (
        f'type=SYSCALL {stamp} arch=c000003e syscall=59 success=yes exit={result} '
        'a0=0 a1=0 a2=0 a3=0 items=1 ppid=10 pid=11 auid=0 uid=0 gid=0 '
        'euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 '
        'comm="printf" exe="/usr/bin/printf" key="incsim_exec"\n'
        f'type=EXECVE {stamp} argc=4 a0="/usr/bin/printf" a1=25730A '
        'a2=74776F20776F726473 a3=D0BFD180D0B8D0B2D0B5D182\n'
        f'type=CWD {stamp} cwd="/tmp"\n'
        f'type=PATH {stamp} item=0 name="/usr/bin/printf" inode=123 '
        'dev=00:01 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL\n'
        f'type=EOE {stamp}\n'
    )


class AuditTests(unittest.TestCase):
    def parse(self, text):
        parser = agent.auparse.AuParser(agent.auparse.AUSOURCE_BUFFER, text)
        self.assertTrue(parser.parse_next_event())
        return agent.normalize(parser, 'test-vm')

    def test_exec_decodes_arguments_and_preserves_root_identity(self):
        event = self.parse(event_records())
        self.assertEqual(event['process']['argv'],
                         ['/usr/bin/printf', '%s\n', 'two words', 'привет'])
        self.assertEqual(event['process']['cwd'], '/tmp')
        self.assertEqual(event['actor']['login_uid'], 0)
        self.assertEqual(event['actor']['session_id'], 3)
        self.assertEqual(event['kind'], 'exec')
        self.assertEqual(event['syscall'], 'execve')
        self.assertTrue(event['syscall_success'])
        self.assertEqual(event['syscall_return'], 0)
        self.assertNotIn('exit_status', event)
        self.assertEqual(json.loads(agent.encode(event)), event)

    def test_failed_syscall_keeps_negative_return_value(self):
        event = self.parse(event_records(result=-1).replace('success=yes', 'success=no'))
        self.assertFalse(event['syscall_success'])
        self.assertEqual(event['syscall_return'], -1)

    def test_fragmented_long_argument_is_reassembled(self):
        text = event_records().replace(
            'a2=74776F20776F726473', 'a2_len=9 a2[0]=74776F20 a2[1]=776F726473')
        event = self.parse(text)
        self.assertEqual(event['process']['argv'][2], 'two words')

    def test_utf8_character_can_span_argument_fragments(self):
        text = event_records().replace(
            'a3=D0BFD180D0B8D0B2D0B5D182',
            'a3_len=12 a3[0]=D0 a3[1]=BFD180D0B8D0B2D0B5D182')
        self.assertEqual(self.parse(text)['process']['argv'][3], 'привет')

    def test_truncated_proctitle_does_not_drop_complete_exec_arguments(self):
        text = event_records().replace(
            'type=EOE', 'type=PROCTITLE msg=audit(1730000000.123:42): proctitle=2F62696E00D0\n'
            'type=EOE')
        event = self.parse(text)
        self.assertEqual(event['process']['argv'][3], 'привет')
        self.assertEqual(event['decoding_warnings'][0]['field'], 'proctitle')

    def test_boundary_helper_is_identified_as_instrumentation(self):
        text = event_records().replace(
            'argc=4 a0="/usr/bin/printf" a1=25730A '
            'a2=74776F20776F726473 a3=D0BFD180D0B8D0B2D0B5D182',
            'argc=3 a0="auditctl" a1="-m" a2="incsim_boundary=' + 'a' * 32 + '"')
        self.assertEqual(self.parse(text)['origin'], 'instrumentation')

    def test_stream_groups_interleaved_events_without_losing_last_event(self):
        parser = agent.auparse.AuParser(agent.auparse.AUSOURCE_FEED, None)
        events = []

        def ready(au, reason, _):
            if reason == agent.auparse.AUPARSE_CB_EVENT_READY:
                events.append(agent.normalize(au, 'test-vm'))

        parser.add_callback(ready, None)
        first, second = event_records(42).splitlines(True), event_records(43).splitlines(True)
        for one, two in zip(first, second):
            parser.feed(one)
            parser.feed(two)
        parser.flush_feed()
        self.assertEqual(len(events), 2)
        self.assertEqual(len({event['event_id'] for event in events}), 2)
        self.assertTrue(all(event['process']['argv'][2] == 'two words' for event in events))

    def test_concurrent_jsonl_writers_preserve_events_and_newlines(self):
        original = agent.ROOT
        with tempfile.TemporaryDirectory() as directory:
            agent.ROOT = Path(directory)
            try:
                def write(prefix):
                    for index in range(15):
                        agent.append({'event_id': f'{prefix}-{index}', 'command': 'a\nb "c"'})

                workers = [multiprocessing.Process(target=write, args=(index,))
                           for index in range(4)]
                for worker in workers:
                    worker.start()
                for worker in workers:
                    worker.join(10)
                    self.assertEqual(worker.exitcode, 0)
                events = [json.loads(line) for line in
                          (agent.ROOT / 'events.jsonl').read_text().splitlines()]
                self.assertEqual(len(events), 60)
                self.assertEqual(len({e['event_id'] for e in events}), 60)
                self.assertTrue(all(e['command'] == 'a\nb "c"' for e in events))
                self.assertEqual((agent.ROOT / 'events.jsonl').stat().st_mode & 0o777, 0o600)
            finally:
                agent.ROOT = original


if __name__ == '__main__':
    unittest.main()
