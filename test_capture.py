"""Capture lifecycle, retries and boundary selection without a real audit daemon."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import incident_audit_capture as capture

START = {'serial': 100, 'timestamp': '2026-11-11T10:00:00.123+00:00', 'boot_id': 'test'}
END = {**START, 'serial': 200, 'timestamp': '2026-11-11T10:01:00.123+00:00'}


def event(serial=150, source='auditd', timestamp=None):
    return {'event_id': f'vm:audit:1.123:{serial}', 'vm_id': 'vm', 'source': source,
            'audit_serial': serial, 'timestamp': timestamp or START['timestamp']}


class CaptureTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.events = []
        self.store = capture.CaptureStore(self.root, lambda e, path: self.events.append(e))
        self.boundary = Mock(return_value=START)
        self.finalize = Mock(return_value={'output': '/test/actions.jsonl', 'events': 3})

    def tearDown(self):
        self.temporary.cleanup()

    def start(self, identifier='trial'):
        return self.store.start(identifier, 'vm', self.boundary)

    def stop(self, identifier='trial'):
        return self.store.stop(identifier, lambda: END, self.finalize)

    def test_idle_does_not_record(self):
        self.assertFalse(self.store.record(event()))
        self.assertFalse(list(self.root.rglob('events.jsonl')))

    def test_start_retry_preserves_original_boundary(self):
        original = self.start()
        self.assertEqual(self.start(), original)
        self.assertEqual(self.boundary.call_count, 1)
        self.assertEqual(original['phase'], 'recording')

    def test_overlapping_start_is_rejected(self):
        self.start()
        with self.assertRaisesRegex(RuntimeError, 'already active'):
            self.start('other')
        self.assertEqual(self.store.current()['session_id'], 'trial')

    def test_same_millisecond_events_are_selected_by_audit_serial(self):
        self.start()
        self.assertFalse(self.store.record(event(99)))
        self.assertFalse(self.store.record(event(100)))
        self.assertTrue(self.store.record(event(101)))
        self.assertEqual(self.events[-1]['capture_session_id'], 'trial')
        window = {**self.store.current(), 'stop_boundary': {**START, 'serial': 200}}
        self.assertTrue(capture.in_window(event(199), window))
        self.assertFalse(capture.in_window(event(200), window))
        self.assertFalse(capture.in_window(event(201), window))

    def test_wrong_stop_does_not_close_active_recording(self):
        self.start()
        with self.assertRaises(RuntimeError):
            self.stop('other')
        self.assertEqual(self.store.current()['phase'], 'recording')
        self.assertTrue(self.store.record(event()))

    def test_stop_is_idempotent_and_events_after_stop_are_ignored(self):
        self.start()
        sealed = self.stop()
        self.assertEqual(self.stop(), sealed)
        self.assertEqual(self.finalize.call_count, 1)
        self.assertFalse(self.store.record(event(151)))
        self.assertFalse(self.store.record(event(source='bash')))
        self.assertEqual(sealed['stop_boundary'], END)
        self.assertEqual(sealed['phase'], 'stopped')

    def test_export_failure_retry_keeps_original_cutoff(self):
        self.start()
        stop_boundary = Mock(return_value=END)
        failed = Mock(side_effect=RuntimeError('temporary export error'))
        with self.assertRaisesRegex(RuntimeError, 'temporary'):
            self.store.stop('trial', stop_boundary, failed)
        self.assertEqual(self.store.current()['phase'], 'stopping')
        self.assertFalse(self.store.record(event(source='bash')))
        self.store.stop('trial', stop_boundary, self.finalize)
        self.assertEqual(stop_boundary.call_count, 1)
        self.assertEqual(self.store.current()['stop_boundary'], END)

    def test_only_delayed_audit_events_inside_the_window_drain_while_stopping(self):
        self.start()

        def finalize(window):
            self.assertTrue(self.store.record(event(199)))
            self.assertFalse(self.store.record(event(200)))
            self.assertFalse(self.store.record(event(201)))
            self.assertFalse(self.store.record(event(source='bash')))
            return {'output': 'test'}

        self.store.stop('trial', lambda: END, finalize)

    def test_closed_session_cannot_be_reused_or_stop_a_new_session(self):
        self.start()
        old = self.stop()
        with self.assertRaisesRegex(RuntimeError, 'already been used'):
            self.start()
        self.start('second')
        with self.assertRaisesRegex(RuntimeError, 'another session is active'):
            self.stop()
        self.assertEqual(self.store.get('trial'), old)
        self.assertEqual(self.store.current()['session_id'], 'second')
        self.assertEqual(self.store.current()['phase'], 'recording')

    def test_state_survives_new_store_instance(self):
        self.start()
        sealed = self.stop()
        new = capture.CaptureStore(self.root, lambda *_: None)
        self.assertEqual(new.get('trial'), sealed)
        self.assertEqual(json.loads((self.root / 'sessions/trial/session.json').read_text()),
                         sealed)

    def test_session_id_cannot_escape_the_storage_directory(self):
        for value in ('../other', '/etc', '.', '..', 'a/b', 'with space', ''):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.start(value)
        self.assertFalse((self.root / 'capture.json').exists())

    def test_reboot_is_not_silently_mixed_into_the_same_window(self):
        self.start()
        with patch.object(capture, 'boot_id', return_value='different-boot'):
            self.assertFalse(self.store.record(event()))
            with self.assertRaisesRegex(RuntimeError, 'rebooted'):
                self.start()
            with self.assertRaisesRegex(RuntimeError, 'rebooted'):
                self.stop()
