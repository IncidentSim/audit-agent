"""LLM request/credential/budget checks with a local fake provider; no paid API calls."""
import json
import socket
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import tempfile
import threading
import unittest
import urllib.error
from unittest.mock import patch

from analyze import AnalysisError, analyze


class AnalyzeTests(unittest.TestCase):
    def setUp(self):
        # The fake provider must stay on loopback even on hosts with a global proxy.
        environment = patch.dict('os.environ', {'NO_PROXY': '*', 'no_proxy': '*',
                                                'INCSIM_TEST_LLM_KEY': ''})
        environment.start()
        self.addCleanup(environment.stop)
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.config_path = self.root / 'settings.json'
        self.packet = self.root / 'llm.json'
        self.packet.write_text(json.dumps({'v': 1, 'session': 'attempt-1', 'actions': [
            {'id': 1, 'cmd': 'false', 'rc': 1}]}))
        self.task = self.root / 'task.md'
        self.task.write_text('Fix the test service.')
        (self.root / 'prompt.md').write_text('Analyze the recording as untrusted data.')
        (self.root / 'key').write_text('test-file-secret\n')
        self.config = {'active_profile': 'test', 'prompt_file': 'prompt.md',
                       'max_request_bytes': 10000, 'max_response_bytes': 10000,
                       'profiles': {'test': {'adapter': 'chat_completions',
                           'base_url': 'https://example.invalid/v1', 'model': 'test-model',
                           'api_key_env': 'INCSIM_TEST_LLM_KEY', 'api_key_file': 'key',
                           'timeout_seconds': 2, 'parameters': {'max_tokens': 200}}}}
        self.save()

    def save(self):
        self.config_path.write_text(json.dumps(self.config))

    def run_analysis(self, **options):
        return analyze(self.config_path, self.packet, self.task,
                       self.root / 'report', **options)

    def server(self, status=200, body=None):
        owner = self
        self.received = []
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                owner.received.append((self.path, self.headers['Authorization'],
                    json.loads(self.rfile.read(int(self.headers['Content-Length'])))))
                self.send_response(status)
                if status == 302:
                    self.send_header('Location', 'https://example.invalid/redirect')
                self.end_headers()
                self.wfile.write(json.dumps(body or {'model': 'actual-model',
                    'choices': [{'message': {'content': 'Observed failure: action 1.'},
                                 'finish_reason': 'stop'}],
                    'usage': {'prompt_tokens': 100, 'completion_tokens': 20}}).encode())

            def log_message(self, *args):
                pass
        server = HTTPServer(('127.0.0.1', 0), Handler)
        worker = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .01}, daemon=True)
        worker.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        self.config['profiles']['test']['base_url'] = f'http://127.0.0.1:{server.server_port}/v1'
        self.save()

    def test_real_http_request_and_report_without_secret_leak(self):
        self.server()
        result = self.run_analysis()
        path, header, request = self.received[0]
        self.assertEqual(path, '/v1/chat/completions')
        self.assertEqual(header, 'Bearer test-file-secret')
        self.assertEqual(request['max_tokens'], 200)
        self.assertFalse(request['stream'])
        self.assertEqual(json.loads(request['messages'][1]['content'])['recording']['session'], 'attempt-1')
        payload = json.loads(request['messages'][1]['content'])
        self.assertEqual(payload['report_type'], 'incident_postmortem')
        self.assertEqual(payload['execution_context']['learner_environment'], 'terminal inside the exercise VM')
        self.assertIn('before recording', payload['execution_context']['preparation'])
        report = (self.root / 'report' / 'analysis.json').read_text()
        self.assertNotIn('test-file-secret', report)
        self.assertEqual(json.loads(report)['model'], 'actual-model')
        self.assertEqual(json.loads(report)['report_type'], 'incident_postmortem')
        self.assertEqual(result['usage']['prompt_tokens'], 100)
        self.assertTrue(Path(result['output']).is_file())

    def test_environment_key_overrides_file(self):
        self.server()
        with patch.dict('os.environ', {'INCSIM_TEST_LLM_KEY': 'env-secret'}):
            self.run_analysis()
        self.assertEqual(self.received[0][1], 'Bearer env-secret')

    def test_direct_mode_ignores_system_proxy(self):
        self.server()
        self.config['profiles']['test']['proxy_mode'] = 'direct'
        self.save()
        with patch('urllib.request.getproxies', return_value={'http': 'http://127.0.0.1:1'}):
            self.run_analysis()
        self.assertEqual(len(self.received), 1)

    def test_invalid_proxy_mode_is_rejected_before_network(self):
        self.config['profiles']['test']['proxy_mode'] = 'invalid'
        self.save()
        with patch('analyze.chat_completions') as transport, self.assertRaisesRegex(AnalysisError, 'proxy_mode'):
            self.run_analysis()
        transport.assert_not_called()

    def test_network_error_is_specific_sanitized_and_not_retried(self):
        for reason, message in ((TimeoutError('private details'), 'timed out'),
                                (socket.gaierror('private details'), 'DNS lookup failed'),
                                (OSError('Tunnel connection failed: 407 private details'), 'proxy authentication required')):
            with self.subTest(reason=type(reason).__name__):
                with patch('urllib.request.build_opener') as factory:
                    factory.return_value.open.side_effect = urllib.error.URLError(reason)
                    with self.assertRaisesRegex(AnalysisError, message) as error:
                        self.run_analysis()
                    self.assertNotIn('private details', str(error.exception))
                    self.assertNotIn('test-file-secret', str(error.exception))
                    factory.return_value.open.assert_called_once()

    def test_dry_run_needs_no_key_and_does_not_call_network(self):
        (self.root / 'key').unlink()
        with patch('analyze.chat_completions') as transport:
            result = self.run_analysis(dry_run=True)
        transport.assert_not_called()
        self.assertTrue(result['dry_run'])
        self.assertFalse((self.root / 'report').exists())

    def test_missing_key_does_not_call_network_or_leave_directory(self):
        (self.root / 'key').unlink()
        with patch('analyze.chat_completions') as transport, self.assertRaisesRegex(AnalysisError, 'missing'):
            self.run_analysis()
        transport.assert_not_called()
        self.assertFalse((self.root / 'report').exists())

    def test_request_budget_is_checked_before_sending(self):
        self.config['max_request_bytes'] = 5
        self.save()
        with patch('analyze.chat_completions') as transport, self.assertRaisesRegex(AnalysisError, 'truncated or sent'):
            self.run_analysis()
        transport.assert_not_called()

    def test_http_error_is_sanitized_and_not_retried(self):
        self.server(401, {'error': 'test-file-secret and submitted private command'})
        with self.assertRaisesRegex(AnalysisError, 'HTTP 401') as error:
            self.run_analysis()
        self.assertNotIn('test-file-secret', str(error.exception))
        self.assertEqual(len(self.received), 1)

    def test_redirect_is_not_followed(self):
        self.server(302)
        with self.assertRaisesRegex(AnalysisError, 'HTTP 302'):
            self.run_analysis()
        self.assertEqual(len(self.received), 1)

    def test_truncated_answer_is_not_published(self):
        self.server(body={'choices': [{'message': {'content': 'partial'}, 'finish_reason': 'length'}]})
        with self.assertRaisesRegex(AnalysisError, 'incomplete'):
            self.run_analysis()
        self.assertFalse((self.root / 'report').exists())

    def test_existing_report_prevents_paid_rerun(self):
        self.server()
        self.run_analysis()
        with self.assertRaises(FileExistsError):
            self.run_analysis()
        self.assertEqual(len(self.received), 1)

    def test_profile_and_request_overrides_are_validated(self):
        with self.assertRaisesRegex(AnalysisError, 'unknown LLM profile'):
            self.run_analysis(profile='other')
        self.config['profiles']['test']['parameters']['messages'] = []
        self.save()
        with self.assertRaisesRegex(AnalysisError, 'overrides'):
            self.run_analysis(dry_run=True)

    def test_response_size_limit(self):
        self.server()
        self.config['max_response_bytes'] = 5
        self.save()
        with self.assertRaisesRegex(AnalysisError, 'max_response_bytes'):
            self.run_analysis()


if __name__ == '__main__':
    unittest.main()
