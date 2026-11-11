#!/usr/bin/env python3
"""Analyze a compact recording on the evaluator host using a configurable LLM."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
import urllib.error
import urllib.parse
import urllib.request

from incident_audit_compact import atomic_text, dumps


class AnalysisError(RuntimeError):
    pass


def load_settings(path, profile=None):
    path = Path(path).resolve()
    config = json.loads(path.read_text(encoding='utf-8'))
    name = profile or config['active_profile']
    if name not in config['profiles']:
        raise AnalysisError('unknown LLM profile')
    provider = config['profiles'][name]
    if provider.get('adapter') != 'chat_completions':
        raise AnalysisError('unsupported adapter; supported: chat_completions')
    base = urllib.parse.urlsplit(provider['base_url'])
    if (base.username or base.password or base.query or base.fragment or not base.hostname or
            (base.scheme != 'https' and not
             (base.scheme == 'http' and base.hostname in ('localhost', '127.0.0.1', '::1')))):
        raise AnalysisError('base_url must be HTTPS without credentials/query; HTTP is allowed only on loopback')
    for field in ('max_request_bytes', 'max_response_bytes'):
        if not isinstance(config[field], int) or config[field] <= 0:
            raise AnalysisError(field + ' must be a positive integer')
    if not isinstance(provider['model'], str) or not provider['model'].strip():
        raise AnalysisError('model must be a nonempty string')
    if not isinstance(provider['timeout_seconds'], (int, float)) or provider['timeout_seconds'] <= 0:
        raise AnalysisError('timeout_seconds must be positive')
    return path.parent, config, name, provider


def build_request(folder, config, provider, packet_path, task_path, validation_path=None):
    packet_bytes = Path(packet_path).read_bytes()
    packet = json.loads(packet_bytes)
    if (packet.get('v') != 1 or not isinstance(packet.get('actions'), list) or
            not isinstance(packet.get('session'), str) or not packet['session']):
        raise AnalysisError('input must be a compact llm.json packet, version 1')
    task = Path(task_path).read_text(encoding='utf-8').strip()
    if not task:
        raise AnalysisError('task description is empty')
    validation = (Path(validation_path).read_text(encoding='utf-8')
                  if validation_path else 'Результат валидации не предоставлен.')
    prompt = (folder / config['prompt_file']).read_text(encoding='utf-8')
    parameters = provider.get('parameters', {})
    if not isinstance(parameters, dict) or set(parameters) & {'model', 'messages', 'stream'}:
        raise AnalysisError('parameters must be an object without model/messages/stream overrides')
    request = {**parameters, 'model': provider['model'], 'stream': False,
               'messages': [{'role': 'system', 'content': prompt},
                            {'role': 'user', 'content': dumps(
                                {'task': task, 'validation': validation, 'recording': packet})}]}
    body = dumps(request).encode('utf-8')
    if len(body) > config['max_request_bytes']:
        raise AnalysisError('request exceeds max_request_bytes; no actions were truncated or sent')
    return body, packet['session'], hashlib.sha256(packet_bytes).hexdigest()


def api_key(folder, provider):
    key = os.environ.get(provider.get('api_key_env', ''), '').strip()
    if not key and provider.get('api_key_file'):
        path = folder / provider['api_key_file']
        if path.is_file():
            key = path.read_text(encoding='utf-8-sig').strip()
    if not key:
        raise AnalysisError('API key is missing; set api_key_env or create api_key_file from the selected profile')
    if any(c.isspace() for c in key):
        raise AnalysisError('API key must be one token without whitespace')
    return key


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def chat_completions(provider, body, key, response_limit):
    endpoint = provider['base_url'].rstrip('/') + '/chat/completions'
    request = urllib.request.Request(endpoint, data=body, method='POST', headers={
        'Content-Type': 'application/json', 'Authorization': 'Bearer ' + key})
    opener = urllib.request.build_opener(NoRedirect())
    try:
        with opener.open(request, timeout=provider['timeout_seconds']) as response:
            raw = response.read(response_limit + 1)
    except urllib.error.HTTPError as error:
        # Never echo provider bodies, headers, keys, or submitted commands into diagnostics.
        error.close()
        hints = {401: 'check API key', 402: 'check provider balance',
                 429: 'provider rate limit; retry later', 400: 'check model and parameters'}
        raise AnalysisError(f'LLM HTTP {error.code}: ' + hints.get(error.code, 'provider request failed')) from None
    except (urllib.error.URLError, TimeoutError, OSError):
        raise AnalysisError('LLM connection failed or timed out; no automatic retry was made') from None
    if len(raw) > response_limit:
        raise AnalysisError('LLM response exceeds max_response_bytes')
    try:
        result = json.loads(raw)
        choice = result['choices'][0]
        content = choice['message']['content']
        finish = choice['finish_reason']
        if not isinstance(content, str) or not content.strip():
            raise ValueError()
        if finish != 'stop':
            raise AnalysisError('LLM response is incomplete or blocked (finish_reason is not stop); no report published')
        return content, result.get('usage'), result.get('model', provider['model']), result.get('id')
    except (ValueError, KeyError, IndexError, TypeError):
        raise AnalysisError('invalid LLM response or missing answer text') from None


def analyze(config_path, packet_path, task_path, output=None, validation_path=None,
            profile=None, dry_run=False):
    folder, config, name, provider = load_settings(config_path, profile)
    body, session, source_hash = build_request(folder, config, provider, packet_path,
                                                task_path, validation_path)
    summary = {'profile': name, 'model': provider['model'], 'session': session,
               'request_bytes': len(body), 'dry_run': dry_run}
    if dry_run:
        return summary
    if output is None:
        raise AnalysisError('output directory is required')
    destination = Path(output)
    # Each invocation is a paid request. Require a fresh destination to avoid accidental reruns.
    destination.mkdir(parents=True, mode=0o700, exist_ok=False)
    try:
        key = api_key(folder, provider)
        content, usage, model, response_id = chat_completions(
            provider, body, key, config['max_response_bytes'])
        report = {'v': 1, 'session': session, 'profile': name, 'model': model,
                  'base_url': provider['base_url'], 'response_id': response_id,
                  'created_at': datetime.now(timezone.utc).isoformat(),
                  'packet_sha256': source_hash, 'request_sha256': hashlib.sha256(body).hexdigest(),
                  'usage': usage, 'analysis': content}
        atomic_text(destination / 'analysis.json', dumps(report) + '\n')
        atomic_text(destination / 'analysis.md', content + '\n')
    except Exception:
        # Remove only this invocation's empty directory; preserve any published artifacts.
        if not any(destination.iterdir()):
            destination.rmdir()
        raise
    return {**summary, 'usage': usage, 'output': str(destination / 'analysis.md')}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path,
                        default=Path(__file__).resolve().parents[1] / 'config/llm.local.json')
    parser.add_argument('--profile')
    parser.add_argument('--input', required=True, type=Path)
    parser.add_argument('--task', required=True, type=Path)
    parser.add_argument('--validation', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args()
    print(dumps(analyze(args.config, args.input, args.task, args.output, args.validation,
                       args.profile, args.dry_run)))


if __name__ == '__main__':
    try:
        main()
    except (AnalysisError, OSError, ValueError, KeyError, TypeError) as error:
        # Validation errors are local; network errors have already been sanitized above.
        print('analysis: ' + str(error), file=sys.stderr)
        sys.exit(1)
