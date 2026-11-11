"""Executed through SSH after recording stops; checks observable demo behavior."""
import json
import subprocess
import urllib.request

active = subprocess.run(['systemctl', 'is-active', '--quiet', 'audit-demo']).returncode == 0
result = {'service_active': active, 'url': 'http://127.0.0.1:8080/health',
          'http_status': None, 'body_matches': False}
try:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(result['url'], timeout=5) as response:
        result['http_status'] = response.status
        result['body_matches'] = response.read(4096).strip() == b'audit-demo-ready'
except OSError:
    result['error'] = 'HTTP endpoint unavailable'
result['passed'] = active and result['http_status'] == 200 and result['body_matches']
print(json.dumps(result))
