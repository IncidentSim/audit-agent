"""Provision only a disposable demo VM, verify baseline, then inject a port fault."""
from pathlib import Path
import subprocess
import time
import urllib.request

opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
web = Path('/opt/audit-demo/www')
web.mkdir(parents=True, exist_ok=True)
(web / 'health').write_text('audit-demo-ready\n')
config = Path('/etc/default/audit-demo')
config.write_text('PORT=8080\n')
Path('/etc/systemd/system/audit-demo.service').write_text('''[Unit]
Description=Audit demo HTTP service
After=network.target
[Service]
User=www-data
EnvironmentFile=/etc/default/audit-demo
ExecStart=/usr/bin/python3 -m http.server ${PORT} --bind 0.0.0.0 --directory /opt/audit-demo/www
Restart=on-failure
[Install]
WantedBy=multi-user.target
''')
subprocess.run(['systemctl', 'daemon-reload'], check=True)
subprocess.run(['systemctl', 'enable', 'audit-demo'], check=True)
subprocess.run(['systemctl', 'restart', 'audit-demo'], check=True)

def wait_for(port):
    for _ in range(100):
        try:
            with opener.open(f'http://127.0.0.1:{port}/health', timeout=1) as response:
                assert response.status == 200 and response.read().strip() == b'audit-demo-ready'
            return
        except OSError:
            time.sleep(.2)
    raise RuntimeError('demo service did not become ready')

wait_for(8080)
config.write_text('PORT=8090\n')
subprocess.run(['systemctl', 'restart', 'audit-demo'], check=True)
wait_for(8090)
try:
    opener.open('http://127.0.0.1:8080/health', timeout=1)
except OSError:
    print('PASS: healthy baseline verified; fault injected; port 8080 unavailable')
else:
    raise RuntimeError('fault injection did not break port 8080')
