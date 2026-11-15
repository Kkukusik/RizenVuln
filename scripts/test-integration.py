#!/usr/bin/env python3
"""Run ignored database tests against a disposable, isolated PostgreSQL Compose project."""
import argparse
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import uuid
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]

def browser_tests(env):
    subprocess.run(['npm', 'run', 'build'], cwd=ROOT / 'frontend', check=True)
    build = subprocess.check_output(['cargo', 'build', '--bin', 'rizenvuln-api', '--message-format=json'], cwd=ROOT, text=True)
    executable = next(item['executable'] for line in build.splitlines()
                      if (item := json.loads(line)).get('executable') and item.get('target', {}).get('name') == 'rizenvuln-api')
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        port = listener.getsockname()[1]
    origin = f'http://127.0.0.1:{port}'
    password = secrets.token_hex(24)
    env.update({'DATABASE_URL': env['TEST_DATABASE_URL'], 'APP_HOST': '127.0.0.1', 'APP_PORT': str(port),
                'PUBLIC_BASE_URL': origin, 'APP_ENV': 'development', 'ADMIN_EMAIL': 'admin@example.test',
                'ADMIN_PASSWORD': password, 'SESSION_SECRET': secrets.token_hex(48), 'SCAN_ENABLED': 'false',
                'FRONTEND_DIR': str(ROOT / 'frontend/dist'), 'E2E_BASE_URL': origin, 'E2E_ADMIN_PASSWORD': password})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with tempfile.TemporaryFile() as log:
        api = subprocess.Popen([executable], cwd=ROOT, env=env, stdout=log, stderr=log)
        try:
            for _ in range(100):
                if api.poll() is not None:
                    raise RuntimeError('Test API failed to start')
                try:
                    with opener.open(origin + '/health/ready', timeout=1) as response:
                        if response.status == 200:
                            break
                except OSError:
                    time.sleep(0.1)
            else:
                raise RuntimeError('Test API readiness timeout')
            subprocess.run(['npm', 'run', 'test:e2e'], cwd=ROOT / 'frontend', env=env, check=True)
        finally:
            api.terminate()
            try:
                api.wait(timeout=10)
            except subprocess.TimeoutExpired:
                api.kill()
                api.wait()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--browser', action='store_true', help='also run Playwright against a disposable API')
    args = parser.parse_args()
    project = 'rvtest-' + uuid.uuid4().hex[:12]
    password = secrets.token_hex(24)
    database = 'rvtest_' + uuid.uuid4().hex
    with tempfile.TemporaryDirectory(prefix='rizenvuln-tests-') as directory:
        config = Path(directory) / 'compose.json'
        config.write_text(json.dumps({'services': {'postgres': {
            'image': 'postgres:17-alpine',
            'environment': {'POSTGRES_USER': 'test', 'POSTGRES_PASSWORD': password, 'POSTGRES_DB': database},
            'ports': ['127.0.0.1::5432'],
            'tmpfs': ['/var/lib/postgresql/data'],
            'healthcheck': {'test': ['CMD', 'pg_isready', '-U', 'test', '-d', database], 'interval': '1s', 'timeout': '3s', 'retries': 40},
        }}}))
        config.chmod(0o600)
        compose = ['docker', 'compose', '-f', str(config), '-p', project]
        try:
            subprocess.run(compose + ['up', '-d', '--wait', '--wait-timeout', '60'], check=True, cwd=ROOT)
            published = subprocess.check_output(compose + ['port', 'postgres', '5432'], text=True).strip()
            host, port = published.rsplit(':', 1)
            try:
                with socket.create_connection((host, int(port)), timeout=2):
                    pass
            except OSError:
                # Linux hosts with restricted loopback forwarding can access the test bridge.
                container = subprocess.check_output(compose + ['ps', '-q', 'postgres'], text=True).strip()
                host = subprocess.check_output(['docker', 'inspect', '-f', '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}', container], text=True).strip()
                port = '5432'
                with socket.create_connection((host, int(port)), timeout=2):
                    pass
            env = os.environ.copy()
            # Ignore local service credentials and use deterministic feature flags in child processes.
            for key in list(env):
                if key.endswith('_ENABLED'):
                    env.pop(key)
            env.update({'TEST_DATABASE_URL': f'postgres://test:{password}@{host}:{port}/{database}',
                        'HARBOR_ENABLED': 'false', 'TELEGRAM_ENABLED': 'false', 'S3_ENABLED': 'false',
                        'DOCKER_DISCOVERY_ENABLED': 'false', 'KUBERNETES_ENABLED': 'false',
                        'GITHUB_ENABLED': 'true', 'INTELLIGENCE_ENABLED': 'false', 'METRICS_TOKEN': secrets.token_hex(24)})
            subprocess.run(['cargo', 'test', '-p', 'rizenvuln-api', '-p', 'rizenvuln-database', '-p', 'rizenvuln-worker', '--', '--ignored'], check=True, cwd=ROOT, env=env)
            if args.browser:
                browser_tests(env)
        finally:
            subprocess.run(compose + ['down', '--volumes', '--remove-orphans'], check=True, cwd=ROOT)

if __name__ == '__main__':
    main()
