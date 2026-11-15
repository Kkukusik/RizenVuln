import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('env_tools', ROOT / 'scripts/env-tools.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class HostsTests(unittest.TestCase):
    def test_idempotent(self):
        base = '127.0.0.1 localhost\n10.20.30.40 other.internal\n'
        out = module.managed_hosts(base, 'storage.internal', '10.20.30.50')
        self.assertEqual(out, module.managed_hosts(out, 'storage.internal', '10.20.30.50'))
        changed = module.managed_hosts(out, 'storage.internal', '10.20.30.51')
        self.assertIn('10.20.30.40 other.internal', changed)
        self.assertNotIn('10.20.30.50', changed)
        self.assertEqual(changed.count(module.MARKER), 1)
    def test_unmanaged_conflict(self):
        with self.assertRaises(ValueError):
            module.managed_hosts('10.0.0.2 storage.internal\n', 'storage.internal', '10.0.0.3')
    def test_no_duplicate_unmanaged(self):
        base = '10.0.0.2 storage.internal\n'
        self.assertEqual(module.managed_hosts(base, 'storage.internal', '10.0.0.2'), base)
    def test_validation(self):
        for hostname, ip in [('bad host', '10.0.0.1'), ('-bad.internal', '10.0.0.1'), ('s.internal','999.1.1.1'),('s.internal','127.0.0.1'),('s.internal','169.254.169.254')]:
            with self.assertRaises(ValueError):
                module.validate(hostname, ip)
        self.assertEqual(module.validate('S3.Internal', '10.0.0.2'), ('s3.internal','10.0.0.2'))
    def test_backups_and_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            hosts = Path(directory)/'hosts'
            hosts.write_text('127.0.0.1 localhost\n')
            args = ['python3',str(ROOT/'scripts/env-tools.py'),'hosts','--env',str(Path(directory)/'none'),'--hostname','storage.internal','--ip','10.0.0.2','--hosts-file',str(hosts)]
            subprocess.run(args, cwd=ROOT, check=True, capture_output=True)
            self.assertEqual(hosts.stat().st_mode & 0o777, 0o644)
            self.assertEqual(len(list(Path(directory).glob('*.bak'))),1)
            subprocess.run(args, cwd=ROOT, check=True, capture_output=True)
            self.assertEqual(len(list(Path(directory).glob('*.bak'))),1)
    def test_missing_config_no_write(self):
        with tempfile.TemporaryDirectory() as directory:
            hosts=Path(directory)/'hosts';hosts.write_text('unchanged\n')
            subprocess.run(['python3',str(ROOT/'scripts/env-tools.py'),'hosts','--env',str(Path(directory)/'absent'),'--hosts-file',str(hosts)],cwd=ROOT,check=True,capture_output=True)
            self.assertEqual(hosts.read_text(),'unchanged\n')
    def test_init_exclusive_secret_file(self):
        with tempfile.TemporaryDirectory() as directory:
            target=Path(directory)/'.env'
            args=['python3',str(ROOT/'scripts/env-tools.py'),'init','--email','operator@example.test','--env',str(target)]
            result=subprocess.run(args,cwd=ROOT,check=True,capture_output=True,text=True)
            env=module.read_env(target)
            self.assertEqual(target.stat().st_mode & 0o777,0o600)
            self.assertGreaterEqual(len(env['ADMIN_PASSWORD']),32)
            self.assertNotIn(env['ADMIN_PASSWORD'],result.stdout)
            self.assertNotEqual(subprocess.run(args,cwd=ROOT,capture_output=True).returncode,0)

if __name__ == '__main__': unittest.main()
