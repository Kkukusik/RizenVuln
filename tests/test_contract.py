import json
from pathlib import Path
import re
import unittest
ROOT=Path(__file__).resolve().parents[1]
class ContractTests(unittest.TestCase):
    def test_routes_documented(self):
        source=(ROOT/'apps/api/src/app.rs').read_text()
        routes=set(re.findall(r'\.route\(\s*"([^"]+)"',source))
        expected={p if p.startswith('/health/') or p=='/metrics' else '/api/v1'+p for p in routes}
        documented=set(json.loads((ROOT/'docs/openapi.json').read_text())['paths'])
        self.assertEqual(expected,documented)
    def test_all_required_tables_exist(self):
        sql=(ROOT/'migrations/0001_initial.sql').read_text()
        names=set(re.findall(r'CREATE TABLE ([a-z_]+)',sql))
        self.assertTrue({'users','sessions','projects','integrations','sources','repositories','images','image_versions','deployments','scan_runs','sbom_artifacts','vulnerabilities','vulnerability_findings','vulnerability_status_history','update_recommendations','version_approvals','notification_rules','notifications','jobs','audit_logs'}.issubset(names))
