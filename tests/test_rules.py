
import ast
import pytest

from sast.models import FindingsCollection, Severity
from sast.engine import RuleRegistry
from sast.analyzer import Analyzer
from sast.rules.hardcoded_secrets import HardcodedSecretsRule, HighEntropyStringRule
from sast.rules.sql_injection import SQLInjectionRule
from sast.rules.command_injection import CommandInjectionRule
from sast.rules.insecure_config import (
    InsecureImportsRule, DebugModeRule, DisabledVerificationRule, WeakCryptoRule,
)
from sast.rules.path_traversal import PathTraversalRule, SSRFRule


def _check_code(rule, code: str) -> list:
    tree = ast.parse(code)
    lines = code.splitlines()
    return rule.check(tree, lines, "test.py")


class TestHardcodedSecrets:
    def test_password_assignment(self):
        findings = _check_code(HardcodedSecretsRule(), 'password = "SuperSecret123"')
        assert len(findings) == 1
        assert findings[0].rule_id == "SAST-001"

    def test_api_key_in_dict(self):
        findings = _check_code(HardcodedSecretsRule(), 'config = {"api_key": "AKIAIOSFODNN7EXAMPLE"}')
        assert len(findings) == 1

    def test_keyword_arg(self):
        findings = _check_code(HardcodedSecretsRule(), 'db.connect(password="hardcoded")')
        assert len(findings) == 1

    def test_env_var_no_finding(self):
        findings = _check_code(HardcodedSecretsRule(), 'password = os.environ.get("PASSWORD")')
        assert len(findings) == 0

    def test_short_value_ignored(self):
        findings = _check_code(HardcodedSecretsRule(), 'password = "ab"')
        assert len(findings) == 0


class TestSQLInjection:
    def test_fstring_in_execute(self):
        code = 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")'
        findings = _check_code(SQLInjectionRule(), code)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_concat_in_execute(self):
        code = 'cursor.execute("SELECT * FROM users WHERE id = " + user_id)'
        findings = _check_code(SQLInjectionRule(), code)
        assert len(findings) == 1

    def test_format_in_execute(self):
        code = 'cursor.execute("SELECT * FROM users WHERE id = {}".format(uid))'
        findings = _check_code(SQLInjectionRule(), code)
        assert len(findings) == 1

    def test_parameterized_no_finding(self):
        code = 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))'
        findings = _check_code(SQLInjectionRule(), code)
        assert len(findings) == 0


class TestCommandInjection:
    def test_os_system(self):
        code = 'os.system(user_input)'
        findings = _check_code(CommandInjectionRule(), code)
        assert len(findings) == 1

    def test_eval(self):
        findings = _check_code(CommandInjectionRule(), "eval(data)")
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_subprocess_shell_true(self):
        code = 'subprocess.call(cmd, shell=True)'
        findings = _check_code(CommandInjectionRule(), code)
        assert len(findings) == 1

    def test_subprocess_no_shell(self):
        code = 'subprocess.run(["ls", "-la"])'
        findings = _check_code(CommandInjectionRule(), code)
        assert len(findings) == 0


class TestInsecureConfig:
    def test_pickle_import(self):
        findings = _check_code(InsecureImportsRule(), "import pickle")
        assert len(findings) == 1

    def test_debug_true(self):
        findings = _check_code(DebugModeRule(), "DEBUG = True")
        assert len(findings) == 1

    def test_debug_false_no_finding(self):
        findings = _check_code(DebugModeRule(), "DEBUG = False")
        assert len(findings) == 0

    def test_verify_false(self):
        code = 'requests.get("https://example.com", verify=False)'
        findings = _check_code(DisabledVerificationRule(), code)
        assert len(findings) == 1

    def test_weak_hash_md5(self):
        code = 'hashlib.md5(data)'
        findings = _check_code(WeakCryptoRule(), code)
        assert len(findings) == 1


class TestPathTraversal:
    def test_open_variable(self):
        code = "open(filename)"
        findings = _check_code(PathTraversalRule(), code)
        assert len(findings) == 1

    def test_open_constant_no_finding(self):
        code = 'open("config.json")'
        findings = _check_code(PathTraversalRule(), code)
        assert len(findings) == 0


class TestSSRF:
    def test_requests_get_variable(self):
        code = "requests.get(url)"
        findings = _check_code(SSRFRule(), code)
        assert len(findings) == 1

    def test_requests_get_constant_no_finding(self):
        code = 'requests.get("https://api.example.com/data")'
        findings = _check_code(SSRFRule(), code)
        assert len(findings) == 0


class TestRuleRegistry:
    def test_auto_discover(self):
        registry = RuleRegistry()
        registry.auto_discover()
        assert len(registry.rules) >= 8

    def test_all_rules_have_ids(self):
        registry = RuleRegistry()
        registry.auto_discover()
        for rule in registry.rules:
            assert rule.rule_id, f"Rule {type(rule).__name__} has no rule_id"


class TestAnalyzer:
    def test_analyze_vulnerable_file(self, tmp_path):
        vuln_code = '''
password = "SuperSecret123"
import pickle
DEBUG = True
'''
        f = tmp_path / "vuln.py"
        f.write_text(vuln_code)

        registry = RuleRegistry()
        registry.auto_discover()
        analyzer = Analyzer(registry)
        findings = analyzer.analyze_file(str(f))
        assert len(findings) >= 3

    def test_analyze_clean_file(self, tmp_path):
        clean_code = '''
import os
password = os.environ.get("PASSWORD")
DEBUG = False
'''
        f = tmp_path / "clean.py"
        f.write_text(clean_code)

        registry = RuleRegistry()
        registry.auto_discover()
        analyzer = Analyzer(registry)
        findings = analyzer.analyze_file(str(f))
        assert len(findings) == 0

