
from __future__ import annotations

import ast
import math
import re
from typing import Optional

from sast.engine import Rule
from sast.models import Finding, Severity


SECRET_PATTERNS = re.compile(
    r"(password|passwd|pwd|secret|api_key|apikey|api_secret|"
    r"access_token|auth_token|private_key|secret_key|"
    r"db_password|database_password|mysql_pwd|"
    r"aws_secret|aws_access_key|heroku_api_key)",
    re.IGNORECASE,
)


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
    )


class HardcodedSecretsRule(Rule):
    rule_id = "SAST-001"
    title = "Hardcoded Secret"
    description = "Hardcoded credentials or secrets detected in source code"
    cwe_id = "CWE-798"
    remediation = "Use environment variables or a secrets manager instead of hardcoding credentials"

    def check(self, tree: ast.AST, source_lines: list[str], file_path: str) -> list[Finding]:
        findings: list[Finding] = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                findings.extend(self._check_assign(node, source_lines, file_path))

            elif isinstance(node, ast.Call):
                findings.extend(self._check_call_kwargs(node, source_lines, file_path))

            elif isinstance(node, ast.Dict):
                findings.extend(self._check_dict(node, source_lines, file_path))

        return findings

    def _check_assign(self, node: ast.Assign, source_lines: list[str], file_path: str) -> list[Finding]:
        findings = []
        for target in node.targets:
            name = self._get_name(target)
            if name and SECRET_PATTERNS.search(name):
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    value = node.value.value
                    if len(value) >= 3 and value.lower() not in ("", "none", "null", "changeme", "xxx", "todo"):
                        findings.append(Finding(
                            rule_id=self.rule_id,
                            title=self.title,
                            description=f"Hardcoded secret assigned to '{name}'",
                            severity=Severity.HIGH,
                            file_path=file_path,
                            line=node.lineno,
                            column=node.col_offset,
                            code_snippet=source_lines[node.lineno - 1].strip() if node.lineno <= len(source_lines) else "",
                            cwe_id=self.cwe_id,
                            remediation=self.remediation,
                        ))
        return findings

    def _check_call_kwargs(self, node: ast.Call, source_lines: list[str], file_path: str) -> list[Finding]:
        findings = []
        for kw in node.keywords:
            if kw.arg and SECRET_PATTERNS.search(kw.arg):
                if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                    value = kw.value.value
                    if len(value) >= 3:
                        findings.append(Finding(
                            rule_id=self.rule_id,
                            title=self.title,
                            description=f"Hardcoded secret in keyword argument '{kw.arg}'",
                            severity=Severity.HIGH,
                            file_path=file_path,
                            line=kw.value.lineno,
                            column=kw.value.col_offset,
                            code_snippet=source_lines[kw.value.lineno - 1].strip() if kw.value.lineno <= len(source_lines) else "",
                            cwe_id=self.cwe_id,
                            remediation=self.remediation,
                        ))
        return findings

    def _check_dict(self, node: ast.Dict, source_lines: list[str], file_path: str) -> list[Finding]:
        findings = []
        for key, value in zip(node.keys, node.values):
            if key is None:
                continue
            if isinstance(key, ast.Constant) and isinstance(key.value, str):
                if SECRET_PATTERNS.search(key.value):
                    if isinstance(value, ast.Constant) and isinstance(value.value, str) and len(value.value) >= 3:
                        findings.append(Finding(
                            rule_id=self.rule_id,
                            title=self.title,
                            description=f"Hardcoded secret in dictionary key '{key.value}'",
                            severity=Severity.HIGH,
                            file_path=file_path,
                            line=key.lineno,
                            column=key.col_offset,
                            code_snippet=source_lines[key.lineno - 1].strip() if key.lineno <= len(source_lines) else "",
                            cwe_id=self.cwe_id,
                            remediation=self.remediation,
                        ))
        return findings

    @staticmethod
    def _get_name(node: ast.AST) -> Optional[str]:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return node.attr
        return None


class HighEntropyStringRule(Rule):
    rule_id = "SAST-002"
    title = "High Entropy String"
    description = "A high-entropy string that may be an embedded secret or key"
    cwe_id = "CWE-798"
    remediation = "Review this string; if it is a secret, move it to environment variables or a secrets manager"

    ENTROPY_THRESHOLD = 4.5
    MIN_LENGTH = 16

    def check(self, tree: ast.AST, source_lines: list[str], file_path: str) -> list[Finding]:
        findings: list[Finding] = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        value = node.value.value
                        if len(value) >= self.MIN_LENGTH and _shannon_entropy(value) >= self.ENTROPY_THRESHOLD:
                            findings.append(Finding(
                                rule_id=self.rule_id,
                                title=self.title,
                                description=f"High-entropy string (entropy={_shannon_entropy(value):.2f}) may be an embedded secret",
                                severity=Severity.MEDIUM,
                                file_path=file_path,
                                line=node.lineno,
                                column=node.col_offset,
                                code_snippet=source_lines[node.lineno - 1].strip() if node.lineno <= len(source_lines) else "",
                                cwe_id=self.cwe_id,
                                remediation=self.remediation,
                            ))

        return findings

