
from __future__ import annotations

import ast

from sast.engine import Rule
from sast.models import Finding, Severity


class InsecureImportsRule(Rule):
    rule_id = "SAST-005"
    title = "Insecure Module Import"
    description = "Import of a module known to have security risks if used improperly"
    cwe_id = "CWE-502"
    remediation = "Avoid using pickle/marshal for untrusted data; use json or a safe serialization format"

    DANGEROUS_IMPORTS = {
        "pickle": ("pickle module can execute arbitrary code during deserialization", Severity.MEDIUM),
        "cPickle": ("cPickle module can execute arbitrary code during deserialization", Severity.MEDIUM),
        "marshal": ("marshal module can execute arbitrary code", Severity.MEDIUM),
        "shelve": ("shelve uses pickle internally and is unsafe with untrusted data", Severity.MEDIUM),
    }

    def check(self, tree: ast.AST, source_lines: list[str], file_path: str) -> list[Finding]:
        findings: list[Finding] = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in self.DANGEROUS_IMPORTS:
                        desc, severity = self.DANGEROUS_IMPORTS[alias.name]
                        findings.append(Finding(
                            rule_id=self.rule_id,
                            title=self.title,
                            description=desc,
                            severity=severity,
                            file_path=file_path,
                            line=node.lineno,
                            column=node.col_offset,
                            code_snippet=source_lines[node.lineno - 1].strip() if node.lineno <= len(source_lines) else "",
                            cwe_id=self.cwe_id,
                            remediation=self.remediation,
                        ))

            elif isinstance(node, ast.ImportFrom):
                if node.module and node.module.split(".")[0] in self.DANGEROUS_IMPORTS:
                    desc, severity = self.DANGEROUS_IMPORTS[node.module.split(".")[0]]
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        description=desc,
                        severity=severity,
                        file_path=file_path,
                        line=node.lineno,
                        column=node.col_offset,
                        code_snippet=source_lines[node.lineno - 1].strip() if node.lineno <= len(source_lines) else "",
                        cwe_id=self.cwe_id,
                        remediation=self.remediation,
                    ))

        return findings


class DebugModeRule(Rule):
    rule_id = "SAST-006"
    title = "Debug Mode Enabled"
    description = "Debug mode is enabled which may expose sensitive information in production"
    cwe_id = "CWE-489"
    remediation = "Set DEBUG = False in production configurations"

    def check(self, tree: ast.AST, source_lines: list[str], file_path: str) -> list[Finding]:
        findings: list[Finding] = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == "DEBUG":
                        if isinstance(node.value, ast.Constant) and node.value.value is True:
                            findings.append(Finding(
                                rule_id=self.rule_id,
                                title=self.title,
                                description="DEBUG is set to True",
                                severity=Severity.MEDIUM,
                                file_path=file_path,
                                line=node.lineno,
                                column=node.col_offset,
                                code_snippet=source_lines[node.lineno - 1].strip() if node.lineno <= len(source_lines) else "",
                                cwe_id=self.cwe_id,
                                remediation=self.remediation,
                            ))

        return findings


class DisabledVerificationRule(Rule):
    rule_id = "SAST-007"
    title = "SSL/TLS Verification Disabled"
    description = "SSL/TLS certificate verification is disabled, enabling man-in-the-middle attacks"
    cwe_id = "CWE-295"
    remediation = "Remove verify=False and use proper certificate verification"

    def check(self, tree: ast.AST, source_lines: list[str], file_path: str) -> list[Finding]:
        findings: list[Finding] = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                for kw in node.keywords:
                    if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                        findings.append(Finding(
                            rule_id=self.rule_id,
                            title=self.title,
                            description="verify=False disables SSL/TLS certificate verification",
                            severity=Severity.HIGH,
                            file_path=file_path,
                            line=kw.value.lineno,
                            column=kw.value.col_offset,
                            code_snippet=source_lines[kw.value.lineno - 1].strip() if kw.value.lineno <= len(source_lines) else "",
                            cwe_id=self.cwe_id,
                            remediation=self.remediation,
                        ))

        return findings


class WeakCryptoRule(Rule):
    rule_id = "SAST-008"
    title = "Weak Cryptographic Hash"
    description = "Use of weak cryptographic hash function (MD5/SHA1) for security purposes"
    cwe_id = "CWE-328"
    remediation = "Use SHA-256 or stronger hash functions; for passwords, use bcrypt, scrypt, or argon2"

    WEAK_HASHES = {"md5", "sha1"}

    def check(self, tree: ast.AST, source_lines: list[str], file_path: str) -> list[Finding]:
        findings: list[Finding] = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr in self.WEAK_HASHES:
                        if isinstance(node.func.value, ast.Name) and node.func.value.id == "hashlib":
                            findings.append(Finding(
                                rule_id=self.rule_id,
                                title=self.title,
                                description=f"hashlib.{node.func.attr}() is cryptographically weak",
                                severity=Severity.MEDIUM,
                                file_path=file_path,
                                line=node.lineno,
                                column=node.col_offset,
                                code_snippet=source_lines[node.lineno - 1].strip() if node.lineno <= len(source_lines) else "",
                                cwe_id=self.cwe_id,
                                remediation=self.remediation,
                            ))

                if isinstance(node.func, ast.Attribute) and node.func.attr == "new":
                    if isinstance(node.func.value, ast.Name) and node.func.value.id == "hashlib":
                        if node.args and isinstance(node.args[0], ast.Constant):
                            if str(node.args[0].value).lower() in self.WEAK_HASHES:
                                findings.append(Finding(
                                    rule_id=self.rule_id,
                                    title=self.title,
                                    description=f"hashlib.new('{node.args[0].value}') uses a weak hash",
                                    severity=Severity.MEDIUM,
                                    file_path=file_path,
                                    line=node.lineno,
                                    column=node.col_offset,
                                    code_snippet=source_lines[node.lineno - 1].strip() if node.lineno <= len(source_lines) else "",
                                    cwe_id=self.cwe_id,
                                    remediation=self.remediation,
                                ))

        return findings

