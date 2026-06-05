
from __future__ import annotations

import ast

from sast.engine import Rule
from sast.models import Finding, Severity


class CommandInjectionRule(Rule):
    rule_id = "SAST-004"
    title = "Potential Command Injection"
    description = "Use of dangerous functions that may allow command injection"
    cwe_id = "CWE-78"
    remediation = "Use subprocess.run() with a list of arguments instead of shell=True; avoid eval/exec"

    DANGEROUS_FUNCTIONS = {
        "eval": ("eval() executes arbitrary Python code", Severity.CRITICAL),
        "exec": ("exec() executes arbitrary Python code", Severity.CRITICAL),
        "compile": ("compile() can be used to execute arbitrary code", Severity.MEDIUM),
    }

    DANGEROUS_OS_CALLS = {
        "system": ("os.system() executes shell commands", Severity.HIGH),
        "popen": ("os.popen() executes shell commands", Severity.HIGH),
    }

    def check(self, tree: ast.AST, source_lines: list[str], file_path: str) -> list[Finding]:
        findings: list[Finding] = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                findings.extend(self._check_call(node, source_lines, file_path))

        return findings

    def _check_call(self, node: ast.Call, source_lines: list[str], file_path: str) -> list[Finding]:
        findings = []

        if isinstance(node.func, ast.Name):
            name = node.func.id
            if name in self.DANGEROUS_FUNCTIONS:
                desc, severity = self.DANGEROUS_FUNCTIONS[name]
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

        elif isinstance(node.func, ast.Attribute):
            attr = node.func.attr

            if attr in self.DANGEROUS_OS_CALLS:
                if isinstance(node.func.value, ast.Name) and node.func.value.id == "os":
                    desc, severity = self.DANGEROUS_OS_CALLS[attr]
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

            if attr in ("call", "run", "Popen", "check_output", "check_call"):
                if isinstance(node.func.value, ast.Name) and node.func.value.id == "subprocess":
                    for kw in node.keywords:
                        if kw.arg == "shell":
                            if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                                findings.append(Finding(
                                    rule_id=self.rule_id,
                                    title=self.title,
                                    description=f"subprocess.{attr}() called with shell=True",
                                    severity=Severity.HIGH,
                                    file_path=file_path,
                                    line=node.lineno,
                                    column=node.col_offset,
                                    code_snippet=source_lines[node.lineno - 1].strip() if node.lineno <= len(source_lines) else "",
                                    cwe_id=self.cwe_id,
                                    remediation="Use subprocess.run() with a list of arguments and shell=False",
                                ))

        return findings

