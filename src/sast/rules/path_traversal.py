
from __future__ import annotations

import ast
from typing import Optional

from sast.engine import Rule
from sast.models import Finding, Severity


class PathTraversalRule(Rule):
    rule_id = "SAST-009"
    title = "Potential Path Traversal"
    description = "File operations using potentially user-controlled input without path validation"
    cwe_id = "CWE-22"
    remediation = "Validate and sanitize file paths; use os.path.realpath() and check against an allowed base directory"

    FILE_OPEN_FUNCTIONS = {"open", "file"}

    def check(self, tree: ast.AST, source_lines: list[str], file_path: str) -> list[Finding]:
        findings: list[Finding] = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                findings.extend(self._check_call(node, source_lines, file_path))

        return findings

    def _check_call(self, node: ast.Call, source_lines: list[str], file_path: str) -> list[Finding]:
        findings = []
        func_name = self._get_func_name(node)

        if func_name in self.FILE_OPEN_FUNCTIONS and node.args:
            arg = node.args[0]
            if self._is_variable_input(arg):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    description=f"{func_name}() called with a variable path, potential path traversal",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line=node.lineno,
                    column=node.col_offset,
                    code_snippet=source_lines[node.lineno - 1].strip() if node.lineno <= len(source_lines) else "",
                    cwe_id=self.cwe_id,
                    remediation=self.remediation,
                ))

        if func_name == "join":
            if isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Attribute):
                    pass

        if func_name == "Path" and node.args:
            arg = node.args[0]
            if self._is_variable_input(arg):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    description="Path() constructed with a variable, ensure path validation is performed",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line=node.lineno,
                    column=node.col_offset,
                    code_snippet=source_lines[node.lineno - 1].strip() if node.lineno <= len(source_lines) else "",
                    cwe_id=self.cwe_id,
                    remediation=self.remediation,
                ))

        return findings

    @staticmethod
    def _is_variable_input(node: ast.AST) -> bool:
        if isinstance(node, ast.Constant):
            return False
        if isinstance(node, ast.Name):
            return True
        if isinstance(node, ast.BinOp):
            return True
        if isinstance(node, ast.JoinedStr):
            return True
        if isinstance(node, ast.Call):
            return True
        if isinstance(node, ast.Subscript):
            return True
        return False

    @staticmethod
    def _get_func_name(node: ast.Call) -> Optional[str]:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
        return None


class SSRFRule(Rule):
    rule_id = "SAST-010"
    title = "Potential SSRF"
    description = "HTTP request made with a potentially user-controlled URL"
    cwe_id = "CWE-918"
    remediation = "Validate and allowlist URLs before making HTTP requests; block internal/private IP ranges"

    HTTP_METHODS = {"get", "post", "put", "delete", "patch", "head", "options", "request"}

    def check(self, tree: ast.AST, source_lines: list[str], file_path: str) -> list[Finding]:
        findings: list[Finding] = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                findings.extend(self._check_call(node, source_lines, file_path))

        return findings

    def _check_call(self, node: ast.Call, source_lines: list[str], file_path: str) -> list[Finding]:
        findings = []

        if not isinstance(node.func, ast.Attribute):
            return findings

        attr = node.func.attr
        if attr not in self.HTTP_METHODS:
            return findings

        caller = node.func.value
        caller_name = None
        if isinstance(caller, ast.Name):
            caller_name = caller.id
        elif isinstance(caller, ast.Attribute):
            caller_name = caller.attr

        if caller_name not in ("requests", "request", "http", "urllib", "httpx", "session", "client"):
            return findings

        if node.args:
            url_arg = node.args[0]
            if PathTraversalRule._is_variable_input(url_arg):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    description=f"{caller_name}.{attr}() called with a variable URL, potential SSRF",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line=node.lineno,
                    column=node.col_offset,
                    code_snippet=source_lines[node.lineno - 1].strip() if node.lineno <= len(source_lines) else "",
                    cwe_id=self.cwe_id,
                    remediation=self.remediation,
                ))

        return findings

