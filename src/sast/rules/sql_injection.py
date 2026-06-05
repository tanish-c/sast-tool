
from __future__ import annotations

import ast
from typing import Optional

from sast.engine import Rule
from sast.models import Finding, Severity


SQL_KEYWORDS = {"select", "insert", "update", "delete", "drop", "create", "alter", "exec", "execute", "union"}


def _is_sql_string(value: str) -> bool:
    first_word = value.strip().split()[0].lower() if value.strip() else ""
    return first_word in SQL_KEYWORDS


def _get_string_value(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


class SQLInjectionRule(Rule):
    rule_id = "SAST-003"
    title = "Potential SQL Injection"
    description = "SQL query built using string formatting or concatenation instead of parameterized queries"
    cwe_id = "CWE-89"
    remediation = "Use parameterized queries (e.g., cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,)))"

    def check(self, tree: ast.AST, source_lines: list[str], file_path: str) -> list[Finding]:
        findings: list[Finding] = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                findings.extend(self._check_execute_call(node, source_lines, file_path))

            if isinstance(node, ast.Assign):
                findings.extend(self._check_sql_assign(node, source_lines, file_path))

        return findings

    def _check_execute_call(self, node: ast.Call, source_lines: list[str], file_path: str) -> list[Finding]:
        findings = []

        func_name = self._get_call_name(node)
        if not func_name or "execute" not in func_name.lower():
            return findings

        if not node.args:
            return findings

        arg = node.args[0]

        if isinstance(arg, ast.JoinedStr):
            has_variable = any(isinstance(v, ast.FormattedValue) for v in arg.values)
            if has_variable:
                findings.append(self._make_finding(
                    "SQL query built with f-string in execute() call",
                    node, source_lines, file_path, Severity.CRITICAL,
                ))

        elif isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
            if self._contains_sql_binop(arg):
                findings.append(self._make_finding(
                    "SQL query built with string concatenation in execute() call",
                    node, source_lines, file_path, Severity.CRITICAL,
                ))

        elif isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Mod):
            left_val = _get_string_value(arg.left) if hasattr(arg, "left") else None
            if left_val and _is_sql_string(left_val):
                findings.append(self._make_finding(
                    "SQL query built with %-formatting in execute() call",
                    node, source_lines, file_path, Severity.CRITICAL,
                ))

        elif isinstance(arg, ast.Call):
            if isinstance(arg.func, ast.Attribute) and arg.func.attr == "format":
                if isinstance(arg.func.value, ast.Constant):
                    val = arg.func.value.value
                    if isinstance(val, str) and _is_sql_string(val):
                        findings.append(self._make_finding(
                            "SQL query built with .format() in execute() call",
                            node, source_lines, file_path, Severity.CRITICAL,
                        ))

        return findings

    def _check_sql_assign(self, node: ast.Assign, source_lines: list[str], file_path: str) -> list[Finding]:
        findings = []
        name = ""
        for target in node.targets:
            if isinstance(target, ast.Name):
                name = target.id.lower()

        if not any(kw in name for kw in ("query", "sql", "stmt", "statement")):
            return findings

        value = node.value

        if isinstance(value, ast.JoinedStr):
            has_variable = any(isinstance(v, ast.FormattedValue) for v in value.values)
            if has_variable:
                findings.append(self._make_finding(
                    f"SQL query variable '{name}' built with f-string",
                    node, source_lines, file_path, Severity.HIGH,
                ))

        elif isinstance(value, ast.BinOp) and isinstance(value.op, ast.Add):
            if self._contains_sql_binop(value):
                findings.append(self._make_finding(
                    f"SQL query variable '{name}' built with string concatenation",
                    node, source_lines, file_path, Severity.HIGH,
                ))

        return findings

    def _contains_sql_binop(self, node: ast.BinOp) -> bool:
        to_check = [node.left, node.right]
        while to_check:
            n = to_check.pop()
            val = _get_string_value(n)
            if val and _is_sql_string(val):
                return True
            if isinstance(n, ast.BinOp):
                to_check.extend([n.left, n.right])
        return False

    def _make_finding(
        self, desc: str, node: ast.AST, source_lines: list[str], file_path: str, severity: Severity
    ) -> Finding:
        return Finding(
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
        )

    @staticmethod
    def _get_call_name(node: ast.Call) -> Optional[str]:
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
        if isinstance(node.func, ast.Name):
            return node.func.id
        return None

