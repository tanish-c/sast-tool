
from __future__ import annotations

import ast
from pathlib import Path

from sast.engine import RuleRegistry
from sast.models import FindingsCollection


class Analyzer:

    def __init__(self, registry: RuleRegistry):
        self.registry = registry
        self.findings = FindingsCollection()

    def analyze_file(self, file_path: str) -> list:
        path = Path(file_path)
        if not path.exists() or path.suffix != ".py":
            return []

        source = path.read_text(encoding="utf-8", errors="replace")
        source_lines = source.splitlines()

        try:
            tree = ast.parse(source, filename=file_path)
        except SyntaxError:
            return []

        file_findings = []
        for rule in self.registry.rules:
            try:
                results = rule.check(tree, source_lines, file_path)
                file_findings.extend(results)
            except Exception:
                continue

        self.findings.add_many(file_findings)
        return file_findings

    def analyze_directory(self, directory: str, recursive: bool = True) -> FindingsCollection:
        root = Path(directory)
        if not root.exists():
            return self.findings

        pattern = "**/*.py" if recursive else "*.py"
        for py_file in sorted(root.glob(pattern)):
            parts = py_file.parts
            if any(p.startswith(".") or p == "__pycache__" or p in ("venv", ".venv", "env", "node_modules") for p in parts):
                continue
            self.analyze_file(str(py_file))

        return self.findings

