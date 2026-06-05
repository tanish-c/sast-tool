
from __future__ import annotations

import abc
import ast
import importlib
import pkgutil
from typing import Optional

from sast.models import Finding


class Rule(abc.ABC):

    rule_id: str = ""
    title: str = ""
    description: str = ""
    cwe_id: Optional[str] = None
    remediation: Optional[str] = None

    @abc.abstractmethod
    def check(self, tree: ast.AST, source_lines: list[str], file_path: str) -> list[Finding]:
        ...


class RuleRegistry:

    def __init__(self):
        self._rules: list[Rule] = []

    def register(self, rule: Rule):
        self._rules.append(rule)

    @property
    def rules(self) -> list[Rule]:
        return list(self._rules)

    def auto_discover(self):
        import sast.rules as rules_pkg

        for importer, modname, ispkg in pkgutil.iter_modules(rules_pkg.__path__):
            module = importlib.import_module(f"sast.rules.{modname}")
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if (
                    isinstance(attr, type)
                    and issubclass(attr, Rule)
                    and attr is not Rule
                    and attr.rule_id
                ):
                    self.register(attr())

