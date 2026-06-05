
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

SEVERITY_TO_SARIF = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "none",
}


@dataclass
class Finding:
    rule_id: str
    title: str
    description: str
    severity: Severity
    file_path: str
    line: int
    column: int = 0
    end_line: Optional[int] = None
    end_column: Optional[int] = None
    code_snippet: str = ""
    cwe_id: Optional[str] = None
    remediation: Optional[str] = None
    finding_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "file_path": self.file_path,
            "line": self.line,
            "column": self.column,
            "code_snippet": self.code_snippet,
            "cwe_id": self.cwe_id,
            "remediation": self.remediation,
        }


class FindingsCollection:

    def __init__(self):
        self._findings: list[Finding] = []

    def add(self, finding: Finding):
        self._findings.append(finding)

    def add_many(self, findings: list[Finding]):
        self._findings.extend(findings)

    @property
    def findings(self) -> list[Finding]:
        return sorted(
            self._findings,
            key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.file_path, f.line),
        )

    @property
    def count(self) -> int:
        return len(self._findings)

    def filter_by_severity(self, min_severity: Severity) -> list[Finding]:
        threshold = SEVERITY_ORDER[min_severity]
        return [f for f in self.findings if SEVERITY_ORDER.get(f.severity, 99) <= threshold]

    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self._findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        return counts

    def to_json(self) -> str:
        return json.dumps([f.to_dict() for f in self.findings], indent=2)

    def to_sarif(self) -> dict:
        rules_map: dict[str, dict] = {}
        results = []

        for f in self.findings:
            if f.rule_id not in rules_map:
                rule_def = {
                    "id": f.rule_id,
                    "name": f.title,
                    "shortDescription": {"text": f.title},
                    "fullDescription": {"text": f.description},
                    "defaultConfiguration": {
                        "level": SEVERITY_TO_SARIF.get(f.severity, "warning")
                    },
                }
                if f.cwe_id:
                    rule_def["properties"] = {
                        "tags": ["security", f.cwe_id],
                    }
                rules_map[f.rule_id] = rule_def

            region = {"startLine": f.line, "startColumn": f.column or 1}
            if f.end_line:
                region["endLine"] = f.end_line
            if f.end_column:
                region["endColumn"] = f.end_column

            result = {
                "ruleId": f.rule_id,
                "level": SEVERITY_TO_SARIF.get(f.severity, "warning"),
                "message": {"text": f.description},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.file_path},
                            "region": region,
                        }
                    }
                ],
            }
            if f.code_snippet:
                result["locations"][0]["physicalLocation"]["region"]["snippet"] = {
                    "text": f.code_snippet
                }
            if f.remediation:
                result["fixes"] = [
                    {"description": {"text": f.remediation}}
                ]
            results.append(result)

        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "sast-tool",
                            "version": "1.0.0",
                            "informationUri": "https://github.com/tanishchhabra/sast-tool",
                            "rules": list(rules_map.values()),
                        }
                    },
                    "results": results,
                }
            ],
        }

