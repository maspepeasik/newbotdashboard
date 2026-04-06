"""
PentestBot v2 — Nuclei Parser
Parses nuclei's JSON output into structured findings.
"""

import json
from typing import Any

SEVERITY_RANK = {
    "critical": 0, "high": 1, "medium": 2,
    "low": 3, "info": 4, "unknown": 5,
}


class NucleiParser:
    """
    Parses raw nuclei JSON output (one JSON object per line).
    Returns normalized findings grouped by severity.
    """

    def parse(self, raw_output: str) -> dict:
        if not raw_output or not raw_output.strip():
            return self._empty()

        findings: list[dict] = []

        for line in raw_output.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                entry = json.loads(line)
                finding = self._extract_finding(entry)
                if finding:
                    findings.append(finding)
            except (json.JSONDecodeError, KeyError, TypeError):
                continue

        # Sort by severity
        findings.sort(key=lambda f: SEVERITY_RANK.get(f.get("severity", "unknown"), 5))

        # Group by severity
        by_severity: dict[str, list] = {}
        for f in findings:
            sev = f.get("severity", "info")
            by_severity.setdefault(sev, []).append(f)

        severity_counts = {
            sev: len(items)
            for sev, items in by_severity.items()
        }

        return {
            "findings": findings,
            "total": len(findings),
            "by_severity": by_severity,
            "severity_counts": severity_counts,
        }

    def _extract_finding(self, entry: dict) -> dict | None:
        info = entry.get("info", {}) or {}
        severity = info.get("severity", "info").lower()
        template_id = entry.get("template-id", "")
        name = info.get("name", template_id or "Unknown Finding")

        if not template_id and not name:
            return None

        # CVE and CVSS
        classification = info.get("classification", {}) or {}
        cve_ids = classification.get("cve-id", []) or []
        if isinstance(cve_ids, str):
            cve_ids = [cve_ids]
        cvss_score = classification.get("cvss-score")

        # Reference links
        references = info.get("reference", []) or []
        if isinstance(references, str):
            references = [references]

        # Matched-at and extracted results
        matched_at       = entry.get("matched-at", entry.get("host", ""))
        extracted_results = entry.get("extracted-results", []) or []
        curl_command      = entry.get("curl-command", "")

        # Tags
        tags = info.get("tags", []) or []
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",")]

        description = info.get("description", "")
        if not description:
            description = f"Nuclei template '{template_id}' matched at {matched_at}."

        return {
            "template_id":  template_id,
            "name":         name,
            "severity":     severity,
            "description":  description,
            "tags":         tags,
            "host":         entry.get("host", ""),
            "matched_at":   matched_at,
            "extracted":    extracted_results[:5],   # Limit to 5 items
            "curl_command": curl_command[:500] if curl_command else "",
            "references":   references[:5],
            "cvss_score":   cvss_score,
            "cve_ids":      cve_ids,
            "source":       "nuclei",
        }

    @staticmethod
    def _empty() -> dict:
        return {
            "findings": [],
            "total": 0,
            "by_severity": {},
            "severity_counts": {},
        }
