"""
PentestBot v2 — Result Aggregator
Merges all pipeline context fields into a single typed AggregatedResult.
This is the boundary between raw pipeline data and clean analysis/report data.
"""

import hashlib
import ipaddress
from dataclasses import dataclass, field
from typing import Optional


# ── Risk scoring weights ──────────────────────────────────────────────────────

SEVERITY_WEIGHT = {
    "critical": 15.0,
    "high":     7.0,
    "medium":   2.5,
    "low":      0.5,
    "info":     0.05,
    "unknown":  0.1,
}

DANGEROUS_PORTS = {
    21:    ("FTP",           "high",   "FTP transmits credentials in plaintext."),
    22:    ("SSH",           "medium", "SSH is exposed; ensure key-only auth and hardened ciphers."),
    23:    ("Telnet",        "critical","Telnet is unencrypted and must be disabled immediately."),
    25:    ("SMTP",          "medium", "SMTP exposed; verify it is not an open relay."),
    53:    ("DNS",           "low",    "DNS exposed publicly; restrict recursive queries."),
    110:   ("POP3",          "medium", "POP3 transmits credentials in plaintext."),
    143:   ("IMAP",          "medium", "IMAP transmits credentials in plaintext."),
    389:   ("LDAP",          "high",   "LDAP exposed; ensure authentication is enforced."),
    445:   ("SMB",           "high",   "SMB exposed; high risk of EternalBlue-style exploits."),
    1433:  ("MSSQL",         "high",   "MSSQL exposed publicly; restrict to trusted IPs only."),
    1521:  ("Oracle",        "high",   "Oracle DB exposed; restrict with firewall rules."),
    3306:  ("MySQL",         "high",   "MySQL exposed publicly; restrict access immediately."),
    3389:  ("RDP",           "critical","RDP is a primary attack vector; restrict to VPN only."),
    5432:  ("PostgreSQL",    "high",   "PostgreSQL exposed; ensure strong auth and IP filtering."),
    5900:  ("VNC",           "critical","VNC exposed; often has weak/no authentication."),
    6379:  ("Redis",         "critical","Redis exposed; unauthenticated access is trivially exploitable."),
    8080:  ("HTTP-Alt",      "low",    "Alternative HTTP port; review for sensitive services."),
    9200:  ("Elasticsearch", "critical","Elasticsearch exposed; data may be publicly readable."),
    27017: ("MongoDB",       "critical","MongoDB exposed; data may be accessible without credentials."),
}


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class ExposedPort:
    port:         int
    host:         str
    service_name: str     = ""
    version:      str     = ""
    is_dangerous: bool    = False
    risk_level:   str     = "info"
    risk_note:    str     = ""
    cpe:          list    = field(default_factory=list)


@dataclass
class Finding:
    id:          str
    title:       str
    severity:    str
    description: str
    affected:    list[str]     = field(default_factory=list)
    source:      str           = ""
    remediation: str           = ""
    references:  list[str]     = field(default_factory=list)
    cvss:        Optional[float] = None
    cve_ids:     list[str]     = field(default_factory=list)
    tags:        list[str]     = field(default_factory=list)
    extra:       dict          = field(default_factory=dict)
    evidence_status: str       = "Observed condition"
    exploitability: str        = "Needs manual validation"
    impact:        str         = "Requires contextual validation"
    priority:      str         = "Review in context"
    validated:     bool        = False


@dataclass
class AggregatedResult:
    """Complete normalized picture of a finished scan."""

    # Identifiers
    scan_id:       str
    target:        str
    target_type:   str
    scan_started:  str
    scan_completed: str
    scan_duration:  float

    # Asset inventory
    subdomains:      list[str]        = field(default_factory=list)
    resolved_ips:    list[str]        = field(default_factory=list)
    ip_to_hosts:     dict             = field(default_factory=dict)
    dns_records:     dict             = field(default_factory=dict)
    origin_data:     dict             = field(default_factory=dict)
    cdn_detected:    bool             = False
    origin_candidates: list[str]      = field(default_factory=list)

    # Network surface
    open_ports:      list[ExposedPort]  = field(default_factory=list)
    dangerous_ports: list[ExposedPort]  = field(default_factory=list)
    services:        list[dict]         = field(default_factory=list)
    os_matches:      list[dict]         = field(default_factory=list)

    # Web surface
    live_hosts:    list[dict]         = field(default_factory=list)
    technologies:  list[str]          = field(default_factory=list)
    web_servers:   list[str]          = field(default_factory=list)
    discovered_urls: list[str]        = field(default_factory=list)

    # TLS
    cert_info:     dict               = field(default_factory=dict)
    tls_findings:  list[dict]         = field(default_factory=list)
    tls_protocols: dict               = field(default_factory=dict)

    # Findings (unified, deduped, sorted)
    findings:         list[Finding]   = field(default_factory=list)
    severity_summary: dict            = field(default_factory=dict)
    observed_findings_count: int      = 0
    excluded_findings_count: int      = 0
    total_findings:   int             = 0

    # Risk
    risk_score:   float = 0.0
    risk_level:   str   = "Unknown"

    # Metadata
    tool_errors:  list[str]  = field(default_factory=list)
    limitations:  list[str]  = field(default_factory=list)
    notes:        list[str]  = field(default_factory=list)
    nmap_scripts: dict       = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = {
            "scan_id":          self.scan_id,
            "target":           self.target,
            "target_type":      self.target_type,
            "scan_started":     self.scan_started,
            "scan_completed":   self.scan_completed,
            "scan_duration":    self.scan_duration,
            "subdomains":       self.subdomains,
            "resolved_ips":     self.resolved_ips,
            "ip_to_hosts":      self.ip_to_hosts,
            "dns_records":      self.dns_records,
            "origin_data":      self.origin_data,
            "cdn_detected":     self.cdn_detected,
            "origin_candidates":self.origin_candidates,
            "open_ports":       [p.__dict__ for p in self.open_ports],
            "dangerous_ports":  [p.__dict__ for p in self.dangerous_ports],
            "services":         self.services,
            "os_matches":       self.os_matches,
            "live_hosts":       self.live_hosts,
            "technologies":     self.technologies,
            "web_servers":      self.web_servers,
            "discovered_urls":  self.discovered_urls,
            "cert_info":        self.cert_info,
            "tls_findings":     self.tls_findings,
            "findings":         [f.__dict__ for f in self.findings],
            "severity_summary": self.severity_summary,
            "observed_findings_count": self.observed_findings_count,
            "excluded_findings_count": self.excluded_findings_count,
            "total_findings":   self.total_findings,
            "risk_score":       self.risk_score,
            "risk_level":       self.risk_level,
            "tool_errors":      self.tool_errors,
            "limitations":      self.limitations,
            "notes":            self.notes,
            "nmap_scripts":     self.nmap_scripts,
        }
        return d


# ── Aggregator ────────────────────────────────────────────────────────────────

class ResultAggregator:
    """
    Takes the raw pipeline ctx dict and returns an AggregatedResult.
    All merging, deduplication, and port enrichment happens here.
    """

    def __init__(self, ctx: dict):
        self.ctx = ctx

    def aggregate(self) -> AggregatedResult:
        ctx = self.ctx
        from datetime import datetime

        result = AggregatedResult(
            scan_id        = ctx.get("scan_id", ""),
            target         = ctx.get("target", ""),
            target_type    = _target_type(ctx.get("target", "")),
            scan_started   = str(ctx.get("scan_started", datetime.utcnow().isoformat())),
            scan_completed = datetime.utcnow().isoformat(),
            scan_duration  = ctx.get("scan_duration", 0.0),
        )

        # ── Asset inventory ───────────────────────────────────────────────
        result.subdomains        = ctx.get("subdomains", [result.target])
        result.resolved_ips      = ctx.get("live_ips", [])
        result.ip_to_hosts       = ctx.get("ip_to_hosts", {})
        result.dns_records       = ctx.get("resolved_hosts", {})
        result.origin_data       = ctx.get("origin_data", {})
        result.cdn_detected      = ctx.get("cdn_detected", False)
        result.origin_candidates = ctx.get("origin_candidates", [])

        # ── Network surface ───────────────────────────────────────────────
        raw_ports  = ctx.get("open_ports", [])
        services   = ctx.get("services", [])
        service_by_host_port = {
            (str(s.get("host", "")).strip(), s["port"]): s
            for s in services
            if "port" in s
        }
        service_by_port = {s["port"]: s for s in services if "port" in s}

        exposed: list[ExposedPort] = []
        dangerous: list[ExposedPort] = []

        for entry in raw_ports:
            port    = entry.get("port", 0)
            host    = entry.get("host", result.target)
            svc_row = service_by_host_port.get((str(host).strip(), port), service_by_port.get(port, {}))

            ep = ExposedPort(
                port         = port,
                host         = host,
                service_name = svc_row.get("service", ""),
                version      = svc_row.get("version", ""),
                cpe          = svc_row.get("cpe", []),
            )

            if port in DANGEROUS_PORTS:
                svc_label, risk, note = DANGEROUS_PORTS[port]
                ep.service_name = ep.service_name or svc_label
                ep.is_dangerous = True
                ep.risk_level   = risk
                ep.risk_note    = note
                dangerous.append(ep)

            exposed.append(ep)

        result.open_ports      = sorted(exposed,   key=lambda p: p.port)
        result.dangerous_ports = sorted(dangerous, key=lambda p: p.port)
        result.services        = services
        result.os_matches      = ctx.get("os_matches", [])
        result.nmap_scripts    = ctx.get("nmap_scripts", {})

        # ── Web surface ───────────────────────────────────────────────────
        result.live_hosts   = _dedupe_live_hosts(ctx.get("live_hosts", []))
        result.technologies = _dedupe_strs(ctx.get("technologies", []))
        result.web_servers  = _dedupe_strs(ctx.get("web_servers", []))
        result.discovered_urls = _dedupe_strs(ctx.get("discovered_urls", []))

        # ── TLS ───────────────────────────────────────────────────────────
        result.cert_info    = ctx.get("cert_info", {})
        result.tls_findings = _dedupe_tls_findings(ctx.get("tls_findings", []))

        # ── Unified Findings ──────────────────────────────────────────────
        all_findings: list[Finding] = []
        seen_ids: set[str] = set()

        def add_finding(f: Finding) -> None:
            if f.id not in seen_ids:
                seen_ids.add(f.id)
                all_findings.append(f)

        # Nuclei findings
        for nf in ctx.get("nuclei_findings", []):
            fid = f"nuclei-{nf.get('template_id') or _finding_fingerprint(nf)}"
            severity = nf.get("severity", "info")
            is_validated = severity in {"critical", "high"}
            add_finding(Finding(
                id          = fid,
                title       = nf.get("name", "Nuclei Finding"),
                severity    = severity,
                description = nf.get("description", ""),
                affected    = [nf.get("matched_at", nf.get("host", result.target))],
                source      = "nuclei",
                references  = nf.get("references", []),
                cvss        = nf.get("cvss_score"),
                cve_ids     = nf.get("cve_ids", []),
                tags        = nf.get("tags", []),
                extra       = {"template_id": nf.get("template_id", ""), "kind": "nuclei"},
                evidence_status="Structured scanner evidence",
                exploitability="Likely exploitable" if is_validated else "Needs manual validation",
                impact="Direct security weakness",
                priority="Immediate Fix (0-7 days)" if severity in {"critical", "high"} else "Short-Term Fix (7-30 days)",
                validated=is_validated,
            ))

        # Nikto findings
        for nf in ctx.get("nikto_findings", []):
            fid = f"nikto-{_finding_fingerprint(nf)}"
            add_finding(Finding(
                id          = fid,
                title       = _truncate(nf.get("description", "Nikto Finding"), 80),
                severity    = nf.get("severity", "info"),
                description = nf.get("description", ""),
                affected    = [result.target],
                source      = "nikto",
                evidence_status="Single-tool heuristic evidence",
                exploitability="Needs manual validation",
                impact="Potential web application weakness",
                priority="Short-Term Fix (7-30 days)",
                extra={"kind": "nikto"},
            ))

        # TLS findings
        for tf in result.tls_findings:
            fid = f"tls-{_finding_fingerprint(tf)}"
            add_finding(Finding(
                id          = fid,
                title       = f"TLS: {tf.get('id', 'Issue')}",
                severity    = tf.get("severity", "info"),
                description = tf.get("description", ""),
                affected    = [f"{result.target}:443"],
                source      = "testssl.sh",
                evidence_status="Transport-layer observation",
                exploitability="Configuration weakness",
                impact="Transport security weakness",
                priority="Hardening / Best Practice",
                extra={"kind": "tls"},
            ))

        # Dangerous port findings
        for dp in result.dangerous_ports:
            if dp.risk_level not in {"critical", "high"}:
                continue
            fid = f"port-{dp.port}"
            add_finding(Finding(
                id          = fid,
                title       = f"Exposed {dp.service_name} Service (Port {dp.port})",
                severity    = dp.risk_level,
                description = dp.risk_note,
                affected    = [f"{dp.host}:{dp.port}"],
                source      = "naabu/nmap",
                evidence_status="Confirmed service exposure",
                exploitability="Directly reachable service exposure",
                impact="Remote attack surface expansion",
                priority="Short-Term Fix (7-30 days)",
                validated=True,
                extra={"kind": "exposed-service"},
            ))

        # Sort by severity
        sev_rank = {s: i for i, s in enumerate(
            ["critical", "high", "medium", "low", "info", "unknown"]
        )}
        all_findings.sort(key=lambda f: sev_rank.get(f.severity, 99))

        result.findings       = all_findings
        result.observed_findings_count = len(all_findings)
        result.total_findings = len(all_findings)

        # Severity summary
        sev_counts: dict = {}
        for f in all_findings:
            sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
        result.severity_summary = sev_counts

        # Tool errors
        result.tool_errors = ctx.get("tool_errors", [])
        result.limitations = _dedupe_strs(ctx.get("limitations", []))

        return result


def _truncate(s: str, n: int) -> str:
    return s[:n - 3] + "..." if len(s) > n else s


def _target_type(target: str) -> str:
    try:
        ipaddress.ip_address(target)
        return "ip"
    except ValueError:
        return "domain"


def _finding_fingerprint(finding: dict) -> str:
    payload = "|".join([
        str(finding.get("id", "")),
        str(finding.get("name", "")),
        str(finding.get("title", "")),
        str(finding.get("description", "")),
        str(finding.get("matched_at", "")),
        str(finding.get("host", "")),
        str(finding.get("url", "")),
    ])
    return hashlib.sha1(payload.encode("utf-8", errors="replace")).hexdigest()[:10]


def _dedupe_strs(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        text = str(value).strip()
        if not text:
            continue
        lowered = text.lower()
        if lowered in seen:
            continue
        seen.add(lowered)
        out.append(text)
    return out


def _dedupe_live_hosts(hosts: list[dict]) -> list[dict]:
    by_url: dict[str, dict] = {}
    for host in hosts:
        if not isinstance(host, dict):
            continue
        url = str(host.get("final_url") or host.get("url") or "").strip()
        if not url:
            continue
        current = dict(host)
        current["url"] = url
        existing = by_url.get(url)
        if existing is None or _host_quality(current) > _host_quality(existing):
            by_url[url] = current
    return sorted(by_url.values(), key=lambda item: item.get("url", ""))


def _host_quality(host: dict) -> tuple[int, int, int, int]:
    return (
        1 if int(host.get("status_code", 0) or 0) > 0 else 0,
        len(host.get("technologies") or []),
        len(host.get("headers") or {}),
        len(str(host.get("title") or "")),
    )


def _dedupe_tls_findings(findings: list[dict]) -> list[dict]:
    seen: set[tuple[str, str, str]] = set()
    out: list[dict] = []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        key = (
            str(finding.get("id", "")).strip().lower(),
            str(finding.get("severity", "")).strip().lower(),
            str(finding.get("description", "")).strip(),
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(finding)
    return out
