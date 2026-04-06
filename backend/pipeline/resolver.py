"""
PentestBot v2 — Resolver Stage
DNS resolution and record enumeration using dnsx.
Resolves all discovered subdomains to their A/CNAME/MX/TXT records.
"""

import json
from pathlib import Path

from pipeline.base_stage import BaseStage


class ResolverStage(BaseStage):
    """
    Stage 2: DNS Resolution

    Takes ctx['subdomains_file'] as input.
    Runs dnsx to resolve A, CNAME, MX, TXT, NS records.
    Populates:
      ctx['resolved_hosts']   → dict: hostname → dns data
      ctx['live_ips']         → list of unique resolved IPs
      ctx['ip_to_hosts']      → dict: IP → [hostnames]
      ctx['dns_records_file'] → path to raw JSON output
    """

    NAME = "Resolver"

    async def run(self) -> None:
        subs_file: Path = self.ctx.get("subdomains_file")
        subdomains: list[str] = self.ctx.get("subdomains", [self.target])

        if not subs_file or not subs_file.exists():
            # Write subdomains to temp file
            subs_file = self.temp_file("subdomains.txt")
            self.write_lines(subs_file, subdomains)

        self.log.info(f"[Resolver] Resolving {len(subdomains)} hosts via dnsx")

        if not self.runner.which("dnsx"):
            self.log.warning("[Resolver] dnsx not found — using socket fallback")
            await self._socket_fallback(subdomains)
            return

        dns_out = self.temp_file("dns_records.json")

        result = await self.runner.run(
            cmd=[
                "dnsx",
                "-l", str(subs_file),
                "-silent",
                "-a", "-cname", "-mx", "-txt", "-ns",
                "-resp",
                "-json",
                "-o", str(dns_out),
            ],
            timeout=120,
        )
        self.log_result(result)
        self.ctx["dns_records_file"] = dns_out

        # Parse JSON output
        resolved_hosts: dict = {}
        ip_to_hosts: dict = {}
        live_ips: list[str] = []

        source = result.stdout if result.stdout.strip() else (
            dns_out.read_text() if dns_out.exists() else ""
        )

        for line in source.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                entry = json.loads(line)
                host    = entry.get("host", "")
                a_recs  = entry.get("a", []) or []
                cname   = entry.get("cname", []) or []
                mx      = entry.get("mx", []) or []
                txt     = entry.get("txt", []) or []
                ns      = entry.get("ns", []) or []

                resolved_hosts[host] = {
                    "a":     a_recs,
                    "cname": cname,
                    "mx":    mx,
                    "txt":   txt,
                    "ns":    ns,
                }

                for ip in a_recs:
                    if ip not in live_ips:
                        live_ips.append(ip)
                    ip_to_hosts.setdefault(ip, []).append(host)

            except (json.JSONDecodeError, KeyError):
                continue

        self.ctx["resolved_hosts"] = resolved_hosts
        self.ctx["live_ips"]       = live_ips
        self.ctx["ip_to_hosts"]    = ip_to_hosts

        self.log.info(
            f"[Resolver] Resolved {len(resolved_hosts)} hosts, "
            f"{len(live_ips)} unique IPs"
        )

        # Write live IPs for downstream stages
        ips_file = self.temp_file("live_ips.txt")
        self.write_lines(ips_file, live_ips if live_ips else [self.target])
        self.ctx["live_ips_file"] = ips_file

    async def _socket_fallback(self, subdomains: list[str]) -> None:
        """Fallback DNS resolution using Python's socket module."""
        import socket

        resolved_hosts: dict = {}
        live_ips: list[str] = []
        ip_to_hosts: dict = {}

        for host in subdomains[:50]:  # Limit fallback to 50 hosts
            try:
                ips = socket.gethostbyname_ex(host)[2]
                resolved_hosts[host] = {"a": ips, "cname": [], "mx": [], "txt": [], "ns": []}
                for ip in ips:
                    if ip not in live_ips:
                        live_ips.append(ip)
                    ip_to_hosts.setdefault(ip, []).append(host)
            except Exception:
                pass

        self.ctx["resolved_hosts"] = resolved_hosts
        self.ctx["live_ips"]       = live_ips
        self.ctx["ip_to_hosts"]    = ip_to_hosts

        ips_file = self.temp_file("live_ips.txt")
        self.write_lines(ips_file, live_ips if live_ips else [self.target])
        self.ctx["live_ips_file"] = ips_file

        self.log.info(
            f"[Resolver] Socket fallback: {len(resolved_hosts)} hosts, "
            f"{len(live_ips)} IPs"
        )
