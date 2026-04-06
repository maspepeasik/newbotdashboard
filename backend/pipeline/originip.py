"""
PentestBot v2 — Origin IP Stage
Multi-method real IP discovery:
  1. Direct DNS resolution
  2. crt.sh certificate transparency search
  3. HackerTarget DNS history
  4. Common bypass subdomain probing
  5. SecurityTrails-style lookup via curl
"""

import asyncio
import ipaddress
import json
import re
import socket
from pipeline.base_stage import BaseStage


_CDN_SIGNATURES = [
    "cloudflare", "akamai", "fastly", "cloudfront", "incapsula",
    "sucuri", "stackpath", "imperva", "arbor", "ddos-guard",
    "azure", "amazonaws", "googleusercontent", "edgecastcdn",
]

_KNOWN_CDN_NETWORKS = tuple(
    ipaddress.ip_network(cidr) for cidr in (
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
        "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
        "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
        "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
        "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    )
)

_BYPASS_PREFIXES = [
    "direct", "origin", "real", "backend", "www2",
    "mail", "ftp", "cpanel", "webmail", "dev", "staging",
]


def _is_cdn(ptr: str) -> bool:
    ptr_lower = ptr.lower()
    return any(sig in ptr_lower for sig in _CDN_SIGNATURES)


def _is_known_cdn_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in network for network in _KNOWN_CDN_NETWORKS)


class OriginIPStage(BaseStage):
    """
    Stage 3: Origin IP Discovery

    Tries multiple techniques to find the real server IP
    behind CDN/WAF proxies.

    Populates:
      ctx['origin_data'] → dict with all discovered IP data
      ctx['cdn_detected'] → bool
      ctx['origin_candidates'] → list[str] of likely real IPs
    """

    NAME = "OriginIP"

    async def run(self) -> None:
        self.log.info(f"[OriginIP] Probing origin IP for {self.target}")

        discovered: dict[str, dict] = {}  # ip → {method, ptr, is_cdn}

        # Run all methods concurrently
        results = await asyncio.gather(
            self._method_direct_dns(),
            self._method_crtsh(),
            self._method_hackertarget(),
            self._method_bypass_subs(),
            return_exceptions=True,
        )

        for result in results:
            if isinstance(result, dict):
                for ip, info in result.items():
                    if ip not in discovered:
                        discovered[ip] = info
                    else:
                        # Merge evidence
                        discovered[ip]["methods"] = (
                            discovered[ip].get("methods", []) + info.get("methods", [])
                        )

        # Enrich with PTR records and CDN classification
        for ip, info in discovered.items():
            ptr = info.get("ptr", "")
            if not ptr:
                try:
                    ptr = socket.gethostbyaddr(ip)[0]
                except Exception:
                    ptr = ""
            info["ptr"] = ptr
            info["is_cdn"] = _is_cdn(ptr) or _is_known_cdn_ip(ip)

        cdn_ips = [ip for ip, d in discovered.items() if d.get("is_cdn")]
        origin_candidates = [ip for ip, d in discovered.items() if not d.get("is_cdn")]

        self.ctx["origin_data"] = {
            "all_ips": list(discovered.keys()),
            "details": discovered,
            "cdn_ips": cdn_ips,
            "origin_candidates": origin_candidates,
        }
        self.ctx["cdn_detected"]      = len(cdn_ips) > 0
        self.ctx["origin_candidates"] = origin_candidates

        self.log.info(
            f"[OriginIP] Found {len(discovered)} IPs total. "
            f"CDN: {cdn_ips}, Origin: {origin_candidates}"
        )

    async def _method_direct_dns(self) -> dict:
        out = {}
        try:
            ips = socket.gethostbyname_ex(self.target)[2]
            for ip in ips:
                out[ip] = {"methods": ["direct_dns"], "ptr": "", "is_cdn": False}
        except Exception:
            pass
        return out

    async def _method_crtsh(self) -> dict:
        """Query crt.sh for historical certificate IPs."""
        out = {}
        if not self.runner.which("curl"):
            return out
        result = await self.runner.run(
            cmd=[
                "curl", "-s", "--max-time", "15",
                f"https://crt.sh/?q=%25.{self.target}&output=json",
            ],
            timeout=20,
        )
        if not result.success or not result.stdout:
            return out
        try:
            entries = json.loads(result.stdout)
            for entry in entries[:100]:
                name_value = entry.get("name_value", "")
                for part in name_value.split("\n"):
                    part = part.strip().lstrip("*.")
                    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', part):
                        out[part] = {"methods": ["crt_sh"], "ptr": "", "is_cdn": False}
        except (json.JSONDecodeError, Exception):
            # Try regex fallback
            ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', result.stdout)
            for ip in ips:
                if not ip.startswith(("0.", "255.", "127.")):
                    out[ip] = {"methods": ["crt_sh_regex"], "ptr": "", "is_cdn": False}
        return out

    async def _method_hackertarget(self) -> dict:
        """Query HackerTarget DNS history API."""
        out = {}
        if not self.runner.which("curl"):
            return out
        result = await self.runner.run(
            cmd=[
                "curl", "-s", "--max-time", "10",
                f"https://api.hackertarget.com/hostsearch/?q={self.target}",
            ],
            timeout=15,
        )
        if not result.success or not result.stdout:
            return out
        for line in result.stdout.splitlines():
            parts = line.split(",")
            if len(parts) == 2:
                ip = parts[1].strip()
                if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', ip):
                    out[ip] = {"methods": ["hackertarget"], "ptr": "", "is_cdn": False}
        return out

    async def _method_bypass_subs(self) -> dict:
        """Probe subdomains that commonly bypass CDN."""
        out = {}
        targets = [
            f"{prefix}.{self.target}"
            for prefix in _BYPASS_PREFIXES
        ]

        async def probe(host: str) -> None:
            try:
                ip = socket.gethostbyname(host)
                out[ip] = {
                    "methods": [f"bypass_subdomain:{host}"],
                    "ptr": "",
                    "is_cdn": False,
                }
            except Exception:
                pass

        await asyncio.gather(*[probe(t) for t in targets])
        return out
