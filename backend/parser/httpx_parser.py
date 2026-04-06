"""
PentestBot v2 — HTTPX Parser
Parses httpx JSON output (one JSON object per line).
Extracts live hosts, technologies, status codes, server headers.
"""

import json


class HttpxParser:
    """
    Parses httpx's JSON output into structured web surface data.
    """

    def parse(self, raw_output: str) -> dict:
        if not raw_output or not raw_output.strip():
            return self._empty()

        live_hosts_map: dict[str, dict] = {}
        technologies: set[str] = set()
        web_servers:  set[str] = set()
        status_dist:  dict     = {}

        for line in raw_output.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            url         = entry.get("url", "")
            status      = entry.get("status-code", entry.get("status_code", 0))
            title       = entry.get("title", "") or ""
            tech_list   = entry.get("tech", []) or []
            server      = entry.get("webserver", entry.get("web-server", "")) or ""
            content_len = entry.get("content-length", 0) or 0
            final_url   = entry.get("final-url", url) or url
            ip_candidates = entry.get("a", [])
            ip = entry.get("host", "") or (
                ip_candidates[0] if isinstance(ip_candidates, list) and ip_candidates else ""
            )
            words       = entry.get("words", 0)
            lines_count = entry.get("lines", 0)

            # Collect response headers of interest
            headers = entry.get("headers", {}) or {}
            interesting_headers = {}
            for hname in [
                "x-powered-by", "x-frame-options", "content-security-policy",
                "strict-transport-security", "x-content-type-options",
                "x-xss-protection", "server", "set-cookie",
            ]:
                val = headers.get(hname, "") or headers.get(hname.title(), "")
                if val:
                    interesting_headers[hname] = val

            canonical_url = final_url or url
            if canonical_url:
                existing = live_hosts_map.get(canonical_url)
                current = {
                    "url":              canonical_url,
                    "final_url":        final_url,
                    "status_code":      status,
                    "title":            title.strip()[:120],
                    "technologies":     tech_list,
                    "web_server":       server,
                    "content_length":   content_len,
                    "ip":               ip,
                    "words":            words,
                    "lines":            lines_count,
                    "headers":          interesting_headers,
                }
                if existing is None or self._score_host(current) > self._score_host(existing):
                    live_hosts_map[canonical_url] = current

            for t in tech_list:
                if isinstance(t, str) and t.strip():
                    technologies.add(t.strip())
            if server:
                web_servers.add(server)

            if status:
                status_dist[status] = status_dist.get(status, 0) + 1

        live_hosts = list(live_hosts_map.values())
        live_hosts.sort(key=lambda h: (h["status_code"] == 0, h["status_code"], h["url"]))

        return {
            "live_hosts":          live_hosts,
            "count":               len(live_hosts),
            "technologies":        sorted(technologies),
            "web_servers":         sorted(web_servers),
            "status_distribution": status_dist,
        }

    @staticmethod
    def _score_host(host: dict) -> tuple[int, int, int, int]:
        return (
            1 if host.get("status_code", 0) else 0,
            len(host.get("technologies") or []),
            len(host.get("headers") or {}),
            len(host.get("title") or ""),
        )

    @staticmethod
    def _empty() -> dict:
        return {
            "live_hosts":          [],
            "count":               0,
            "technologies":        [],
            "web_servers":         [],
            "status_distribution": {},
        }
