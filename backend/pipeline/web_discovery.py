"""
PentestBot v2 - Web Discovery Stage
Expands the web attack surface using passive URL sources and focused crawling.
"""

from __future__ import annotations
import asyncio
from urllib.parse import urlparse

from pipeline.base_stage import BaseStage


class WebDiscoveryStage(BaseStage):
    """
    Stage 7: Web Discovery

    Collects additional URLs from:
      - gau (historical passive URL discovery)
      - katana (focused crawling from already live URLs)

    The output is intentionally capped and filtered to stay within the target's
    web scope and to avoid turning passive observations into noisy findings.
    """

    NAME = "WebDiscovery"

    async def run(self) -> None:
        self.clear_stage_error()

        live_hosts = self.ctx.get("live_hosts", [])
        seed_urls = [host.get("url", "") for host in live_hosts if host.get("url")]
        if not seed_urls:
            self.ctx["discovered_urls"] = []
            self.log.info("[WebDiscovery] No live web hosts to expand.")
            return

        if not getattr(self.config, "enable_web_discovery", True):
            self.ctx["discovered_urls"] = list(dict.fromkeys(seed_urls))
            self.log.info("[WebDiscovery] Disabled by configuration.")
            return

        discovered: list[str] = []
        discovered.extend(seed_urls)
        discovered.extend(await self._run_gau())
        discovered.extend(await self._run_katana(seed_urls))

        filtered = self._normalize_urls(discovered)
        self.ctx["discovered_urls"] = filtered

        urls_file = self.temp_file("discovered_urls.txt")
        self.write_lines(urls_file, filtered or seed_urls)
        self.ctx["discovered_urls_file"] = urls_file

        self.log.info(
            f"[WebDiscovery] Retained {len(filtered)} scoped URL(s) "
            f"from {len(discovered)} candidate(s)"
        )

    async def _run_gau(self) -> list[str]:
        if not self.runner.which("gau"):
            self.add_tool_error("gau not found; skipped passive URL discovery.")
            return []

        result = await self.runner.run(
            cmd=["gau", "--subs", self.target],
            timeout=self.config.gau_timeout,
        )
        self.log_result(result)
        if not result.success and not result.stdout:
            self.add_tool_error(
                f"gau failed: {self._format_tool_error(result)}"
            )
            return []
        return self._extract_urls(result.stdout)

    async def _run_katana(self, seed_urls: list[str]) -> list[str]:
        if not self.runner.which("katana"):
            self.add_tool_error("katana not found; skipped focused crawling.")
            return []

        seed_file = self.temp_file("web_discovery_seeds.txt")
        self.write_lines(seed_file, seed_urls[:20])

        cmd = [
            "katana",
            "-list",
            str(seed_file),
            "-silent",
            "-d",
            str(self.config.katana_depth),
            "-jc",
        ]
        result = await self.runner.run(cmd=cmd, timeout=self.config.katana_timeout)
        if not result.success and "flag provided but not defined" in result.stderr.lower():
            cmd = [
                "katana",
                "-list",
                str(seed_file),
                "-silent",
                "-d",
                str(self.config.katana_depth),
            ]
            result = await self.runner.run(cmd=cmd, timeout=self.config.katana_timeout)
        self.log_result(result)
        if not result.success and not result.stdout:
            self.add_tool_error(
                f"katana failed: {self._format_tool_error(result)}"
            )
            return []
        return self._extract_urls(result.stdout)

    def _normalize_urls(self, raw_urls: list[str]) -> list[str]:
        seen: set[str] = set()
        normalized: list[str] = []
        max_urls = max(20, int(getattr(self.config, "max_discovered_urls", 150)))

        for candidate in raw_urls:
            parsed = urlparse(str(candidate).strip())
            if parsed.scheme not in {"http", "https"}:
                continue
            host = (parsed.hostname or "").lower()
            if not host:
                continue
            if host != self.target and not host.endswith(f".{self.target}"):
                continue

            # Prefer path-bearing URLs and parameterized endpoints first.
            cleaned = parsed._replace(fragment="").geturl().rstrip("/")
            if cleaned in seen:
                continue
            seen.add(cleaned)
            normalized.append(cleaned)

        normalized.sort(key=self._url_priority)
        return normalized[:max_urls]

    @staticmethod
    def _extract_urls(raw: str) -> list[str]:
        return [
            line.strip()
            for line in raw.splitlines()
            if line.strip().startswith(("http://", "https://"))
        ]

    @staticmethod
    def _url_priority(url: str) -> tuple[int, int, int, str]:
        parsed = urlparse(url)
        has_query = 0 if parsed.query else 1
        path_depth = -len([part for part in parsed.path.split("/") if part])
        is_root = 1 if parsed.path in {"", "/"} else 0
        return (has_query, is_root, path_depth, url)

    @staticmethod
    def _format_tool_error(result) -> str:
        details = result.stderr.strip()
        if not details:
            stdout_snippet = result.stdout.strip().replace("\n", " ")
            if stdout_snippet:
                details = stdout_snippet[:200]
        if not details:
            details = f"return code {result.returncode}"
        return details
