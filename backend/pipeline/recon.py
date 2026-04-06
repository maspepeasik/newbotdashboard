"""
PentestBot v2 — Recon Stage
Passive + active subdomain enumeration using:
  - subfinder  (multi-source passive)
  - assetfinder (certificate transparency + APIs)
  - anew       (deduplication)
"""

import asyncio
from pathlib import Path

from pipeline.base_stage import BaseStage


class ReconStage(BaseStage):
    """
    Stage 1: Subdomain Discovery

    Uses subfinder and assetfinder in parallel, then pipes
    both outputs through `anew` to produce a clean, deduplicated list.
    Populates ctx['subdomains'] with the result.
    """

    NAME = "Recon"

    async def run(self) -> None:
        self.log.info(f"[Recon] Starting subdomain discovery for {self.target}")

        # Run subfinder, assetfinder (and optionally Amass) in parallel
        tasks = [self._run_subfinder(), self._run_assetfinder()]

        if getattr(self.config, "enable_amass", False):
            self.log.info("[Recon] Amass enabled — adding to discovery pipeline")
            tasks.append(self._run_amass())

        results = await asyncio.gather(*tasks)

        all_raw: list[str] = []
        for result_list in results:
            all_raw.extend(result_list)

        # Merge + deduplicate with anew
        deduped = await self._deduplicate(all_raw)

        # Always include the root target itself
        if self.target not in deduped:
            deduped.insert(0, self.target)

        self.ctx["subdomains"] = deduped
        subs_file = self.temp_file("subdomains.txt")
        self.write_lines(subs_file, deduped)
        self.ctx["subdomains_file"] = subs_file

        self.log.info(
            f"[Recon] Done: {len(deduped)} unique subdomains discovered."
        )

    async def _run_subfinder(self) -> list[str]:
        """Run subfinder for passive subdomain discovery."""
        if not self.runner.which("subfinder"):
            self.log.warning("[Recon] subfinder not found, skipping.")
            return []

        result = await self.runner.run(
            cmd=[
                "subfinder",
                "-d", self.target,
                "-silent",
                "-t", str(self.config.subfinder_threads),
                "-timeout", str(self.config.subfinder_timeout),
                "-all",   # Use all sources
            ],
            timeout=self.config.subfinder_timeout + 30,
        )
        self.log_result(result)
        if not result.stdout:
            return []
        return [
            line.strip()
            for line in result.stdout.splitlines()
            if line.strip() and "." in line
        ]

    async def _run_assetfinder(self) -> list[str]:
        """Run assetfinder for certificate transparency lookups."""
        if not self.runner.which("assetfinder"):
            self.log.warning("[Recon] assetfinder not found, skipping.")
            return []

        result = await self.runner.run(
            cmd=["assetfinder", "--subs-only", self.target],
            timeout=self.config.assetfinder_timeout,
        )
        self.log_result(result)
        if not result.stdout:
            return []
        return [
            line.strip()
            for line in result.stdout.splitlines()
            if line.strip() and self.target in line
        ]

    async def _run_amass(self) -> list[str]:
        """Run Amass for comprehensive subdomain enumeration (optional, heavy)."""
        if not self.runner.which("amass"):
            self.log.warning("[Recon] amass not found, skipping.")
            self.add_tool_error("amass binary not found.")
            return []

        amass_timeout = getattr(self.config, "amass_timeout", 300)
        result = await self.runner.run(
            cmd=[
                "amass", "enum",
                "-passive",
                "-d", self.target,
                "-timeout", str(amass_timeout // 60),  # amass uses minutes
            ],
            timeout=amass_timeout + 30,
        )
        self.log_result(result)
        if not result.stdout:
            return []
        return [
            line.strip()
            for line in result.stdout.splitlines()
            if line.strip() and "." in line
        ]

    async def _deduplicate(self, items: list[str]) -> list[str]:
        """
        Use `anew` for deduplication if available,
        otherwise fall back to a Python set.
        """
        if not items:
            return []

        if self.runner.which("anew"):
            # anew reads from stdin and only outputs new (unique) lines
            raw_input = "\n".join(items)
            anew_file = self.temp_file("anew_seen.txt")
            result = await self.runner.run(
                cmd=["anew", str(anew_file)],
                stdin_data=raw_input,
                timeout=30,
            )
            if result.success and result.stdout:
                return [
                    line.strip()
                    for line in result.stdout.splitlines()
                    if line.strip()
                ]

        # Python fallback deduplication (order-preserving)
        seen: set[str] = set()
        out: list[str] = []
        for item in items:
            if item not in seen:
                seen.add(item)
                out.append(item)
        return out
