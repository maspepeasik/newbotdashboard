"""
PentestBot v2 - Vulnerability Scan Stage
Runs Nuclei (template-based) and Nikto (web server checks) in parallel.
"""

import asyncio
from pathlib import Path

from pipeline.base_stage import BaseStage


class VulnScanStage(BaseStage):
    """
    Stage 7: Vulnerability Scanning

    Nuclei: fast template-based scanning across all live endpoints.
    Nikto: deep web server misconfiguration scanning on the primary target.

    Both are run concurrently to save time.
    """

    NAME = "VulnScan"
    MAX_NUCLEI_TARGETS = 4  # Default; overridden by deep mode via ctx
    NIKTO_NOISE_MARKERS = (
        "no cgi directories found",
        "cgi tests skipped",
        "scan terminated:",
        "host(s) tested",
        "start time:",
        "end time:",
        "target ip:",
        "target hostname:",
        "target port:",
        "platform:",
        "server:",
        "multiple ips found:",
        "error:",
        "consider using mitmproxy",
        "cannot test http/3 over quic",
        "uncommon header",
        "allowed http methods",
        "strict-transport-security",
        "x-frame-options",
        "content-security-policy",
    )
    NUCLEI_EXCLUDED_TEMPLATE_IDS = {
        "rdap-whois",
        "dns-waf-detect",
        "dns-caa",
        "dns-ns",
        "dns-mx",
        "dns-soa",
        "ssl-dns-names",
        "ssl-issuer",
        "tls-version",
        "http-missing-security-headers",
    }
    NUCLEI_EXCLUDED_NAME_FRAGMENTS = (
        "rdap whois",
        "ns record",
        "mx record",
        "soa record",
        "caa record",
        "ssl dns names",
        "detect ssl certificate issuer",
        "tls version",
        "http missing security headers",
        "dns waf detection",
    )

    async def run(self) -> None:
        self.clear_stage_error()
        live_urls_file = self.ctx.get("discovered_urls_file") or self.ctx.get("live_urls_file")
        live_hosts = self.ctx.get("live_hosts", [])

        if not live_urls_file or not live_urls_file.exists():
            live_urls_file = self.temp_file("live_urls.txt")
            urls = [host["url"] for host in live_hosts] or self._candidate_urls()
            self.write_lines(live_urls_file, urls)

        primary_url = self._pick_primary_url(live_hosts, live_urls_file)

        self.log.info("[VulnScan] Starting Nuclei + Nikto in parallel")
        self.log.info(f"[VulnScan] Primary URL: {primary_url}")

        # Set dynamic nuclei target count from scan profile
        if self.ctx.get("scan_mode") == "deep":
            from scan_profiles import DEEP_MAX_NUCLEI_TARGETS
            self.ctx["max_nuclei_targets"] = DEEP_MAX_NUCLEI_TARGETS

        nuclei_task = self._run_nuclei(live_urls_file)
        nikto_task = self._run_nikto(primary_url)

        # Conditionally run CMS-specific tools in deep mode when detected
        cms_tasks = []
        if self.ctx.get("scan_mode") == "deep":
            cms_tasks = self._get_cms_scan_tasks(primary_url)

        all_tasks = [nuclei_task, nikto_task] + cms_tasks
        all_results = await asyncio.gather(
            *all_tasks,
            return_exceptions=True,
        )

        nuclei_result = all_results[0]
        nikto_result = all_results[1]

        if isinstance(nuclei_result, Exception):
            self.log.error(f"[VulnScan] Nuclei failed: {nuclei_result}")
            self.add_tool_error(f"nuclei failed: {nuclei_result}")
        if isinstance(nikto_result, Exception):
            self.log.error(f"[VulnScan] Nikto failed: {nikto_result}")
            self.add_tool_error(f"nikto failed: {nikto_result}")

        # Log CMS tool errors
        for i, cms_result in enumerate(all_results[2:]):
            if isinstance(cms_result, Exception):
                self.log.warning(f"[VulnScan] CMS tool {i} failed: {cms_result}")
                self.add_tool_error(f"CMS scan failed: {cms_result}")

        from parser.nuclei_parser import NucleiParser

        parser = NucleiParser()
        nuclei_raw = self.ctx.get("nuclei_raw", "")
        nuclei_parsed = parser.parse(nuclei_raw)
        filtered_nuclei = [
            finding
            for finding in nuclei_parsed.get("findings", [])
            if self._is_reportable_nuclei_finding(finding)
        ]
        self.ctx["nuclei_findings"] = filtered_nuclei
        self.ctx["nuclei_findings_count"] = len(filtered_nuclei)
        self.ctx["nuclei_by_severity"] = nuclei_parsed.get("by_severity", {})

        if self.ctx.get("nuclei_error") and self.ctx.get("nikto_error"):
            self.set_stage_error(
                "Both nuclei and nikto failed; vulnerability coverage is incomplete."
            )

        self.log.info(
            f"[VulnScan] Nuclei: {self.ctx['nuclei_findings_count']} reportable findings | "
            f"Nikto: {len(self.ctx.get('nikto_findings', []))} findings"
        )

    async def _run_nuclei(self, urls_file: Path) -> None:
        if not self.runner.which("nuclei"):
            self.log.warning("[VulnScan] nuclei not found - skipping")
            self.ctx["nuclei_raw"] = ""
            self.ctx["nuclei_error"] = "binary not found"
            self.add_tool_error("nuclei binary not found.")
            return

        templates_arg = self._resolve_nuclei_templates()
        if not templates_arg:
            # Auto-download templates if missing
            self.log.info("[VulnScan] nuclei templates missing — downloading...")
            dl = await self.runner.run(
                cmd=["nuclei", "-update-templates", "-duc"],
                timeout=120,
            )
            if dl.success:
                self.log.info("[VulnScan] nuclei templates downloaded successfully")
            else:
                self.log.warning(f"[VulnScan] nuclei template download failed: {dl.stderr[:200]}")
            templates_arg = self._resolve_nuclei_templates()

        if not templates_arg:
            self.log.warning("[VulnScan] nuclei templates not found - skipping")
            self.ctx["nuclei_raw"] = ""
            self.ctx["nuclei_error"] = "templates not found"
            self.add_tool_error(
                "nuclei templates not found; run `nuclei -update-templates` "
                "or set NUCLEI_TEMPLATES."
            )
            return

        cfg = self.config
        nuclei_urls_file = self._prepare_nuclei_urls(urls_file)
        json_flags = self._nuclei_json_flags()
        base_cmd = [
            "nuclei",
            "-l",
            str(nuclei_urls_file),
            "-silent",
            "-severity",
            cfg.nuclei_severity,
            "-rate-limit",
            str(cfg.nuclei_rate_limit),
            "-c",
            "15",
            "-bulk-size",
            "10",
            "-t",
            templates_arg,
            "-duc",
            "-no-color",
        ]

        result = None
        attempted_flags: list[str] = []
        for json_flag in json_flags:
            attempted_flags.append(json_flag)
            cmd = list(base_cmd)
            cmd.insert(4, json_flag)
            self.log.info(f"[VulnScan] Running nuclei with output flag: {json_flag}")
            result = await self.runner.run(cmd=cmd, timeout=cfg.nuclei_timeout)
            self.log_result(result)
            if result.success:
                break
            self.log.warning(
                f"[VulnScan] nuclei attempt with {json_flag} failed: "
                f"{self._format_tool_error(result)}"
            )
            if result.timed_out:
                break

        assert result is not None
        self.ctx["nuclei_raw"] = result.stdout
        if result.success:
            self.ctx.pop("nuclei_error", None)
            return

        error = self._format_tool_error(result)
        error = f"{error} (tried: {', '.join(attempted_flags)})"
        self.ctx["nuclei_error"] = error
        self.add_tool_error(f"nuclei failed: {error}")
        if result.timed_out:
            self.add_tool_error(
                "nuclei scan timed out; vulnerability coverage may be incomplete."
            )

    async def _run_nikto(self, target_url: str) -> None:
        if not getattr(self.config, "enable_nikto", False):
            self.log.info("[VulnScan] Nikto disabled by configuration")
            self.ctx["nikto_raw"] = ""
            self.ctx["nikto_findings"] = []
            self.ctx["nikto_error"] = "disabled by configuration"
            return

        if not self.runner.which("nikto"):
            self.log.warning("[VulnScan] nikto not found - skipping")
            self.ctx["nikto_raw"] = ""
            self.ctx["nikto_findings"] = []
            self.ctx["nikto_error"] = "binary not found"
            self.add_tool_error("nikto binary not found.")
            return

        host = target_url
        port = "80"
        ssl = False

        if target_url.startswith("https://"):
            host = target_url.replace("https://", "")
            port = "443"
            ssl = True
        elif target_url.startswith("http://"):
            host = target_url.replace("http://", "")

        host = host.rstrip("/").split("/")[0]
        if ":" in host:
            host, port = host.rsplit(":", 1)

        cmd = [
            "nikto",
            "-host",
            host,
            "-port",
            port,
            "-ask",
            "no",
            "-nointeractive",
            "-Tuning",
            "1234578",
        ]
        if ssl:
            cmd.append("-ssl")

        result = await self.runner.run(cmd=cmd, timeout=self.config.nikto_timeout)
        self.log_result(result)

        raw = "\n".join(part for part in (result.stdout, result.stderr) if part).strip()
        self.ctx["nikto_raw"] = raw
        self._parse_nikto(raw)
        if result.success:
            self.ctx.pop("nikto_error", None)
            return

        error = self._format_tool_error(result)
        self.ctx["nikto_error"] = error
        self.add_tool_error(f"nikto failed: {error}")

    def _parse_nikto(self, raw: str) -> None:
        findings = []
        seen: set[str] = set()
        for line in raw.splitlines():
            line = line.strip()
            if not line.startswith("+ "):
                continue
            content = line[2:].strip()
            if not content or "No web server found" in content:
                continue

            severity = "info"
            lowered = content.lower()
            if any(marker in lowered for marker in self.NIKTO_NOISE_MARKERS):
                continue
            if any(token in lowered for token in [
                "vuln",
                "xss",
                "sql inject",
                "rce",
                "remote code",
                "cve-",
                "command injection",
                "path traversal",
                "file disclosure",
            ]):
                severity = "medium"
            if any(token in lowered for token in [
                "critical",
                "arbitrary",
                "remote code execution",
                "authentication bypass",
                "sql injection",
            ]):
                severity = "high"
            if severity == "info":
                continue
            if content in seen:
                continue
            seen.add(content)

            findings.append({
                "description": content,
                "severity": severity,
                "source": "nikto",
            })
        self.ctx["nikto_findings"] = findings

    def _is_reportable_nuclei_finding(self, finding: dict) -> bool:
        severity = str(finding.get("severity", "info")).lower()
        if severity not in {"critical", "high", "medium"}:
            return False

        template_id = str(finding.get("template_id", "")).strip().lower()
        if template_id in self.NUCLEI_EXCLUDED_TEMPLATE_IDS:
            return False

        name = str(finding.get("name", "")).strip().lower()
        if any(fragment in name for fragment in self.NUCLEI_EXCLUDED_NAME_FRAGMENTS):
            return False

        description = str(finding.get("description", "")).strip().lower()
        if any(
            marker in description
            for marker in (
                "registration data access protocol",
                "an ns record was detected",
                "an mx record was detected",
                "a caa record was discovered",
                "extract the issuer",
                "subject alternative name",
                "tls version detection",
            )
        ):
            return False

        return True

    def _get_cms_scan_tasks(self, primary_url: str) -> list:
        """Return WPScan/Joomscan tasks if fingerprinting detected the relevant CMS."""
        tasks = []
        technologies = [t.lower() for t in self.ctx.get("technologies", [])]
        fingerprint_techs = [t.lower() for t in self.ctx.get("fingerprint_technologies", [])]
        all_techs = technologies + fingerprint_techs

        if any("wordpress" in t for t in all_techs):
            self.log.info("[VulnScan] WordPress detected — queueing WPScan")
            tasks.append(self._run_wpscan(primary_url))

        if any("joomla" in t for t in all_techs):
            self.log.info("[VulnScan] Joomla detected — queueing Joomscan")
            tasks.append(self._run_joomscan(primary_url))

        return tasks

    async def _run_wpscan(self, target_url: str) -> None:
        """Run WPScan for WordPress-specific vulnerability detection."""
        if not self.runner.which("wpscan"):
            self.log.warning("[VulnScan] wpscan not found - skipping")
            self.add_tool_error("wpscan binary not found.")
            return

        cmd = [
            "wpscan",
            "--url", target_url,
            "--no-banner",
            "--random-user-agent",
            "--format", "cli",
        ]
        result = await self.runner.run(cmd=cmd, timeout=self.config.wpscan_timeout)
        self.log_result(result)

        if result.stdout:
            self.log.info(f"[VulnScan] WPScan complete ({len(result.stdout)} bytes)")

    async def _run_joomscan(self, target_url: str) -> None:
        """Run Joomscan for Joomla-specific vulnerability detection."""
        if not self.runner.which("joomscan"):
            self.log.warning("[VulnScan] joomscan not found - skipping")
            self.add_tool_error("joomscan binary not found.")
            return

        cmd = ["joomscan", "-u", target_url]
        result = await self.runner.run(cmd=cmd, timeout=self.config.joomscan_timeout)
        self.log_result(result)

        if result.stdout:
            self.log.info(f"[VulnScan] Joomscan complete ({len(result.stdout)} bytes)")

    def _pick_primary_url(self, live_hosts: list[dict], live_urls_file: Path) -> str:
        if live_hosts:
            return live_hosts[0]["url"]

        urls = self.read_lines(live_urls_file)
        if urls:
            return urls[0]

        return self._candidate_urls()[0]

    @staticmethod
    def _dir_has_templates(path: Path) -> bool:
        """Return True only if the directory exists AND contains .yaml files."""
        if not path.is_dir():
            return False
        # Quick check: look for at least one .yaml file (recurse one level)
        try:
            return any(path.rglob("*.yaml"))
        except (OSError, StopIteration):
            return False

    def _resolve_nuclei_templates(self) -> str | None:
        configured = str(self.config.nuclei_templates or "").strip()
        if configured:
            paths = [
                Path(part.strip()).expanduser()
                for part in configured.split(",")
                if part.strip()
            ]
            if paths and all(self._dir_has_templates(p) for p in paths):
                return configured
            # Directory exists but is empty — fall through to common dirs

        common_dirs = [
            Path.home() / "nuclei-templates",
            Path.home() / ".nuclei-templates",
            Path.home() / ".local" / "nuclei-templates",
            Path.home() / ".local" / "share" / "nuclei-templates",
            Path.home() / ".config" / "nuclei" / "templates",
            Path("/home/ubuntu/nuclei-templates"),
            Path("/home/ubuntu/.nuclei-templates"),
            Path("/home/ubuntu/.local/nuclei-templates"),
            Path("/home/ubuntu/.local/share/nuclei-templates"),
            Path("/usr/local/share/nuclei-templates"),
            Path("/opt/nuclei-templates"),
        ]
        for candidate in common_dirs:
            if self._dir_has_templates(candidate):
                return str(candidate)
        return None

    def _prepare_nuclei_urls(self, urls_file: Path) -> Path:
        urls = self.read_lines(urls_file)
        selected = self._select_nuclei_urls(urls)
        out_file = self.temp_file("nuclei_urls.txt")
        self.write_lines(out_file, selected)
        self.log.info(
            f"[VulnScan] Nuclei target set reduced to {len(selected)} URL(s)"
        )
        return out_file

    def _select_nuclei_urls(self, urls: list[str]) -> list[str]:
        if not urls:
            max_targets = self.ctx.get("max_nuclei_targets", self.MAX_NUCLEI_TARGETS)
            return self._candidate_urls()[:max_targets]

        def score(url: str) -> tuple[int, int, int, str]:
            normalized = url.lower()
            host = normalized.split("://", 1)[-1].split("/", 1)[0]
            hostname = host.split(":", 1)[0]
            is_root = 0 if hostname == self.target else 1
            is_subdomain = 0 if hostname.endswith(f".{self.target}") else 1
            is_https = 0 if normalized.startswith("https://") else 1
            return (is_root, is_subdomain, is_https, normalized)

        ordered = sorted(dict.fromkeys(urls), key=score)
        max_targets = self.ctx.get("max_nuclei_targets", self.MAX_NUCLEI_TARGETS)
        return ordered[:max_targets]

    def _candidate_urls(self) -> list[str]:
        port_list = self.ctx.get("port_list", [80, 443])
        urls: list[str] = []

        if 443 in port_list:
            urls.append(f"https://{self.target}")
        if 80 in port_list:
            urls.append(f"http://{self.target}")

        for port in port_list:
            if port in {80, 443}:
                continue
            if port in {4443, 8443, 9443}:
                urls.append(f"https://{self.target}:{port}")
            elif port in {3000, 5000, 8000, 8080, 8888, 9000, 9090}:
                urls.append(f"http://{self.target}:{port}")

        if not urls:
            urls = [f"https://{self.target}", f"http://{self.target}"]

        seen: set[str] = set()
        deduped: list[str] = []
        for url in urls:
            if url not in seen:
                seen.add(url)
                deduped.append(url)
        return deduped[:20]

    def _nuclei_json_flags(self) -> list[str]:
        # Nuclei v3 uses -jsonl for JSON Lines output.
        # Fallback to -je (JSON Events) which also works in v3.
        # Note: -json is a v2 flag and does NOT exist in v3.
        return ["-jsonl", "-je"]

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
