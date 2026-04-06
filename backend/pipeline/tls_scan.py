import json
from urllib.parse import urlparse

from pipeline.base_stage import BaseStage


class TLSScanStage(BaseStage):

    NAME = "TLSScan"

    async def run(self) -> None:
        tls_targets = self._candidate_tls_targets()
        tls_target = tls_targets[0]
        self.ctx["tls_target"] = tls_target
        self.log.info(f"[TLSScan] Analyzing TLS on {tls_target}")

        if self.runner.which("testssl.sh"):
            successful_target = None
            for candidate in tls_targets:
                self.ctx["tls_target"] = candidate
                self.log.info(f"[TLSScan] Trying TLS target {candidate}")
                if await self._run_testssl(candidate):
                    successful_target = candidate
                    break

            if successful_target and self.runner.which("python") and getattr(self.config, "enable_sslyze", True):
                await self._run_sslyze(successful_target)
            elif self.runner.which("openssl"):
                await self._openssl_fallback()
        else:
            self.log.warning("[TLSScan] No TLS scanner available")
            self._empty_result()

    async def handle_timeout(self) -> None:
        error = f"testssl.sh timed out after {self.config.testssl_timeout}s"
        self.ctx["tls_error"] = error
        self.add_tool_error(error)
        self.ctx.setdefault("limitations", []).append(error)
        self.log.warning(f"[TLSScan] {error}")

        if self.runner.which("openssl"):
            self.log.warning("[TLSScan] Falling back to openssl certificate probe after timeout")
            await self._openssl_fallback()
        else:
            self._empty_result()
            self.set_stage_error("TLS analysis timed out and no openssl fallback is available.")

    async def _run_testssl(self, tls_target: str) -> bool:

        json_out = self.temp_file("testssl_output.json")

        result = await self.runner.run(
            cmd=[
                "testssl.sh",
                "--quiet",
                "--jsonfile", str(json_out),
                "--severity", "LOW",
                "--fast",
                "--sneaky",
                tls_target,
            ],
            timeout=self.config.testssl_timeout,
        )

        self.ctx["tls_raw"] = result.stdout

        raw_json = None

        if json_out.exists():
            try:
                raw_json = json.loads(json_out.read_text())
            except Exception:
                pass

        if raw_json:
            self.ctx["tls_json"] = raw_json
            self._parse_testssl_json(raw_json)
        else:
            self._parse_testssl_text(result.stdout)

        parsed_output_available = bool(raw_json) or bool(self.ctx.get("tls_findings")) or bool(self.ctx.get("cert_info"))

        if result.success:
            self.log_result(result)
            self.ctx.pop("tls_error", None)
            return True

        if parsed_output_available:
            note = result.stderr.strip() or f"return code {result.returncode}"
            self.log.info(f"[TLSScan] testssl.sh produced usable output ({note})")
            self.ctx["tls_partial_error"] = note
            self.ctx.setdefault("limitations", []).append(
                f"TLS analysis used partial testssl.sh output: {note}"
            )
            self.ctx.pop("tls_error", None)
            return True

        self.log_result(result)
        error = result.stderr.strip() or f"return code {result.returncode}"
        self.ctx["tls_error"] = error
        self.add_tool_error(f"testssl.sh failed: {error}")
        self.ctx.setdefault("limitations", []).append(f"TLS analysis failed: {error}")

        if self.runner.which("openssl"):
            self.log.warning("[TLSScan] Falling back to openssl certificate probe")
            await self._openssl_fallback()
        else:
            self.set_stage_error("TLS analysis failed and no openssl fallback is available.")
        return False

    def _parse_testssl_json(self, data):
        findings = []
        cert_info = {}
        for item in self._flatten_testssl_items(data):
            item_id = str(item.get("id", "")).lower()
            finding = str(item.get("finding", "")).strip()
            severity = str(item.get("severity", "INFO")).upper()

            cert_field = self._certificate_field(item_id)
            if cert_field and finding:
                cert_info[cert_field] = finding
                continue

            if item_id.startswith("cert_") and finding:
                cert_info[item_id.removeprefix("cert_")] = finding
                continue

            if item_id in {"scan_time", "target"}:
                continue
            if severity in {"OK", "INFO"}:
                continue
            if "not vulnerable" in finding.lower():
                continue
            if not finding:
                continue
            if self._is_inconclusive_finding(item_id, finding):
                # Log inconclusive checks but don't add non-actionable ones as limitations
                check_name = item.get('id', item_id)
                if not self._is_ignorable_inconclusive(item_id):
                    self.ctx.setdefault("limitations", []).append(
                        f"TLS check '{check_name}' was inconclusive: {finding}"
                    )
                continue

            findings.append(self._normalize_finding(item))

        self.ctx["tls_findings"] = findings
        self.ctx["cert_info"] = cert_info

        self.log.info(f"[TLSScan] {len(findings)} TLS findings")

    def _flatten_testssl_items(self, data) -> list[dict]:
        if isinstance(data, list):
            if all(isinstance(item, dict) and "id" in item for item in data):
                return [item for item in data if isinstance(item, dict)]
            out = []
            for item in data:
                out.extend(self._flatten_testssl_items(item))
            return out

        if not isinstance(data, dict):
            return []

        if "scanResult" in data:
            out = []
            for block in data.get("scanResult", []):
                if not isinstance(block, dict):
                    continue
                for key in ("serverDefaults", "protocols", "vulnerabilities", "certificate", "cipherTests"):
                    values = block.get(key, [])
                    if isinstance(values, list):
                        out.extend(item for item in values if isinstance(item, dict))
            return out

        return [data] if "id" in data else []

    @staticmethod
    def _certificate_field(item_id: str) -> str | None:
        mapping = {
            "cert_subject": "subject",
            "cert_issuer": "issuer",
            "cert_serialnumber": "serial_number",
            "cert_notbefore": "not_before",
            "cert_notafter": "not_after",
            "cert_keysize": "key_size",
            "cert_keyalg": "key_algorithm",
            "cert_sigalg": "signature_algorithm",
            "cert_san": "subject_alt_names",
            "cert_commonname": "common_name",
        }
        return mapping.get(item_id)

    def _parse_testssl_text(self, raw):

        findings = []

        for line in raw.splitlines():

            line = line.strip().lower()

            if any(marker in line for marker in ("not tested", "stalled", "terminated")):
                self.ctx.setdefault("limitations", []).append(
                    f"TLS text output was inconclusive: {line}"
                )
                continue

            if "vulnerable" in line or "critical" in line or "high" in line:
                findings.append({
                    "id": "tls_text",
                    "description": line,
                    "severity": "medium",
                    "source": "testssl.sh"
                })

        self.ctx["tls_findings"] = findings
        self.ctx["cert_info"] = {}

    async def _openssl_fallback(self):
        tls_target = self.ctx.get("tls_target", f"{self.target}:443")

        result = await self.runner.run(
            cmd=["openssl", "s_client", "-connect", str(tls_target)],
            timeout=30,
        )

        self.ctx["tls_raw"] = "\n".join(
            part for part in (result.stdout, result.stderr) if part
        ).strip()
        self.ctx["tls_findings"] = []
        self.ctx["cert_info"] = self._extract_cert_info(self.ctx["tls_raw"])

        if result.success:
            self.ctx.pop("tls_error", None)
            return

        error = result.stderr.strip() or f"return code {result.returncode}"
        self.ctx["tls_error"] = error
        self.set_stage_error(f"openssl TLS fallback failed: {error}")

    def _empty_result(self):

        self.ctx["tls_raw"] = ""
        self.ctx["tls_findings"] = []
        self.ctx["cert_info"] = {}

    @staticmethod
    def _extract_cert_info(raw: str) -> dict:
        cert_info: dict[str, str] = {}
        for line in raw.splitlines():
            stripped = line.strip()
            lowered = stripped.lower()
            if lowered.startswith("subject="):
                cert_info["subject"] = stripped.split("=", 1)[1].strip()
            elif lowered.startswith("issuer="):
                cert_info["issuer"] = stripped.split("=", 1)[1].strip()
            elif "notbefore=" in lowered:
                cert_info["not_before"] = stripped.split("=", 1)[1].strip()
            elif "notafter=" in lowered:
                cert_info["not_after"] = stripped.split("=", 1)[1].strip()
        return cert_info

    @staticmethod
    def _normalize_finding(item):
        return {
            "id": item.get("id", ""),
            "description": item.get("finding", ""),
            "severity": item.get("severity", "info").lower(),
            "source": "testssl.sh",
        }

    async def _run_sslyze(self, tls_target: str) -> None:
        result = await self.runner.run(
            cmd=[
                "python",
                "-m",
                "sslyze",
                "--json_out=-",
                tls_target,
            ],
            timeout=self.config.sslyze_timeout,
        )

        if not result.success and not result.stdout:
            self.ctx.setdefault("limitations", []).append(
                f"SSLyze unavailable or failed: {result.stderr.strip() or result.returncode}"
            )
            return

        if "server_scan_results" not in result.stdout:
            return

        self.log.info("[TLSScan] SSLyze completed as a secondary TLS validation source")

    def _candidate_tls_targets(self) -> list[str]:
        live_hosts = self.ctx.get("live_hosts", [])
        candidates: list[tuple[int, int, str]] = []

        for host in live_hosts:
            url = str(host.get("url", "")).strip()
            if not url.lower().startswith("https://"):
                continue
            parsed = urlparse(url)
            hostname = (parsed.hostname or "").strip()
            if not hostname:
                continue
            port = parsed.port or 443
            target = f"{hostname}:{port}"
            priority = self._tls_target_priority(hostname, port)
            quality = self._tls_host_quality(host)
            candidates.append((priority, quality, target))

        if not candidates:
            candidates.append((self._tls_target_priority(self.target, 443), 0, f"{self.target}:443"))
        else:
            candidates.append((99, 0, f"{self.target}:443"))

        ordered = [
            target
            for _, _, target in sorted(candidates, key=lambda item: (item[0], -item[1], item[2]))
        ]

        seen: set[str] = set()
        deduped: list[str] = []
        for target in ordered:
            if target in seen:
                continue
            seen.add(target)
            deduped.append(target)
        return deduped[:5] or [f"{self.target}:443"]

    def _tls_target_priority(self, hostname: str, port: int) -> int:
        host = hostname.lower()
        target = self.target.lower()
        if host == target and port == 443:
            return 0
        if host == target:
            return 1
        if host.endswith(f".{target}") and port == 443:
            return 2
        if host.endswith(f".{target}"):
            return 3
        return 4

    @staticmethod
    def _tls_host_quality(host: dict) -> int:
        status = int(host.get("status_code", 0) or 0)
        headers = host.get("headers") or {}
        has_hsts = 1 if "strict-transport-security" in {str(key).lower() for key in headers.keys()} else 0
        return (
            (1000 if status == 200 else 0)
            + (500 if 200 <= status < 400 else 0)
            + (100 if has_hsts else 0)
            + len(str(host.get("title", "") or ""))
        )

    @staticmethod
    def _is_inconclusive_finding(item_id: str, finding: str) -> bool:
        text = f"{item_id} {finding}".lower()
        return any(
            marker in text
            for marker in (
                "not tested",
                "terminated",
                "stalled",
                "timed out",
                "inconclusive",
                " --",
                "test failed",
            )
        )
    @staticmethod
    def _is_ignorable_inconclusive(item_id: str) -> bool:
        """Return True for inconclusive checks that are not actionable."""
        ignorable = {
            "quic", "dns_caarecord", "dns_caa", "ipv6",
            "rp_banner", "trust", "caa_rr",
        }
        return item_id.lower() in ignorable
