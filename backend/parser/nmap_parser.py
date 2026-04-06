"""
PentestBot v2 — Nmap Parser
Parses nmap XML (-oX) and grepable (-oG) output formats.
Extracts services, versions, OS matches, and NSE script results.
"""

import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional


class NmapParser:
    """
    Comprehensive nmap output parser.
    Prefers XML parsing (most accurate); falls back to grepable text.
    """

    def parse(
        self,
        xml_path: Optional[Path] = None,
        grep_output: Optional[str] = None,
    ) -> dict:
        """Parse nmap output. XML is preferred over grep format."""
        if xml_path and xml_path.exists():
            try:
                return self._parse_xml(xml_path)
            except ET.ParseError:
                pass

        if grep_output:
            return self._parse_grep(grep_output)

        return self._empty()

    # ── XML Parser ────────────────────────────────────────────────────────

    def _parse_xml(self, xml_path: Path) -> dict:
        tree = ET.parse(str(xml_path))
        root = tree.getroot()

        hosts     = []
        services  = []
        os_matches = []
        script_results: dict[str, list] = {}

        for host_el in root.findall(".//host"):
            status = host_el.find("status")
            if status is None or status.get("state") != "up":
                continue

            # IP address
            addr_el = host_el.find("address[@addrtype='ipv4']")
            if addr_el is None:
                addr_el = host_el.find("address[@addrtype='ipv6']")
            ip = addr_el.get("addr", "") if addr_el is not None else ""

            # Hostname
            hostname_el = host_el.find(".//hostname[@type='PTR']")
            if hostname_el is None:
                hostname_el = host_el.find(".//hostname")
            hostname = hostname_el.get("name", "") if hostname_el is not None else ""

            hosts.append({"ip": ip, "hostname": hostname})

            # OS detection
            for osmatch in host_el.findall(".//osmatch"):
                os_matches.append({
                    "name":     osmatch.get("name", ""),
                    "accuracy": int(osmatch.get("accuracy", 0)),
                    "host":     ip,
                })

            # Ports and services
            for port_el in host_el.findall(".//port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue

                portid   = int(port_el.get("portid", 0))
                protocol = port_el.get("protocol", "tcp")

                service_el  = port_el.find("service")
                svc_name    = ""
                svc_product = ""
                svc_version = ""
                svc_extra   = ""
                svc_cpe     = []

                if service_el is not None:
                    svc_name    = service_el.get("name", "")
                    svc_product = service_el.get("product", "")
                    svc_version = service_el.get("version", "")
                    svc_extra   = service_el.get("extrainfo", "")
                    svc_cpe     = [
                        cpe.text for cpe in service_el.findall("cpe")
                        if cpe.text
                    ]

                # Full version string
                version_str = " ".join(filter(None, [svc_product, svc_version, svc_extra])).strip()

                services.append({
                    "host":     ip,
                    "port":     portid,
                    "protocol": protocol,
                    "service":  svc_name,
                    "version":  version_str,
                    "cpe":      svc_cpe,
                    "state":    "open",
                })

                # NSE script output
                port_scripts = []
                for script_el in port_el.findall("script"):
                    script_id     = script_el.get("id", "")
                    script_output = script_el.get("output", "").strip()
                    port_scripts.append({
                        "id":     script_id,
                        "output": script_output[:1000],
                    })
                if port_scripts:
                    key = f"{ip}:{portid}"
                    script_results[key] = port_scripts

        # Sort OS matches by accuracy
        os_matches.sort(key=lambda x: x["accuracy"], reverse=True)

        return {
            "hosts":          hosts,
            "services":       services,
            "os_matches":     os_matches[:5],
            "script_results": script_results,
            "service_count":  len(services),
        }

    # ── Grepable Parser ───────────────────────────────────────────────────

    def _parse_grep(self, raw: str) -> dict:
        hosts    = []
        services = []
        seen_ports: set = set()

        current_ip = ""
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Host line: Host: 1.2.3.4 (hostname.com)  Status: Up
            m = re.match(r"Host:\s+(\S+)\s+\(([^)]*)\)", line)
            if m:
                current_ip = m.group(1)
                hostname   = m.group(2)
                hosts.append({"ip": current_ip, "hostname": hostname})

            # Ports: 80/open/tcp//http//Apache httpd 2.4//
            if "Ports:" in line and current_ip:
                ports_section = line.split("Ports:", 1)[1]
                for port_str in ports_section.split(","):
                    port_str = port_str.strip()
                    parts = port_str.split("/")
                    if len(parts) < 7:
                        continue
                    portid   = parts[0].strip()
                    state    = parts[1].strip()
                    protocol = parts[2].strip()
                    service  = parts[4].strip()
                    version  = parts[6].strip()

                    if state == "open" and portid.isdigit():
                        key = (current_ip, int(portid))
                        if key not in seen_ports:
                            seen_ports.add(key)
                            services.append({
                                "host":     current_ip,
                                "port":     int(portid),
                                "protocol": protocol,
                                "service":  service,
                                "version":  version,
                                "cpe":      [],
                                "state":    "open",
                            })

        return {
            "hosts":          hosts,
            "services":       services,
            "os_matches":     [],
            "script_results": {},
            "service_count":  len(services),
        }

    @staticmethod
    def _empty() -> dict:
        return {
            "hosts":          [],
            "services":       [],
            "os_matches":     [],
            "script_results": {},
            "service_count":  0,
        }
