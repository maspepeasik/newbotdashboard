"""
PentestBot v2 — Screenshots Stage
Captures visual evidence of web endpoints using gowitness.
"""

import asyncio
from pathlib import Path
from pipeline.base_stage import BaseStage


class ScreenshotsStage(BaseStage):
    """
    Stage 14: Automated Screenshots
    Uses gowitness to capture screenshots of all discovered live URLs.
    """

    NAME = "Screenshots"

    async def run(self) -> None:
        self.clear_stage_error()

        if not self.runner.which("gowitness"):
            self.log.warning("[Screenshots] gowitness not found - skipping")
            return

        live_hosts = self.ctx.get("live_hosts", [])
        if not live_hosts:
            self.log.info("[Screenshots] No live hosts found for screenshots")
            return

        # Prepare URL list for gowitness
        urls = [host["url"] for host in live_hosts]
        urls_file = self.temp_file("screenshot_targets.txt")
        self.write_lines(urls_file, urls)

        # Output directory for screenshots
        screenshot_dir = self.ctx["work_dir"] / "screenshots"
        screenshot_dir.mkdir(parents=True, exist_ok=True)

        self.log.info(f"[Screenshots] Capturing {len(urls)} screenshots...")

        # Run gowitness
        # Flags:
        # scan file: take input from file
        # --screenshot-path: where to save images
        # --disable-logging: keep it clean
        cmd = [
            "gowitness",
            "scan",
            "file",
            "-f", str(urls_file),
            "--screenshot-path", str(screenshot_dir),
            "--threads", "4",
            "--disable-logging",
        ]

        result = await self.runner.run(cmd=cmd, timeout=300)
        self.log_result(result)

        if result.success:
            # Store screenshot path in context for the reporter
            self.ctx["screenshot_dir"] = screenshot_dir
            # Count images captured
            captured = list(screenshot_dir.glob("*.png"))
            self.log.info(f"[Screenshots] Captured {len(captured)} screenshots successfully")
        else:
            self.add_tool_error(f"gowitness failed: {result.stderr[:200]}")
