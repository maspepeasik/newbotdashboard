#!/usr/bin/env python3
"""
PentestBot v2 - Automated Penetration Testing System
Entry point: initializes all subsystems and launches the FastAPI server.
Telegram bot integration is optional — runs automatically if token is configured.
"""

import argparse
import asyncio
import os
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING

# Ensure project root is importable
sys.path.insert(0, str(Path(__file__).resolve().parent))

from utils.logger import get_logger, setup_logging

if TYPE_CHECKING:
    from config import Config

logger = get_logger("main")


def _projectdiscovery_httpx_path(runner) -> str | None:
    for candidate in ("pd-httpx", "/usr/local/bin/pd-httpx", "httpx", "/usr/local/bin/httpx"):
        resolved = runner.resolve_binary(candidate)
        if not resolved:
            continue
        try:
            result = subprocess.run(
                [resolved, "-h"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except Exception:
            continue

        help_text = f"{result.stdout}\n{result.stderr}".lower()
        if "usage: httpx [options] url" in help_text:
            continue
        if (
            "projectdiscovery" in help_text
            or "http toolkit" in help_text
            or "-tech-detect" in help_text
        ):
            return resolved
    return None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="PentestBot v2 - Automated Penetration Testing Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--config",
        default=".env",
        help="Path to .env configuration file (default: .env)",
    )
    parser.add_argument(
        "--check-tools",
        action="store_true",
        help="Verify all required tools are installed and exit",
    )
    parser.add_argument(
        "--test-scan",
        metavar="TARGET",
        help="Run a headless test scan without Telegram",
    )
    parser.add_argument(
        "--api-only",
        action="store_true",
        help="Run in API-only mode (no Telegram bot even if token is set)",
    )
    parser.add_argument(
        "--scan-mode",
        choices=["fast", "deep"],
        default="fast",
        help="Scan mode: 'fast' (default) or 'deep' (thorough, slower)",
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default=None,
        help="Override log level from config",
    )
    return parser.parse_args()


def _python_module_available(module: str) -> bool:
    try:
        result = subprocess.run(
            [sys.executable, "-m", module, "--help"],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except Exception:
        return False
    combined = f"{result.stdout}\n{result.stderr}".lower()
    if "no module named" in combined:
        return False
    return result.returncode == 0


def check_tools(env_file: str = ".env") -> bool:
    """Verify all required external tools are installed."""
    from config import load_config
    from utils.command_runner import CommandRunner

    config = load_config(env_file, require_secrets=False)
    runner = CommandRunner()
    tools = [
        "subfinder",
        "assetfinder",
        "dnsx",
        "anew",
        "naabu",
        "nmap",
        "httpx",
        "nuclei",
        "testssl.sh",
        "curl",
        "jq",
    ]
    config_required_tools: list[str] = []
    optional_tools = ["nikto", "amass", "gobuster", "whatweb", "wafw00f",
                      "webanalyze", "wpscan", "joomscan", "dirsearch"]

    if getattr(config.scan, "enable_web_discovery", True):
        config_required_tools.extend(["katana", "gau"])
    if getattr(config.scan, "enable_nikto", False):
        config_required_tools.append("nikto")
    if getattr(config.scan, "enable_amass", False):
        config_required_tools.append("amass")
    if getattr(config.scan, "enable_gobuster", True):
        config_required_tools.append("gobuster")
    if getattr(config.scan, "enable_fingerprint", True):
        config_required_tools.extend(["whatweb", "wafw00f"])

    print("\n" + "=" * 50)
    print("  PentestBot v2 - Tool Check")
    print("=" * 50)

    missing = []
    for tool in tools:
        ok = runner.which(tool)
        status = "[FOUND] "
        wrong_binary = False

        if tool == "httpx":
            resolved = _projectdiscovery_httpx_path(runner)
            ok = resolved is not None
            wrong_binary = not ok and runner.resolve_binary("httpx") is not None
        elif tool == "nikto" and ok:
            resolved = runner.resolve_binary(tool) or tool
            result = subprocess.run(
                [resolved, "-Version"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            text = f"{result.stdout}\n{result.stderr}".lower()
            if "required module not found" in text:
                ok = False
        elif tool == "testssl.sh" and ok:
            resolved = runner.resolve_binary(tool) or tool
            result = subprocess.run(
                [resolved, "--help"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            text = f"{result.stdout}\n{result.stderr}".lower()
            if (
                "need to install hexdump" in text
                or "need to install ps" in text
                or 'neither "dig", "host", "drill" nor "nslookup" is present' in text
            ):
                ok = False

        if not ok:
            status = "[WRONG] " if wrong_binary else "[MISS]  "

        print(f"  {status}  {tool}")
        if not ok:
            missing.append(tool)

    for tool in config_required_tools:
        ok = runner.which(tool)
        print(f"  {'[FOUND] ' if ok else '[MISS]  '}  {tool} (enabled)")
        if not ok:
            missing.append(tool)

    sslyze_enabled = getattr(config.scan, "enable_sslyze", True)
    if sslyze_enabled:
        sslyze_ok = _python_module_available("sslyze")
        print(f"  {'[FOUND] ' if sslyze_ok else '[MISS]  '}  sslyze (enabled)")
        if not sslyze_ok:
            missing.append("sslyze")
    else:
        print("  [OPT] --  sslyze (disabled)")

    for tool in optional_tools:
        if tool in config_required_tools:
            continue
        ok = runner.which(tool)
        print(f"  {'[OPT] OK' if ok else '[OPT] --'}  {tool}")

    nuclei_templates = os.getenv("NUCLEI_TEMPLATES", "").strip()
    nuclei_template_paths = [
        Path(nuclei_templates).expanduser() if nuclei_templates else None,
        Path.home() / "nuclei-templates",
        Path.home() / ".config" / "nuclei" / "templates",
        Path("/usr/local/share/nuclei-templates"),
        Path("/opt/nuclei-templates"),
    ]
    templates_ok = any(
        path and path.exists() and any(path.iterdir())
        for path in nuclei_template_paths
    )
    print(f"  {'[FOUND] ' if templates_ok else '[MISS]  '}  nuclei-templates")
    if not templates_ok:
        missing.append("nuclei-templates")

    print("=" * 50)

    if missing:
        print(f"\nMissing or invalid: {', '.join(missing)}")
        print("   Run: sudo bash scripts/install_tools.sh\n")
        return False

    print("\nAll tools present. PentestBot is ready.\n")
    return True


async def run_test_scan(target: str, config: "Config", scan_mode: str = "fast") -> None:
    """Run a complete scan outside Telegram for debugging."""
    from core.database import Database
    from core.job_manager import JobManager
    from core.queue_manager import QueueManager

    db = Database(config.db_path)
    await db.initialize()

    queue = QueueManager(max_concurrent=1)
    job_mgr = JobManager(config=config, database=db, queue=queue)
    await job_mgr.start()

    print(f"\nStarting test scan: {target} (mode={scan_mode})")

    def on_progress(scan_id: str, stage: str, message: str) -> None:
        print(f"  [{stage}] {message}")

    try:
        job = await job_mgr.submit(
            user_id=0,
            raw_target=target,
            on_progress=on_progress,
            scan_mode=scan_mode,
        )
        print(f"  Job ID: {job.scan_id}")

        while job.state.value not in ("completed", "failed", "cancelled"):
            await asyncio.sleep(2)

        if job.pdf_path:
            print(f"\nReport: {job.pdf_path}")
        else:
            print(f"\nFailed: {job.error}")
    finally:
        await job_mgr.stop()
        await db.close()


async def main_async(config: "Config", api_only: bool = False) -> None:
    """Initialize all subsystems and run the API server (with optional Telegram bot)."""
    import uvicorn

    from core.database import Database
    from core.job_manager import JobManager
    from core.queue_manager import QueueManager
    from service.http_api import create_app

    logger.info("=" * 55)
    logger.info("  PentestBot v2 starting up")
    logger.info("=" * 55)

    db = Database(config.db_path)
    await db.initialize()
    logger.info("Database initialized.")

    queue = QueueManager(max_concurrent=config.max_concurrent_scans)
    job_mgr = JobManager(config=config, database=db, queue=queue)
    await job_mgr.start()
    logger.info("Job manager started (max concurrent: %s).", config.max_concurrent_scans)

    # Create FastAPI application
    app = create_app(config=config, database=db, job_manager=job_mgr)
    logger.info("FastAPI application created.")

    # Start Telegram bot as background task if enabled and not api-only mode
    bot_task = None
    if config.telegram.enabled and not api_only:
        try:
            from bot.telegram_bot import TelegramBot
            bot = TelegramBot(config=config, job_manager=job_mgr)
            bot_task = asyncio.create_task(bot.run())
            logger.info("Telegram bot started as background task.")
        except ImportError:
            logger.warning("Telegram bot module not available. Running in API-only mode.")
        except Exception as e:
            logger.warning("Failed to start Telegram bot: %s. Running in API-only mode.", e)
    else:
        if api_only:
            logger.info("API-only mode enabled. Telegram bot disabled.")
        else:
            logger.info("No Telegram token configured. Running in API-only mode.")

    # Run Uvicorn server
    uvicorn_config = uvicorn.Config(
        app,
        host=config.api.host,
        port=config.api.port,
        log_level="info",
        access_log=True,
    )
    server = uvicorn.Server(uvicorn_config)

    logger.info(
        "API server starting on http://%s:%s",
        config.api.host,
        config.api.port,
    )

    try:
        await server.serve()
    finally:
        logger.info("Shutting down...")
        if bot_task and not bot_task.done():
            bot_task.cancel()
            try:
                await bot_task
            except (asyncio.CancelledError, Exception):
                pass
        await job_mgr.stop()
        await db.close()
        logger.info("Shutdown complete.")


def main() -> None:
    args = parse_args()

    if args.check_tools:
        sys.exit(0 if check_tools(args.config) else 1)

    from config import load_config

    config = load_config(args.config)
    if args.log_level:
        config.log_level = args.log_level
    setup_logging(config.log_level, config.log_dir)

    if args.test_scan:
        asyncio.run(run_test_scan(args.test_scan, config, scan_mode=args.scan_mode))
        return

    asyncio.run(main_async(config, api_only=args.api_only))


if __name__ == "__main__":
    main()
