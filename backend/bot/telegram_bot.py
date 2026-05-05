"""
PentestBot v2 — Telegram Bot Interface
Full-featured bot with command handling, inline confirmation dialogs,
live progress updates, scan history, and PDF report delivery.
"""

import asyncio
import html
from typing import Optional

from telegram import (
    Update, InlineKeyboardButton, InlineKeyboardMarkup,
    BotCommand,
)
from telegram.ext import (
    Application, CommandHandler, CallbackQueryHandler,
    MessageHandler, filters, ContextTypes,
)
from telegram.constants import ParseMode, ChatAction
from telegram.request import HTTPXRequest
from telegram.error import TelegramError, BadRequest

from config import Config
from core.job_manager import JobManager, JobState, ScanJob
from utils.logger import get_logger

logger = get_logger("bot.telegram")

# ── Stage display metadata ────────────────────────────────────────────────────

STAGE_META: dict[str, tuple[str, str]] = {
    "Recon":         ("🔍", "Subdomain Discovery"),
    "Resolver":      ("🌐", "DNS Resolution"),
    "OriginIP":      ("🎯", "Origin IP Detection"),
    "PortScan":      ("🔌", "Port Scanning"),
    "ServiceScan":   ("🛠️", "Service Detection"),
    "HTTPProbe":     ("🌍", "HTTP Probing"),
    "VulnScan":      ("⚡", "Vulnerability Scanning"),
    "TLSScan":       ("🔒", "TLS Analysis"),
    "Aggregation":   ("📊", "Aggregating Results"),
    "AIAnalysis":    ("🧠", "AI Analysis"),
    "Report":        ("📄", "Generating Report"),
    "Done":          ("✅", "Complete"),
    "Error":         ("❌", "Error"),
}

HELP_TEXT = """
🤖 <b>PentestBot v2</b> — Automated Penetration Testing

<b>Commands:</b>
/scan &lt;target&gt; — Start a full security assessment
/status        — Check your active scan progress
/cancel        — Cancel your running scan
/history       — View your recent scan history
/stats         — Show system statistics
/help          — Show this help message

<b>Examples:</b>
  <code>/scan example.com</code>
  <code>/scan 203.0.113.10</code>

<b>What gets tested:</b>
  • Subdomain enumeration and asset discovery
  • DNS resolution and CDN/WAF detection
  • Port scanning and service fingerprinting
  • Web technology identification
  • Vulnerability scanning (Nuclei + Nikto)
  • TLS/SSL configuration analysis
  • AI-powered security analysis (Groq)
  • Professional PDF report generation

⚠️ <i>Only scan targets you own or have explicit written permission to test.
Unauthorized scanning is illegal.</i>
"""


class TelegramBot:
    """
    Full Telegram bot implementation for PentestBot v2.

    Responsibilities:
    - Receive and validate user commands
    - Enforce target authorization disclaimers
    - Post live progress updates to each user's chat
    - Deliver the final PDF report upon completion
    - Expose history and status commands backed by the database
    """

    def __init__(self, config: Config, job_manager: JobManager):
        self.config      = config
        self.job_manager = job_manager
        self._app: Optional[Application] = None
        # Track the progress message ID per scan_id for editing
        self._progress_msgs: dict[str, int] = {}

    async def run(self) -> None:
        """Build and run the application."""

        request = HTTPXRequest(
            connect_timeout=20.0,
            read_timeout=45.0,
            write_timeout=45.0,
            pool_timeout=20.0,
        )
        get_updates_request = HTTPXRequest(
            connect_timeout=20.0,
            read_timeout=90.0,
            write_timeout=45.0,
            pool_timeout=20.0,
        )

        self._app = (
            Application.builder()
            .token(self.config.telegram.token)
            .request(request)
            .get_updates_request(get_updates_request)
            .build()
        )

        self._register_handlers()
        await self._set_commands()

        logger.info("Telegram bot polling started.")

        await self._app.initialize()
        await self._app.start()
        await self._app.updater.start_polling(
            poll_interval=2.0,
            timeout=45,
            bootstrap_retries=-1,
            read_timeout=55.0,
            write_timeout=45.0,
            connect_timeout=20.0,
            pool_timeout=20.0,
        )

        try:
            while True:
                await asyncio.sleep(3600)
        finally:
            await self._app.updater.stop()
            await self._app.stop()
            await self._app.shutdown()

    # ── Setup ─────────────────────────────────────────────────────────────────

    def _register_handlers(self) -> None:
        app = self._app
        app.add_handler(CommandHandler("start",   self._cmd_start))
        app.add_handler(CommandHandler("help",    self._cmd_help))
        app.add_handler(CommandHandler("scan",    self._cmd_scan))
        app.add_handler(CommandHandler("status",  self._cmd_status))
        app.add_handler(CommandHandler("cancel",  self._cmd_cancel))
        app.add_handler(CommandHandler("history", self._cmd_history))
        app.add_handler(CommandHandler("stats",   self._cmd_stats))
        app.add_handler(CallbackQueryHandler(self._on_callback))
        app.add_handler(
            MessageHandler(filters.TEXT & ~filters.COMMAND, self._on_text)
        )

    async def _set_commands(self) -> None:
        commands = [
            BotCommand("scan",    "Start a security assessment"),
            BotCommand("status",  "Check scan progress"),
            BotCommand("cancel",  "Cancel running scan"),
            BotCommand("history", "View recent scans"),
            BotCommand("stats",   "System statistics"),
            BotCommand("help",    "Show help"),
        ]
        try:
            await self._app.bot.set_my_commands(commands)
        except TelegramError as e:
            logger.warning(f"Could not set bot commands: {e}")

    # ── Authorization ─────────────────────────────────────────────────────────

    def _authorized(self, user_id: int) -> bool:
        allowed = self.config.telegram.allowed_user_ids
        return not allowed or user_id in allowed

    async def _deny(self, update: Update) -> None:
        await update.message.reply_text(
            "⛔ <b>Access Denied.</b>\n"
            "You are not authorized to use this bot.",
            parse_mode=ParseMode.HTML,
        )

    # ── Command: /start ───────────────────────────────────────────────────────

    async def _cmd_start(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        user = update.effective_user
        if not self._authorized(user.id):
            return await self._deny(update)
        await update.message.reply_text(
            f"👋 Welcome, <b>{html.escape(user.first_name)}</b>!\n\n"
            "I am <b>PentestBot v2</b> — your automated penetration testing assistant.\n\n"
            "Type /help to get started.",
            parse_mode=ParseMode.HTML,
        )

    # ── Command: /help ────────────────────────────────────────────────────────

    async def _cmd_help(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        if not self._authorized(update.effective_user.id):
            return await self._deny(update)
        await update.message.reply_text(HELP_TEXT, parse_mode=ParseMode.HTML)

    # ── Command: /scan ────────────────────────────────────────────────────────

    async def _cmd_scan(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        user = update.effective_user
        if not self._authorized(user.id):
            return await self._deny(update)

        if not ctx.args:
            await update.message.reply_text(
                "❌ Usage: <code>/scan &lt;domain or IP&gt;</code>\n\n"
                "Example: <code>/scan example.com</code>",
                parse_mode=ParseMode.HTML,
            )
            return

        raw_target = ctx.args[0].strip()

        # Check for already running scan
        active = self.job_manager.active_job_for_user(user.id)
        if active:
            kb = InlineKeyboardMarkup([[
                InlineKeyboardButton(
                    "🛑 Cancel current scan",
                    callback_data=f"cancel:{active.scan_id}",
                )
            ]])
            await update.message.reply_text(
                f"⚠️ You already have a scan running.\n\n"
                f"Target: <code>{html.escape(active.target)}</code>\n"
                f"Stage: <b>{active.current_stage}</b>\n"
                f"Running: <b>{active.duration_str()}</b>",
                parse_mode=ParseMode.HTML,
                reply_markup=kb,
            )
            return

        # Legal disclaimer confirmation
        kb = InlineKeyboardMarkup([[
            InlineKeyboardButton(
                "✅ Yes, I have permission",
                callback_data=f"confirm:{raw_target}",
            ),
            InlineKeyboardButton(
                "❌ Cancel",
                callback_data="cancel_new",
            ),
        ]])
        await update.message.reply_text(
            f"🎯 <b>Target:</b> <code>{html.escape(raw_target)}</code>\n\n"
            "⚠️ <b>Legal Notice:</b>\n"
            "By proceeding you confirm you own this target or have "
            "<b>explicit written authorization</b> to test it.\n\n"
            "Do you have permission to scan this target?",
            parse_mode=ParseMode.HTML,
            reply_markup=kb,
        )

    # ── Command: /status ─────────────────────────────────────────────────────

    async def _cmd_status(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        user = update.effective_user
        if not self._authorized(user.id):
            return await self._deny(update)

        job = self.job_manager.active_job_for_user(user.id)
        if not job:
            await update.message.reply_text(
                "ℹ️ No active scan. Use <code>/scan &lt;target&gt;</code> to start one.",
                parse_mode=ParseMode.HTML,
            )
            return

        await update.message.reply_text(
            self._job_status_text(job),
            parse_mode=ParseMode.HTML,
        )

    # ── Command: /cancel ─────────────────────────────────────────────────────

    async def _cmd_cancel(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        user = update.effective_user
        if not self._authorized(user.id):
            return await self._deny(update)

        job = self.job_manager.active_job_for_user(user.id)
        if not job:
            await update.message.reply_text("ℹ️ No active scan to cancel.")
            return

        ok = await self.job_manager.cancel(job.scan_id)
        if ok:
            await update.message.reply_text(
                f"🛑 Scan for <code>{html.escape(job.target)}</code> has been cancelled.",
                parse_mode=ParseMode.HTML,
            )
        else:
            await update.message.reply_text(
                "⚠️ Could not cancel the scan (may have already completed)."
            )

    # ── Command: /history ─────────────────────────────────────────────────────

    async def _cmd_history(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        user = update.effective_user
        if not self._authorized(user.id):
            return await self._deny(update)

        scans = await self.job_manager.db.get_user_scans(user.id, limit=10)
        if not scans:
            await update.message.reply_text("📭 No scan history found.")
            return

        state_icons = {
            "completed": "✅", "failed": "❌",
            "running": "⏳", "cancelled": "🛑", "queued": "⏸",
        }
        lines = ["📋 <b>Your Recent Scans</b>\n"]
        for scan in scans:
            icon   = state_icons.get(scan["state"], "❓")
            target = html.escape(scan["target"])
            state  = scan["state"]
            sid    = scan["scan_id"]
            summary = {}
            if scan.get("summary"):
                import json
                try:
                    summary = json.loads(scan["summary"])
                except Exception:
                    pass

            line = f"{icon} <code>{target}</code> — <b>{state}</b>"
            if summary.get("risk_level"):
                line += f" — Risk: <b>{summary['risk_level']}</b>"
            if summary.get("total_findings") is not None:
                line += f" — Findings: <b>{summary['total_findings']}</b>"
            line += f"\n   <code>{sid}</code>"
            lines.append(line)

        await update.message.reply_text(
            "\n\n".join(lines),
            parse_mode=ParseMode.HTML,
        )

    # ── Command: /stats ───────────────────────────────────────────────────────

    async def _cmd_stats(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        user = update.effective_user
        if not self._authorized(user.id):
            return await self._deny(update)

        stats    = await self.job_manager.db.get_stats()
        q_status = self.job_manager.queue.status_summary()

        msg = (
            "📊 <b>PentestBot v2 — System Stats</b>\n\n"
            f"<b>Database:</b>\n"
            f"  Completed scans: {stats.get('completed', 0)}\n"
            f"  Failed: {stats.get('failed', 0)}\n"
            f"  Cancelled: {stats.get('cancelled', 0)}\n"
            f"  Unique users: {stats.get('unique_users', 0)}\n\n"
            f"<b>Queue:</b>\n"
            f"  Running: {self.job_manager.queue.active_count}\n"
            f"  Waiting: {self.job_manager.queue.queue_depth}\n"
            f"  Max concurrent: {self.config.max_concurrent_scans}"
        )
        await update.message.reply_text(msg, parse_mode=ParseMode.HTML)

    # ── Callbacks ─────────────────────────────────────────────────────────────

    async def _on_callback(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        query = update.callback_query
        await query.answer()
        data    = query.data or ""
        user_id = query.from_user.id
        if not self._authorized(user_id):
            await query.edit_message_text(
                "⛔ <b>Access Denied.</b>\nYou are not authorized to use this bot.",
                parse_mode=ParseMode.HTML,
            )
            return

        if data == "cancel_new":
            await query.edit_message_text("❌ Scan cancelled.")

        elif data.startswith("confirm:"):
            raw_target = data.split(":", 1)[1]
            await query.edit_message_text(
                f"🚀 <b>Launching scan for:</b> <code>{html.escape(raw_target)}</code>\n\n"
                "Initializing pipeline...",
                parse_mode=ParseMode.HTML,
            )
            await self._launch_scan(
                chat_id     = query.message.chat_id,
                msg_id      = query.message.message_id,
                user_id     = user_id,
                raw_target  = raw_target,
            )

        elif data.startswith("cancel:"):
            scan_id = data.split(":", 1)[1]
            ok = await self.job_manager.cancel(scan_id)
            msg = (
                f"🛑 Scan <code>{scan_id}</code> cancelled."
                if ok else
                "⚠️ Could not cancel (already done or not found)."
            )
            await query.edit_message_text(msg, parse_mode=ParseMode.HTML)

    # ── Scan launch + progress loop ───────────────────────────────────────────

    async def _launch_scan(
        self,
        chat_id: int,
        msg_id: int,
        user_id: int,
        raw_target: str,
    ) -> None:
        """Submit scan and hook up async progress callback."""

        async def on_progress(scan_id: str, stage: str, message: str) -> None:
            emoji, label = STAGE_META.get(stage, ("🔄", stage))
            text = (
                f"{emoji} <b>[{label}]</b>\n"
                f"{html.escape(message)}\n\n"
                f"<i>Stage: {stage} — use /status for details</i>"
            )
            pmid = self._progress_msgs.get(scan_id)
            if pmid:
                try:
                    await self._app.bot.edit_message_text(
                        chat_id    = chat_id,
                        message_id = pmid,
                        text       = text,
                        parse_mode = ParseMode.HTML,
                    )
                except (TelegramError, BadRequest):
                    pass

            # When done, deliver result
            if stage in ("Done", "Error"):
                await asyncio.sleep(1)
                job = self.job_manager.get_job(scan_id)
                if job:
                    await self._deliver_result(chat_id, job)
                self._progress_msgs.pop(scan_id, None)

        try:
            job = await self.job_manager.submit(
                user_id     = user_id,
                raw_target  = raw_target,
                on_progress = on_progress,
            )

            # Post live progress message (will be edited by on_progress)
            progress_msg = await self._app.bot.send_message(
                chat_id    = chat_id,
                text       = f"⏳ <b>Scan queued</b> for <code>{html.escape(raw_target)}</code>",
                parse_mode = ParseMode.HTML,
            )
            self._progress_msgs[job.scan_id] = progress_msg.message_id

        except ValueError as e:
            await self._app.bot.send_message(
                chat_id    = chat_id,
                text       = f"❌ <b>Invalid target:</b> {html.escape(str(e))}",
                parse_mode = ParseMode.HTML,
            )
        except Exception as e:
            logger.exception(f"Scan launch error: {e}")
            await self._app.bot.send_message(
                chat_id    = chat_id,
                text       = f"❌ <b>Error launching scan:</b> {html.escape(str(e))}",
                parse_mode = ParseMode.HTML,
            )

    async def _deliver_result(self, chat_id: int, job: ScanJob) -> None:
        """Send completion summary and PDF to user."""
        if job.state == JobState.COMPLETED and job.pdf_path and job.pdf_path.exists():
            logger.info(
                "Delivering completed scan %s to chat %s (pdf=%s)",
                job.scan_id,
                chat_id,
                job.pdf_path,
            )
            summary = (
                f"✅ <b>Scan Complete!</b>\n\n"
                f"🎯 Target:    <code>{html.escape(job.target)}</code>\n"
                f"⏱  Duration: <b>{job.duration_str()}</b>\n"
                f"🆔 Scan ID:  <code>{job.scan_id}</code>\n\n"
                "📋 <b>Full report attached below.</b>"
            )
            await self._app.bot.send_message(
                chat_id    = chat_id,
                text       = summary,
                parse_mode = ParseMode.HTML,
            )
            await self._app.bot.send_chat_action(
                chat_id = chat_id,
                action  = ChatAction.UPLOAD_DOCUMENT,
            )
            try:
                with open(job.pdf_path, "rb") as f:
                    sent = await self._app.bot.send_document(
                        chat_id  = chat_id,
                        document = f,
                        filename = job.pdf_path.name,
                        caption  = (
                            f"📄 Penetration Test Report\n"
                            f"Target: {job.target} | ID: {job.scan_id}"
                        ),
                    )
                logger.info(
                    "PDF delivered for scan %s to chat %s as message %s",
                    job.scan_id,
                    chat_id,
                    getattr(sent, "message_id", "unknown"),
                )
            except Exception as e:
                logger.exception(
                    "PDF delivery failed for scan %s to chat %s: %s",
                    job.scan_id,
                    chat_id,
                    e,
                )
                await self._app.bot.send_message(
                    chat_id    = chat_id,
                    text       = f"⚠️ Report was generated but could not be sent: {e}",
                    parse_mode = ParseMode.HTML,
                )

        elif job.state == JobState.CANCELLED:
            await self._app.bot.send_message(
                chat_id    = chat_id,
                text       = f"🛑 Scan for <code>{html.escape(job.target)}</code> was cancelled.",
                parse_mode = ParseMode.HTML,
            )
        else:
            err = html.escape(job.error or "Unknown error")
            await self._app.bot.send_message(
                chat_id    = chat_id,
                text       = (
                    f"❌ <b>Scan failed for</b> <code>{html.escape(job.target)}</code>\n\n"
                    f"Error: <code>{err}</code>"
                ),
                parse_mode = ParseMode.HTML,
            )

    # ── Fallback handler ──────────────────────────────────────────────────────

    async def _on_text(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        if not self._authorized(update.effective_user.id):
            return
        await update.message.reply_text(
            "Use <code>/scan &lt;target&gt;</code> to start a scan, "
            "or <code>/help</code> for all commands.",
            parse_mode=ParseMode.HTML,
        )

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _job_status_text(job: ScanJob) -> str:
        state_icons = {
            JobState.QUEUED:    "⏸",
            JobState.RUNNING:   "⏳",
            JobState.COMPLETED: "✅",
            JobState.FAILED:    "❌",
            JobState.CANCELLED: "🛑",
        }
        icon = state_icons.get(job.state, "❓")
        return (
            f"📊 <b>Scan Status</b>\n\n"
            f"{icon} State:    <b>{job.state.value}</b>\n"
            f"🎯 Target:   <code>{html.escape(job.target)}</code>\n"
            f"🔄 Stage:    <b>{html.escape(job.current_stage)}</b>\n"
            f"⏱ Running:  <b>{job.duration_str()}</b>\n"
            f"🆔 Scan ID: <code>{job.scan_id}</code>"
        )
