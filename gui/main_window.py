"""CloudAI main window: Chat, Scripts, Connections, Audit. The GUI only calls core functions."""
from PySide6.QtCore import QTimer
from PySide6.QtWidgets import (
    QHBoxLayout, QHeaderView, QLabel, QMainWindow, QPushButton, QTableWidget, QTabWidget, QVBoxLayout, QWidget,
)

from core import audit, db, llm
from core.aws_conn import AwsConnection
from core.config import check_settings, settings
from gui.chat_page import ChatPage
from gui.common import fill_table
from gui.connections_page import ConnectionsPage
from gui.scripts_page import ScriptsPage
from gui.workers import WorkerPool

SCHEDULER_INTERVAL_MS = 30_000


class AuditPage(QWidget):
    COLS = [("id", "#"), ("ts", "Time"), ("actor", "Actor"), ("tool_name", "Tool"), ("risk", "Risk"),
            ("approval", "Approval"), ("status", "Status"), ("result_summary", "Result"),
            ("request", "Request"), ("tool_args", "Args")]

    def __init__(self, pool: WorkerPool):
        super().__init__()
        self.pool = pool
        self.table = QTableWidget()
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.info = QLabel("")
        btn = QPushButton("Refresh")
        btn.clicked.connect(self.refresh)
        top = QHBoxLayout()
        top.addWidget(btn)
        top.addWidget(self.info, 1)
        lay = QVBoxLayout(self)
        lay.addLayout(top)
        lay.addWidget(self.table, 1)

    def refresh(self):
        self.pool.start(audit.recent, 200, on_done=self._show,
                        on_fail=lambda m: self.info.setText(f"Cannot load audit log: {m}"))

    def _show(self, rows):
        fill_table(self.table, rows, self.COLS)
        self.table.resizeColumnsToContents()
        self.info.setText(f"{len(rows)} most recent actions")


def _startup() -> list[str]:
    """Worker thread: apply DB migrations, then check DB / LM Studio / settings."""
    lines = []
    try:
        db.ensure_schema()
    except Exception as e:
        lines.append(f"⚠ Could not apply DB migrations: {e}")
    ok_db, db_msg = db.ping()
    ok_llm, llm_msg = llm.ping()
    return [("DB ✓ " if ok_db else "DB ✗ ") + db_msg, ("LLM ✓ " if ok_llm else "LLM ✗ ") + llm_msg] + lines + \
        [f"⚠ {p}" for p in check_settings()]


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CloudAI — AI-driven AWS management")
        self.resize(1150, 780)
        self.pool = WorkerPool()
        self.conn = AwsConnection(settings.app_user)

        self.audit_page = AuditPage(self.pool)
        self.scripts_page = ScriptsPage(self.pool, self.conn, on_activity=self.audit_page.refresh)
        self.chat = ChatPage(self.pool, self.conn, on_activity=self._activity, on_open_script=self.open_script)
        self.connections = ConnectionsPage(self.pool, settings.app_user)

        self.tabs = QTabWidget()
        self.tabs.addTab(self.chat, "💬 Chat")
        self.tabs.addTab(self.scripts_page, "📝 Scripts")
        self.tabs.addTab(self.connections, "🔑 Connections")
        self.tabs.addTab(self.audit_page, "📋 Audit log")
        self.setCentralWidget(self.tabs)

        self.statusBar().showMessage(f"User: {settings.app_user} · checking database and LM Studio…")
        self.pool.start(_startup, on_done=self._started)

        # Scheduler: run due scripts every 30 s (only while the app is open).
        self.timer = QTimer(self)
        self.timer.timeout.connect(lambda: self.scripts_page.tick(self._scheduled_ran))

    def _started(self, lines):
        self.statusBar().showMessage(f"User: {settings.app_user} · " + " · ".join(lines[:2]))
        problems = [l for l in lines if not l.startswith(("DB ✓", "LLM ✓"))]
        if problems:
            self.statusBar().setToolTip("\n".join(problems))
            self.chat.append("**Setup check:**\n\n" + "\n".join(f"- {p}" for p in problems))
        self.connections.refresh()
        self.scripts_page.refresh()
        self.audit_page.refresh()
        self.timer.start(SCHEDULER_INTERVAL_MS)

    def _activity(self):
        self.audit_page.refresh()
        self.scripts_page.refresh()

    def open_script(self, script_id: int):
        self.tabs.setCurrentWidget(self.scripts_page)
        self.scripts_page.open_script(script_id)

    def _scheduled_ran(self, results):
        for r in results:
            icon = "✅" if r.get("ok") else "❌"
            self.chat.append(f"{icon} **Scheduled script #{r['id']} ran.** See the Scripts page for details.")
        self.audit_page.refresh()
