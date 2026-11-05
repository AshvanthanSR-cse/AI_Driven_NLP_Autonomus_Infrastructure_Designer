"""Kintsugi main window: Chat, Scripts, Connections, Tools, Audit. The GUI only calls core functions."""
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QPixmap
from PySide6.QtWidgets import (
    QComboBox, QFrame, QHBoxLayout, QHeaderView, QLabel, QMainWindow, QPushButton, QTableWidget, QTabWidget,
    QVBoxLayout, QWidget,
)

from core import audit, db, llm, local_steps, scripts
from core.aws_conn import AwsConnection
from core.config import check_settings, set_region, settings
from gui.chat_page import ChatPage
from gui.common import AWS_REGIONS, fill_table, style_table
from gui.connections_page import ConnectionsPage
from gui.scripts_page import ScriptsPage
from gui.theme import LOGO_MARK, page_title
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
        lay.setContentsMargins(16, 14, 16, 14)
        lay.addWidget(page_title("Audit log", "Every action Kintsugi took or prepared, with who approved it."))
        lay.addLayout(top)
        lay.addWidget(self.table, 1)
        style_table(self.table)

    def refresh(self):
        self.pool.start(audit.recent, 200, on_done=self._show,
                        on_fail=lambda m: self.info.setText(f"Cannot load audit log: {m}"))

    def _show(self, rows):
        fill_table(self.table, rows, self.COLS)
        self.table.resizeColumnsToContents()
        self.info.setText(f"{len(rows)} most recent actions")


class ToolsPage(QWidget):
    """Prerequisites: local tools the recipes need (version commands). Nothing is installed by the app."""
    COLS = [("tool", "Tool"), ("status", "Status"), ("version", "Version"), ("hint", "How to fix"),
            ("used_for", "Used for")]
    USED_FOR = {"docker": "Docker images, ECS Fargate, EKS apps, Ansible (runs in a container)",
                "terraform": "Your Terraform folders", "kubectl": "Deploying apps to EKS",
                "eksctl": "Creating / deleting EKS clusters", "helm": "Helm charts (optional)",
                "aws": "EKS kubeconfig and tokens", "az": "Azure connections signed in with az login"}

    def __init__(self, pool: WorkerPool):
        super().__init__()
        self.pool = pool
        self.table = QTableWidget()
        self.table.horizontalHeader().setStretchLastSection(True)
        self.info = QLabel("")
        btn = QPushButton("Check again")
        btn.clicked.connect(self.refresh)
        top = QHBoxLayout()
        top.addWidget(btn)
        top.addWidget(self.info, 1)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 14, 16, 14)
        lay.addWidget(page_title("Tools on this computer",
                                 "Recipes (Docker, ECS, EKS, Ansible, Terraform) and Azure connections use these "
                                 "local tools. Kintsugi only checks them; it never installs anything. Ansible needs "
                                 "no WSL: it runs inside a Docker container that Kintsugi builds the first time."))
        lay.addLayout(top)
        lay.addWidget(self.table, 1)
        style_table(self.table)

    def refresh(self):
        self.info.setText("Checking...")
        self.pool.start(local_steps.tool_status, on_done=self._show,
                        on_fail=lambda m: self.info.setText(f"Check failed: {m}"))

    def _show(self, rows):
        for r in rows:
            r["status"] = "ready" if r["ok"] else ("installed, not working" if r["installed"] else "missing")
            r["used_for"] = self.USED_FOR.get(r["tool"], "")
        fill_table(self.table, rows, self.COLS)
        self.table.resizeColumnsToContents()
        missing = [r["tool"] for r in rows if not r["ok"]]
        self.info.setText("All tools ready." if not missing else f"Not ready: {', '.join(missing)}")


def _startup() -> list[str]:
    """Worker thread: apply DB migrations, then check DB / LM Studio / settings."""
    lines = []
    try:
        db.ensure_schema()
    except Exception as e:
        lines.append(f"Warning: could not apply DB migrations: {e}")
    try:
        if n := scripts.recover_stale(settings.app_user):
            lines.append(f"Warning: {n} script(s) were still 'running' when Kintsugi closed; marked failed (check AWS)")
    except Exception:
        pass
    ok_db, db_msg = db.ping()
    ok_llm, llm_msg = llm.ping()
    return [("DB ok: " if ok_db else "DB error: ") + db_msg, ("LLM ok: " if ok_llm else "LLM error: ") + llm_msg] + lines + \
        [f"Warning: {p}" for p in check_settings()]


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Kintsugi - AI-driven AWS management")
        self.resize(1150, 780)
        self.pool = WorkerPool()
        self.conn = AwsConnection(settings.app_user)

        self.audit_page = AuditPage(self.pool)
        self.scripts_page = ScriptsPage(self.pool, self.conn, on_activity=self.audit_page.refresh)
        self.chat = ChatPage(self.pool, self.conn, on_activity=self._activity, on_open_script=self.open_script)
        self.connections = ConnectionsPage(self.pool, settings.app_user)
        self.tools_page = ToolsPage(self.pool)

        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        self.tabs.addTab(self.chat, "Chat")
        self.tabs.addTab(self.scripts_page, "Scripts")
        self.tabs.addTab(self.connections, "Connections")
        self.tabs.addTab(self.tools_page, "Tools")
        self.tabs.addTab(self.audit_page, "Audit log")
        central = QWidget()
        outer = QVBoxLayout(central)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        outer.addWidget(self._header())
        outer.addWidget(self.tabs, 1)
        self.setCentralWidget(central)

        self.statusBar().showMessage(f"User: {settings.app_user} · checking database and LM Studio...")
        self.pool.start(_startup, on_done=self._started)

        self.timer = QTimer(self)
        self.timer.timeout.connect(lambda: self.scripts_page.tick(self._scheduled_ran))

    def _header(self) -> QFrame:
        bar = QFrame()
        bar.setObjectName("Header")
        lay = QHBoxLayout(bar)
        lay.setContentsMargins(18, 10, 18, 10)
        logo = QLabel()
        logo.setPixmap(QPixmap(LOGO_MARK).scaledToHeight(34, Qt.SmoothTransformation))
        title = QLabel("Kintsugi")
        title.setObjectName("AppTitle")
        sub = QLabel("AI-driven cloud management · AWS · Azure · Google Cloud")
        sub.setObjectName("AppSub")
        self.header_info = QLabel(f"{settings.app_user} · AWS region")
        self.header_info.setObjectName("AppSub")
        self.region_box = QComboBox()
        self.region_box.setEditable(True)
        self.region_box.addItems(AWS_REGIONS if settings.aws_region in AWS_REGIONS
                                 else [settings.aws_region] + AWS_REGIONS)
        self.region_box.setCurrentText(settings.aws_region)
        self.region_box.setMinimumWidth(150)
        self.region_box.setToolTip("Region used for chat, lookups and new scripts. Saved scripts keep their own region.")
        self.region_box.activated.connect(lambda _: self._change_region(self.region_box.currentText()))
        self.region_box.lineEdit().editingFinished.connect(lambda: self._change_region(self.region_box.currentText()))
        tz = QLabel(f"· {settings.app_timezone}")
        tz.setObjectName("AppSub")
        lay.addWidget(logo)
        lay.addSpacing(6)
        lay.addWidget(title)
        lay.addSpacing(10)
        lay.addWidget(sub)
        lay.addStretch()
        lay.addWidget(self.header_info)
        lay.addSpacing(6)
        lay.addWidget(self.region_box)
        lay.addSpacing(6)
        lay.addWidget(tz)
        return bar

    def _change_region(self, region: str):
        if region.strip().lower() == settings.aws_region:
            return
        try:
            region = set_region(region)
        except ValueError as e:
            self.statusBar().showMessage(str(e), 8000)
            self.region_box.setCurrentText(settings.aws_region)
            return
        if self.region_box.findText(region) < 0:
            self.region_box.insertItem(0, region)
        self.region_box.setCurrentText(region)
        self.connections.region.setCurrentText(region)
        self.statusBar().showMessage(f"AWS region switched to {region}. New chats, lookups and scripts use it.", 8000)
        self.chat.append(f"**Region switched to {region}.** Saved scripts keep the region they were created with.")

    def _started(self, lines):
        self.statusBar().showMessage(f"User: {settings.app_user} · " + " · ".join(lines[:2]))
        problems = [l for l in lines if not l.startswith(("DB ok", "LLM ok"))]
        if problems:
            self.statusBar().setToolTip("\n".join(problems))
            self.chat.append("**Setup check:**\n\n" + "\n".join(f"- {p}" for p in problems))
        self.connections.refresh()
        self.tools_page.refresh()
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
            result = "succeeded" if r.get("ok") else "failed"
            self.chat.append(f"**Scheduled script #{r['id']} {result}.** See the Scripts page for details.")
        self.audit_page.refresh()
