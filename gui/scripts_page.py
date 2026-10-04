"""Scripts page: every write request from chat lands here.

Flow: read the script -> ✔ Approve or ✖ Deny (or ✏ Edit it yourself) -> ▶ Run now or ⏰ Schedule.
Scripts written by the agent can never run before you approve them; an edited script needs a new approval.
"""
from datetime import datetime, timedelta

from PySide6.QtCore import QDateTime, Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QAbstractItemView, QDateTimeEdit, QFrame, QHBoxLayout, QHeaderView, QInputDialog, QLabel, QMessageBox,
    QPlainTextEdit, QPushButton, QStackedWidget, QTableWidget, QVBoxLayout, QWidget,
)

from core import scripts
from core.config import settings
from gui.common import LOCAL_TZ, fill_table, fmt_time

STATUS_ICON = {"draft": "🟡 waiting for your review", "approved": "✔ approved", "denied": "✖ denied",
               "scheduled": "⏰ scheduled", "running": "▶ running", "succeeded": "✅ succeeded",
               "failed": "❌ failed", "cancelled": "⏹ cancelled"}

EDIT_HELP = ("Edit the steps CloudAI will run (JSON). Each step: service, operation (boto3 names), params; optional "
             "description, region, save_as, wait, undo. Values like {{vpc.Vpc.VpcId}} come from an earlier step's "
             "save_as. Everything is checked again when you save, and the script must be approved again.")


class ScriptsPage(QWidget):
    LIST_COLS = [("id", "#"), ("title", "Script"), ("status", "Status"), ("destructive", "Destructive"),
                 ("run_at", f"Scheduled for ({settings.app_timezone})"), ("created_at", "Created"),
                 ("last_run_at", "Last run")]

    def __init__(self, pool, conn, on_activity):
        super().__init__()
        self.pool, self.conn, self.on_activity = pool, conn, on_activity
        self.owner = conn.owner
        self.rows: list[dict] = []
        self.current: dict | None = None
        self.editing = False

        self.stack = QStackedWidget()
        self.stack.addWidget(self._build_list())
        self.stack.addWidget(self._build_detail())
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addWidget(self.stack)

    # ================= list view =================
    def _build_list(self) -> QWidget:
        w = QWidget()
        self.table = QTableWidget()
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.cellDoubleClicked.connect(lambda r, _c: self._open_row(r))
        open_btn = QPushButton("Open script")
        open_btn.clicked.connect(lambda: self._open_row(self.table.currentRow()))
        refresh = QPushButton("Refresh")
        refresh.clicked.connect(self.refresh)
        self.list_info = QLabel("")
        top = QHBoxLayout()
        top.addWidget(open_btn)
        top.addWidget(refresh)
        top.addWidget(self.list_info, 1)
        lay = QVBoxLayout(w)
        lay.addWidget(QLabel("<h3>Scripts</h3>When you ask the AI to change something, it writes a script here. "
                             "Open it, read it, then <b>Approve</b> or <b>Deny</b> it (or edit it yourself). "
                             "Only approved scripts can be run or scheduled."))
        lay.addLayout(top)
        lay.addWidget(self.table, 1)
        return w

    def refresh(self):
        self.pool.start(scripts.list_scripts, self.owner, on_done=self._show_list,
                        on_fail=lambda m: self.list_info.setText(f"Cannot load scripts: {m}"))

    def _show_list(self, rows):
        self.rows = rows
        selected = self.current["id"] if self.current else None
        fill_table(self.table, rows, self.LIST_COLS,
                   fmt={"status": lambda r: STATUS_ICON.get(r["status"], r["status"])})
        waiting = sum(r["status"] == "draft" for r in rows)
        self.list_info.setText(f"{len(rows)} script(s)" + (f" · {waiting} waiting for your review" if waiting else "")
                               + " · double-click to open")
        for i, r in enumerate(rows):
            if r["id"] == selected:
                self.table.selectRow(i)

    def _open_row(self, r: int):
        if 0 <= r < len(self.rows):
            self.open_script(self.rows[r]["id"])
        else:
            self.list_info.setText("Select a script in the list first.")

    # ================= detail view =================
    def _build_detail(self) -> QWidget:
        w = QWidget()
        back = QPushButton("← All scripts")
        back.clicked.connect(self.show_list)
        self.d_title = QLabel()
        self.d_title.setTextFormat(Qt.RichText)
        self.d_title.setWordWrap(True)
        self.d_meta = QLabel()
        self.d_meta.setWordWrap(True)
        self.d_meta.setTextInteractionFlags(Qt.TextSelectableByMouse)
        mono = QFont("Consolas")
        mono.setStyleHint(QFont.Monospace)

        self.d_text = QPlainTextEdit()                # read view: AWS CLI equivalent
        self.d_text.setReadOnly(True)
        self.d_text.setFont(mono)
        self.d_editor = QPlainTextEdit()              # edit view: the steps that run (JSON)
        self.d_editor.setFont(mono)
        self.d_editor.hide()
        self.edit_help = QLabel(EDIT_HELP)
        self.edit_help.setWordWrap(True)
        self.edit_help.setStyleSheet("color: gray;")
        self.edit_help.hide()
        self.script_label = QLabel("<b>Script</b> (read it before approving)")

        self.d_result = QPlainTextEdit()
        self.d_result.setReadOnly(True)
        self.d_result.setFont(mono)
        self.d_result.setMaximumHeight(140)

        # --- review bar: Approve / Deny / Edit
        self.approve_btn = QPushButton("✔ Approve")
        self.approve_btn.setStyleSheet("QPushButton { font-weight: bold; color: #1e8449; } QPushButton:disabled { color: #aaaaaa; }")
        self.deny_btn = QPushButton("✖ Deny")
        self.deny_btn.setStyleSheet("QPushButton { font-weight: bold; color: #c0392b; } QPushButton:disabled { color: #aaaaaa; }")
        self.edit_btn = QPushButton("✏ Edit script")
        self.save_edit_btn = QPushButton("💾 Save changes")
        self.save_edit_btn.setStyleSheet("font-weight: bold;")
        self.discard_edit_btn = QPushButton("Discard changes")
        self.save_edit_btn.hide()
        self.discard_edit_btn.hide()
        self.review_state = QLabel()
        review = QFrame()
        review.setFrameShape(QFrame.StyledPanel)
        rl = QHBoxLayout(review)
        rl.addWidget(QLabel("<b>Review:</b>"))
        for b in (self.approve_btn, self.deny_btn, self.edit_btn, self.save_edit_btn, self.discard_edit_btn):
            rl.addWidget(b)
        rl.addWidget(self.review_state, 1)

        # --- run bar: Run now / Dry run / Schedule
        self.run_btn = QPushButton("▶ Run now")
        self.run_btn.setStyleSheet("font-weight: bold;")
        self.dry_btn = QPushButton("Dry run (check only)")
        self.when = QDateTimeEdit()
        self.when.setCalendarPopup(True)
        self.when.setDisplayFormat("yyyy-MM-dd HH:mm")
        self.sched_btn = QPushButton("⏰ Schedule")
        self.cancel_btn = QPushButton("Cancel schedule")
        self.delete_btn = QPushButton("Delete")
        run_bar = QHBoxLayout()
        run_bar.addWidget(QLabel("<b>Run:</b>"))
        run_bar.addWidget(self.run_btn)
        run_bar.addWidget(self.dry_btn)
        run_bar.addSpacing(16)
        run_bar.addWidget(QLabel(f"at ({settings.app_timezone}):"))
        run_bar.addWidget(self.when)
        run_bar.addWidget(self.sched_btn)
        run_bar.addWidget(self.cancel_btn)
        run_bar.addStretch()
        run_bar.addWidget(self.delete_btn)

        self.approve_btn.clicked.connect(self.approve)
        self.deny_btn.clicked.connect(self.deny)
        self.edit_btn.clicked.connect(self.start_edit)
        self.save_edit_btn.clicked.connect(self.save_edit)
        self.discard_edit_btn.clicked.connect(lambda: self._set_editing(False))
        self.run_btn.clicked.connect(self.run_now)
        self.dry_btn.clicked.connect(self.dry_run)
        self.sched_btn.clicked.connect(self.schedule)
        self.cancel_btn.clicked.connect(self.cancel)
        self.delete_btn.clicked.connect(self.delete)

        lay = QVBoxLayout(w)
        top = QHBoxLayout()
        top.addWidget(back)
        top.addWidget(self.d_title, 1)
        lay.addLayout(top)
        lay.addWidget(self.d_meta)
        lay.addWidget(self.script_label)
        lay.addWidget(self.edit_help)
        lay.addWidget(self.d_text, 1)
        lay.addWidget(self.d_editor, 1)
        lay.addWidget(review)
        lay.addLayout(run_bar)
        lay.addWidget(QLabel("<b>Result</b>"))
        lay.addWidget(self.d_result)
        lay.addWidget(QLabel("<i>Scheduled scripts run only while CloudAI is open. Scripts run with your "
                             "'Write' connection (Connections page).</i>"))
        return w

    def show_list(self):
        if self.editing and not self._confirm_discard():
            return
        self._set_editing(False)
        self.stack.setCurrentIndex(0)
        self.refresh()

    def open_script(self, script_id: int):
        self.pool.start(scripts.get_script, self.owner, script_id, on_done=self._show_detail,
                        on_fail=self._open_failed)

    def _open_failed(self, msg: str):
        QMessageBox.information(self, "Script", msg)
        self.current = None
        self.stack.setCurrentIndex(0)
        self.refresh()

    def _show_detail(self, row: dict):
        self.current = row
        self._set_editing(False)
        warn = "  <span style='color:#c0392b'>⚠ DESTRUCTIVE (needs a typed confirmation)</span>" if row["destructive"] else ""
        self.d_title.setText(f"<h3>Script #{row['id']}: {row['title']}{warn}</h3>")
        meta = [f"<b>Status:</b> {STATUS_ICON.get(row['status'], row['status'])}",
                f"<b>Region:</b> {row['region']}", f"<b>Steps:</b> {len(row['steps'])}",
                f"<b>Created:</b> {fmt_time(row['created_at'])}"]
        if row["approved_at"]:
            meta.append(f"<b>Approved:</b> {fmt_time(row['approved_at'])}")
        if row["run_at"]:
            meta.append(f"<b>Scheduled for:</b> {fmt_time(row['run_at'])} {settings.app_timezone}")
        if row["last_run_at"]:
            meta.append(f"<b>Last run:</b> {fmt_time(row['last_run_at'])}")
        self.d_meta.setText(" · ".join(meta) + f"<br><b>Your request:</b> {row['request'] or ''}")
        self.d_text.setPlainText(row["script_text"])
        self.d_result.setPlainText(row["result"] or "")
        self._update_buttons()
        default = (row["run_at"].astimezone(LOCAL_TZ) if row["run_at"]
                   else datetime.now(LOCAL_TZ) + timedelta(minutes=10))
        self.when.setDateTime(QDateTime(default.year, default.month, default.day, default.hour, default.minute, 0))
        self.stack.setCurrentIndex(1)

    def _update_buttons(self):
        st = self.current["status"] if self.current else ""
        runnable = st in scripts.RUNNABLE
        e = self.editing
        self.approve_btn.setEnabled(not e and st in ("draft", "denied"))
        self.deny_btn.setEnabled(not e and st in ("draft", "approved", "scheduled", "failed"))
        self.edit_btn.setEnabled(not e and st not in ("running",))
        self.run_btn.setEnabled(not e and runnable)
        self.sched_btn.setEnabled(not e and runnable)
        self.when.setEnabled(not e and runnable)
        self.cancel_btn.setEnabled(not e and st == "scheduled")
        self.dry_btn.setEnabled(not e and st != "running")
        self.delete_btn.setEnabled(not e and st != "running")
        hint = {"draft": "Read the script, then Approve or Deny it. Run and Schedule unlock after you approve.",
                "approved": "Approved. You can Run now or Schedule it.",
                "denied": "Denied. It cannot run. Approve it if you change your mind, edit it, or delete it.",
                "scheduled": "Approved and scheduled.", "running": "Running…",
                "succeeded": "Finished. Edit it if you want to run a changed version (needs approval again).",
                "failed": "The last run failed. You can run it again (still approved) or edit it."}.get(st, "")
        tip = "" if runnable else "Approve the script first"
        for b in (self.run_btn, self.sched_btn):
            b.setToolTip(tip)
        self.review_state.setText(f"<i>{hint}</i>")

    # ================= review: approve / deny / edit =================
    def _reload(self, row=None):
        if row:
            self._show_detail(row)
        elif self.current:
            self.open_script(self.current["id"])
        self.refresh()
        self.on_activity()

    def approve(self):
        if QMessageBox.question(self, "Approve script",
                                f"Approve script #{self.current['id']}?\n\n{self.current['title']}\n\n"
                                "Approving does not run it yet; you can then Run now or Schedule it.") != QMessageBox.Yes:
            return
        self.pool.start(scripts.approve_script, self.owner, self.current["id"], on_done=self._reload,
                        on_fail=self._error)

    def deny(self):
        reason, ok = QInputDialog.getText(self, "Deny script",
                                          f"Deny script #{self.current['id']}? It will not be able to run.\n"
                                          "Reason (optional):")
        if not ok:
            return
        self.pool.start(scripts.deny_script, self.owner, self.current["id"], reason, on_done=self._reload,
                        on_fail=self._error)

    def _set_editing(self, on: bool):
        self.editing = on
        self.d_text.setVisible(not on)
        self.d_editor.setVisible(on)
        self.edit_help.setVisible(on)
        self.save_edit_btn.setVisible(on)
        self.discard_edit_btn.setVisible(on)
        self.edit_btn.setVisible(not on)
        self.script_label.setText("<b>Edit script</b> (steps that will run)" if on
                                  else "<b>Script</b> (read it before approving)")
        if self.current:
            self._update_buttons()

    def start_edit(self):
        if self.current["status"] == "scheduled" and QMessageBox.question(
                self, "Edit script", "Editing cancels the schedule and the approval. Continue?") != QMessageBox.Yes:
            return
        self.d_editor.setPlainText(scripts.editable_steps_text(self.current))
        self._set_editing(True)

    def save_edit(self):
        text = self.d_editor.toPlainText()
        self.save_edit_btn.setEnabled(False)
        self.pool.start(scripts.update_steps, self.owner, self.current["id"], text,
                        on_done=lambda row: (self.save_edit_btn.setEnabled(True), self._reload(row),
                                             self.d_result.setPlainText("Saved. The script was checked again and "
                                                                        "now needs your approval.")),
                        on_fail=lambda m: (self.save_edit_btn.setEnabled(True),
                                           QMessageBox.warning(self, "Not saved", m)))

    def _confirm_discard(self) -> bool:
        return QMessageBox.question(self, "Unsaved changes", "Discard your edits?") == QMessageBox.Yes

    def _error(self, msg: str):
        QMessageBox.warning(self, "Script", msg)
        if "no longer exists" in msg:
            self._open_failed(msg)

    # ================= run =================
    def _confirm(self, verb: str) -> str | None:
        """Destructive scripts need a typed confirmation. Returns the typed text, or None if cancelled."""
        row = self.current
        if not row["destructive"]:
            ok = QMessageBox.question(self, f"{verb} script", f"{verb} script #{row['id']}: {row['title']}?")
            return "" if ok == QMessageBox.Yes else None
        phrase = scripts.confirm_phrase(row["id"])
        text, ok = QInputDialog.getText(self, "Typed confirmation required",
                                        f"This script deletes or removes AWS resources.\nType exactly:  {phrase}")
        return text if ok else None

    def _after_run(self, r: dict):
        self.d_result.setPlainText(("✅ Finished\n" if r["ok"] else "❌ Failed\n") + r["log"])
        self.refresh()
        self.on_activity()
        if self.current:
            self.pool.start(scripts.get_script, self.owner, self.current["id"],
                            on_done=lambda row: (setattr(self, "current", row), self._update_buttons()))

    def run_now(self):
        typed = self._confirm("Run")
        if typed is None:
            return
        self.run_btn.setEnabled(False)
        self.d_result.setPlainText("Running… (steps that wait, like a NAT gateway, can take a few minutes)")
        self.pool.start(scripts.run_script, self.owner, self.current["id"], self.conn, typed,
                        on_done=self._after_run, on_fail=lambda m: (self.d_result.setPlainText(f"❌ {m}"),
                                                                    self._update_buttons()))

    def dry_run(self):
        self.d_result.setPlainText("Checking (dry run, nothing is changed)…")
        self.pool.start(scripts.run_script, self.owner, self.current["id"], self.conn, dry_run=True,
                        on_done=lambda r: self.d_result.setPlainText(
                            {True: "Dry run OK\n", False: "Dry run found a problem\n"}.get(r["ok"], "") + r["log"]),
                        on_fail=lambda m: self.d_result.setPlainText(f"❌ {m}"))

    def schedule(self):
        q = self.when.dateTime()
        d, t = q.date(), q.time()
        run_at = datetime(d.year(), d.month(), d.day(), t.hour(), t.minute(), tzinfo=LOCAL_TZ)
        typed = self._confirm(f"Schedule for {run_at:%Y-%m-%d %H:%M} —")
        if typed is None:
            return
        self.pool.start(scripts.schedule_script, self.owner, self.current["id"], run_at, typed,
                        on_done=self._reload, on_fail=self._error)

    def cancel(self):
        self.pool.start(scripts.cancel_script, self.owner, self.current["id"], on_done=lambda _: self._reload(),
                        on_fail=self._error)

    def delete(self):
        if QMessageBox.question(self, "Delete script", f"Delete script #{self.current['id']}? "
                                "(This only deletes the script, not anything in AWS.)") != QMessageBox.Yes:
            return
        self.pool.start(scripts.delete_script, self.owner, self.current["id"],
                        on_done=lambda _: (setattr(self, "current", None), self.show_list()), on_fail=self._error)

    # ================= timer (every 30 s from the main window) =================
    def tick(self, on_ran):
        """Run due scheduled scripts and keep the list fresh (scripts can change from chat or other runs)."""
        self.pool.start(scripts.run_due_scripts, self.owner, self.conn,
                        on_done=lambda results: (results and on_ran(results), self.refresh()))
