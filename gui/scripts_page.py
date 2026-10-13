"""Scripts page: every write request from chat lands here.

Flow: read the script -> Approve or Deny (or edit it yourself) -> Run now or Schedule.
Scripts written by the agent can never run before you approve them; an edited script needs a new approval.
Delete removes only the script from Kintsugi, never anything in AWS (select several in the list, or delete
every script that is still waiting for review or was denied).
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
from gui.common import LOCAL_TZ, fill_table, fmt_time, style_table
from gui.theme import DANGER, SUCCESS, page_title, primary

STATUS_ICON = {"draft": "waiting for your review", "approved": "approved", "denied": "denied",
               "scheduled": "scheduled", "running": "running", "succeeded": "succeeded",
               "failed": "failed", "cancelled": "cancelled"}

DELETE_STYLE = f"QPushButton {{ font-weight: 600; color: {DANGER}; }} QPushButton:disabled {{ color: #a0a7b4; }}"

EDIT_HELP = ("Edit the steps Kintsugi will run (JSON). Each step: service, operation (boto3 names), params; optional "
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

    def _build_list(self) -> QWidget:
        w = QWidget()
        self.table = QTableWidget()
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.cellDoubleClicked.connect(lambda r, _c: self._open_row(r))
        open_btn = primary(QPushButton("Open script"))
        open_btn.clicked.connect(lambda: self._open_row(self.table.currentRow()))
        refresh = QPushButton("Refresh")
        refresh.clicked.connect(self.refresh)
        del_sel = QPushButton("Delete selected")
        del_sel.setStyleSheet(DELETE_STYLE)
        del_sel.setToolTip("Delete the selected scripts (Ctrl/Shift-click to select several). Nothing in AWS is touched.")
        del_sel.clicked.connect(self.delete_selected)
        del_unapproved = QPushButton("Delete all not approved")
        del_unapproved.setStyleSheet(DELETE_STYLE)
        del_unapproved.setToolTip("Delete every script that is still waiting for review or was denied.")
        del_unapproved.clicked.connect(self.delete_unapproved)
        self.list_info = QLabel("")
        top = QHBoxLayout()
        top.addWidget(open_btn)
        top.addWidget(refresh)
        top.addSpacing(16)
        top.addWidget(del_sel)
        top.addWidget(del_unapproved)
        top.addWidget(self.list_info, 1)
        lay = QVBoxLayout(w)
        lay.setContentsMargins(16, 14, 16, 14)
        lay.addWidget(page_title("Scripts", "When you ask the AI to change something, it writes a script here. "
                                 "Open it, read it, then Approve or Deny it (or edit it yourself). "
                                 "Only approved scripts can be run or scheduled."))
        lay.addLayout(top)
        lay.addWidget(self.table, 1)
        style_table(self.table)
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
                               + " · double-click to open · Ctrl/Shift-click to select several")
        for i, r in enumerate(rows):
            if r["id"] == selected:
                self.table.selectRow(i)

    def _selected_ids(self) -> list[int]:
        rows = sorted({i.row() for i in self.table.selectedIndexes()})
        return [self.rows[r]["id"] for r in rows if 0 <= r < len(self.rows)]

    def delete_selected(self):
        ids = self._selected_ids()
        if not ids:
            self.list_info.setText("Select one or more scripts first (Ctrl/Shift-click for several).")
            return
        listing = ", ".join(f"#{i}" for i in ids)
        if QMessageBox.question(self, "Delete scripts", f"Delete {len(ids)} script(s): {listing}?\n\n"
                                "This deletes only the scripts in Kintsugi, not anything in AWS. "
                                "A deleted teardown script cannot be recovered.") != QMessageBox.Yes:
            return
        self.pool.start(scripts.delete_scripts, self.owner, ids, on_done=self._deleted,
                        on_fail=lambda m: QMessageBox.warning(self, "Delete", m))

    def delete_unapproved(self):
        n = sum(r["status"] in ("draft", "denied") for r in self.rows)
        if not n:
            self.list_info.setText("No scripts are waiting for review or denied.")
            return
        if QMessageBox.question(self, "Delete not approved",
                                f"Delete all {n} script(s) that are waiting for review or were denied?\n\n"
                                "Approved, scheduled and finished scripts are kept. Nothing in AWS is touched."
                                ) != QMessageBox.Yes:
            return
        self.pool.start(scripts.delete_unapproved, self.owner, on_done=self._deleted,
                        on_fail=lambda m: QMessageBox.warning(self, "Delete", m))

    def _deleted(self, res: dict):
        msg = f"Deleted {len(res['deleted'])} script(s)."
        if res["skipped"]:
            msg += " Skipped (running now): " + ", ".join(f"#{i}" for i in res["skipped"]) + "."
        if self.current and self.current["id"] in res["deleted"]:
            self.current = None
        self.on_activity()
        self.pool.start(scripts.list_scripts, self.owner,
                        on_done=lambda rows: (self._show_list(rows), self.list_info.setText(msg)))

    def _open_row(self, r: int):
        if 0 <= r < len(self.rows):
            self.open_script(self.rows[r]["id"])
        else:
            self.list_info.setText("Select a script in the list first.")

    def _build_detail(self) -> QWidget:
        w = QWidget()
        back = QPushButton("< All scripts")
        back.clicked.connect(self.show_list)
        self.d_title = QLabel()
        self.d_title.setTextFormat(Qt.RichText)
        self.d_title.setWordWrap(True)
        self.d_meta = QLabel()
        self.d_meta.setWordWrap(True)
        self.d_meta.setTextInteractionFlags(Qt.TextSelectableByMouse)
        mono = QFont("Consolas")
        mono.setStyleHint(QFont.Monospace)

        self.d_text = QPlainTextEdit()
        self.d_text.setReadOnly(True)
        self.d_text.setFont(mono)
        self.d_editor = QPlainTextEdit()
        self.d_editor.setFont(mono)
        self.d_editor.hide()
        self.edit_help = QLabel(EDIT_HELP)
        self.edit_help.setWordWrap(True)
        self.edit_help.setObjectName("Muted")
        self.edit_help.hide()
        self.script_label = QLabel("<b>Script</b> (read it before approving)")

        self.d_result = QPlainTextEdit()
        self.d_result.setReadOnly(True)
        self.d_result.setFont(mono)
        self.d_result.setMaximumHeight(220)

        self.approve_btn = QPushButton("Approve")
        self.approve_btn.setStyleSheet(f"QPushButton {{ font-weight: 600; color: {SUCCESS}; }} "
                                       f"QPushButton:disabled {{ color: #a0a7b4; }}")
        self.deny_btn = QPushButton("Deny")
        self.deny_btn.setStyleSheet(DELETE_STYLE)
        self.edit_btn = QPushButton("Edit script")
        self.save_edit_btn = QPushButton("Save changes")
        primary(self.save_edit_btn)
        self.discard_edit_btn = QPushButton("Discard changes")
        self.save_edit_btn.hide()
        self.discard_edit_btn.hide()
        self.review_state = QLabel()
        self.delete_btn = QPushButton("Delete script")
        self.delete_btn.setStyleSheet(DELETE_STYLE)
        self.delete_btn.setToolTip("Delete this script from Kintsugi (nothing in AWS is changed)")
        review = QFrame()
        review.setObjectName("Card")
        rl = QHBoxLayout(review)
        rl.addWidget(QLabel("<b>Review:</b>"))
        for b in (self.approve_btn, self.deny_btn, self.edit_btn, self.save_edit_btn, self.discard_edit_btn):
            rl.addWidget(b)
        rl.addWidget(self.review_state, 1)
        rl.addWidget(self.delete_btn)

        self.run_btn = QPushButton("Run now")
        primary(self.run_btn)
        self.dry_btn = QPushButton("Dry run (check only)")
        self.when = QDateTimeEdit()
        self.when.setCalendarPopup(True)
        self.when.setDisplayFormat("yyyy-MM-dd HH:mm")
        self.sched_btn = QPushButton("Schedule")
        self.cancel_btn = QPushButton("Cancel schedule")
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
        lay.setContentsMargins(16, 14, 16, 14)
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
        lay.addWidget(QLabel("<i>Scheduled scripts run only while Kintsugi is open. Scripts run with your "
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
        warn = ("  <span style='color:#c0392b'>Needs a typed confirmation (deletes resources or changes "
                "IAM access)</span>" if row["destructive"] else "")
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
                "scheduled": "Approved and scheduled.", "running": "Running...",
                "succeeded": "Finished. Edit it if you want to run a changed version (needs approval again).",
                "failed": "The last run failed. You can run it again (still approved) or edit it."}.get(st, "")
        tip = "" if runnable else "Approve the script first"
        for b in (self.run_btn, self.sched_btn):
            b.setToolTip(tip)
        self.review_state.setText(f"<i>{hint}</i>")

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

    def _confirm(self, verb: str) -> str | None:
        """Destructive scripts need a typed confirmation. Returns the typed text, or None if cancelled."""
        row = self.current
        if not row["destructive"]:
            ok = QMessageBox.question(self, f"{verb} script", f"{verb} script #{row['id']}: {row['title']}?")
            return "" if ok == QMessageBox.Yes else None
        phrase = scripts.confirm_phrase(row["id"])
        text, ok = QInputDialog.getText(self, "Typed confirmation required",
                                        f"This script deletes AWS resources or changes IAM access.\n"
                                        f"Type exactly:  {phrase}")
        return text if ok else None

    def _after_run(self, r: dict):
        self.d_result.setPlainText(("Finished\n" if r["ok"] else "Failed\n") + r["log"])
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
        self.delete_btn.setEnabled(False)
        self.d_result.setPlainText("Running... live output below. Long steps (NAT gateway, Docker build, EKS cluster "
                                   "creation) can take many minutes; you can keep using the app.")
        self.pool.start(scripts.run_script, self.owner, self.current["id"], self.conn, typed,
                        on_done=self._after_run, on_progress=self._progress,
                        on_fail=lambda m: (self.d_result.setPlainText(f"Error: {m}"), self._update_buttons()))

    def _progress(self, line: str):
        self.d_result.appendPlainText(line)

    def dry_run(self):
        self.d_result.setPlainText("Checking (dry run, nothing is changed)...")
        self.pool.start(scripts.run_script, self.owner, self.current["id"], self.conn, dry_run=True,
                        on_done=lambda r: self.d_result.setPlainText(
                            {True: "Dry run OK\n", False: "Dry run found a problem\n"}.get(r["ok"], "") + r["log"]),
                        on_fail=lambda m: self.d_result.setPlainText(f"Error: {m}"))

    def schedule(self):
        q = self.when.dateTime()
        d, t = q.date(), q.time()
        run_at = datetime(d.year(), d.month(), d.day(), t.hour(), t.minute(), tzinfo=LOCAL_TZ)
        typed = self._confirm(f"Schedule for {run_at:%Y-%m-%d %H:%M} -")
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

    def tick(self, on_ran):
        """Run due scheduled scripts and keep the list fresh (scripts can change from chat or other runs)."""
        self.pool.start(scripts.run_due_scripts, self.owner, self.conn,
                        on_done=lambda results: (results and on_ran(results), self.refresh()))
