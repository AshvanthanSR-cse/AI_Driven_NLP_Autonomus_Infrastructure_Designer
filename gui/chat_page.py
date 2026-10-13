"""Chat page: questions are answered here directly; write requests become scripts (Scripts page).
Files and folders can be attached (buttons or drag & drop); only their paths are used, never sent as content.
Before anything is built, a prerequisites card lists what must already exist (missing items block the build)."""
import html
import re
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QTextDocument
from PySide6.QtWidgets import (
    QComboBox, QFileDialog, QFormLayout, QFrame, QGroupBox, QHBoxLayout, QLabel, QLineEdit, QListWidget,
    QListWidgetItem, QPushButton, QScrollArea, QSpinBox, QTextBrowser, QVBoxLayout, QWidget,
)

from core import agent, db, prereqs, recipes, templates
from core.tools import ToolContext, describe_attachment
from gui.theme import ACCENT, BORDER, MUTED, primary

BUBBLE = {"user": ("You", "#e8efff"), "assistant": ("Kintsugi", "#ffffff"), "note": ("", "#f6f7f9")}


class ScriptCard(QFrame):
    def __init__(self, saved: dict, on_open):
        super().__init__()
        self.setStyleSheet(f"ScriptCard {{ background: white; border: 1px solid {BORDER}; "
                           f"border-left: 4px solid {ACCENT}; border-radius: 8px; }}")
        lay = QHBoxLayout(self)
        warn = "  (destructive)" if saved.get("destructive") else ""
        lay.addWidget(QLabel(f"Script #{saved['id']} saved: <b>{saved['title']}</b>{warn} · "
                             f"<i>waiting for your Approve / Deny</i>"), 1)
        btn = primary(QPushButton("Open script"))
        btn.clicked.connect(lambda: on_open(saved["id"]))
        lay.addWidget(btn)


class PathPicker(QWidget):
    """Text box + Browse button for a local folder or file (e.g. the site folder, the SSH key)."""

    def __init__(self, kind: str, value: str = ""):
        super().__init__()
        self.kind = kind
        self.edit = QLineEdit(value)
        self.edit.setPlaceholderText("D:\\path\\to\\folder" if kind == "folder" else "D:\\path\\to\\file")
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addWidget(self.edit, 1)
        for label, mode in ((("File...", "file"), ("Folder...", "folder")) if kind == "path" else (("Browse...", kind),)):
            btn = QPushButton(label)
            btn.clicked.connect(lambda _=False, m=mode: self._browse(m))
            lay.addWidget(btn)

    def _browse(self, mode: str):
        start = self.edit.text().strip() or ""
        if mode == "folder":
            path = QFileDialog.getExistingDirectory(self, "Choose a folder", start)
        else:
            filt = "SSH key (*.pem);;All files (*)" if self.kind == "file" else "All files (*)"
            path, _ = QFileDialog.getOpenFileName(self, "Choose a file", start, filt)
        if path:
            self.edit.setText(path.replace("/", "\\"))

    def text(self) -> str:
        return self.edit.text().strip().strip('"')


def prereq_rows(report: dict, compact: bool = False) -> str:
    """HTML lines of a prerequisites checklist (icons + what to do)."""
    colors = {"missing": "#c0392b", "ready": "#1e8449", "manual": "#9c640c", "unknown": "#7f8c8d"}
    rows = []
    for i in report["items"]:
        color = colors.get(i["status"], "inherit")
        line = (f"{prereqs.STATUS_ICON[i['status']]} <b>{html.escape(i['title'])}</b>"
                f"{'' if i['required'] else ' (optional)'} - "
                f"<span style='color:{color}'>{prereqs.status_text(i)}</span>")
        if i["found"] and not compact:
            line += "<br>&nbsp;&nbsp;&nbsp;&nbsp;found: " + html.escape(", ".join(i["found"][:4]))
        if i["how"] and i["status"] in ("missing", "manual", "unknown") and not compact:
            line += "<br>&nbsp;&nbsp;&nbsp;&nbsp;<i>how: " + html.escape(i["how"]) + "</i>"
        rows.append(line)
    return "<br>".join(rows)


class PrereqCard(QGroupBox):
    """What must exist before building (core/prereqs.py). Missing items block the build: 'Check again'."""

    def __init__(self, payload: dict, on_recheck, on_close):
        blocking = payload["blocking"]
        super().__init__(("Create these first: " if blocking else "Prerequisites: ") + payload["title"])
        self.payload = payload
        self.setStyleSheet(f"QGroupBox {{ font-weight: bold; border: 1px solid "
                           f"{'#c0392b' if blocking else '#1e8449'}; border-radius: 6px; margin-top: 10px; "
                           f"padding-top: 12px; }}")
        lay = QVBoxLayout(self)
        head = QLabel("Nothing is built until the missing items exist. Create them (the 'how' line says how), "
                      "then click Check again." if blocking else
                      "Everything required is in place." + (" Ask to build it when ready." if not payload.get(
                          "template") else ""))
        head.setWordWrap(True)
        head.setStyleSheet("font-weight: normal;")
        lay.addWidget(head)
        body = QLabel(prereq_rows(payload))
        body.setWordWrap(True)
        body.setTextFormat(Qt.RichText)
        body.setStyleSheet("font-weight: normal;")
        lay.addWidget(body)
        for note in payload.get("notes", []):
            n = QLabel(note)
            n.setWordWrap(True)
            n.setStyleSheet("font-weight: normal; color: gray;")
            lay.addWidget(n)
        row = QHBoxLayout()
        row.addStretch()
        close, again = QPushButton("Close"), QPushButton("Check again")
        primary(again)
        row.addWidget(close)
        row.addWidget(again)
        lay.addLayout(row)
        again.clicked.connect(lambda: on_recheck(self))
        close.clicked.connect(lambda: on_close(self))


class QuestionCard(QGroupBox):
    """Form for the questions of a task template (VPC, EC2 ...). Options come from the user's AWS account."""

    def __init__(self, payload: dict, on_submit, on_cancel):
        super().__init__(f"Details needed: {payload['title']}")
        self.payload, self.widgets = payload, {}
        self.setStyleSheet("QGroupBox { font-weight: bold; border: 1px solid #b9770e; border-radius: 6px; "
                           "margin-top: 10px; padding-top: 12px; }")
        lay = QVBoxLayout(self)
        if payload.get("prerequisites"):
            pre = QLabel("<b>Prerequisites</b><br>" + prereq_rows(payload["prerequisites"], compact=True))
            pre.setWordWrap(True)
            pre.setTextFormat(Qt.RichText)
            pre.setStyleSheet("font-weight: normal;")
            lay.addWidget(pre)
        for note in payload.get("notes", []):
            n = QLabel(note)
            n.setWordWrap(True)
            n.setStyleSheet("font-weight: normal; color: #9c640c;")
            lay.addWidget(n)
        form = QFormLayout()
        for q in payload["questions"]:
            widget = self._widget(q)
            self.widgets[q["key"]] = (q, widget)
            label = QLabel(q["question"])
            label.setWordWrap(True)
            label.setToolTip(q.get("why", ""))
            label.setStyleSheet("font-weight: normal;")
            box = QVBoxLayout()
            box.addWidget(widget)
            hint = q.get("why", "")
            if q.get("error"):
                hint = f"<span style='color:#c0392b'>{q['error']}</span>" + (f"<br>{hint}" if hint else "")
            if hint:
                h = QLabel(hint)
                h.setWordWrap(True)
                h.setStyleSheet("font-weight: normal; color: gray;")
                box.addWidget(h)
            form.addRow(label, box)
        lay.addLayout(form)
        row = QHBoxLayout()
        row.addStretch()
        cancel, ok = QPushButton("Cancel"), QPushButton("Create script")
        primary(ok)
        row.addWidget(cancel)
        row.addWidget(ok)
        lay.addLayout(row)
        ok.clicked.connect(lambda: on_submit(self, self.values()))
        cancel.clicked.connect(lambda: on_cancel(self))

    @staticmethod
    def _widget(q: dict):
        default = q.get("default")
        if q["kind"] == "choice":
            w = QComboBox()
            w.setEditable(bool(q.get("allow_custom")))
            for o in q.get("options", []):
                w.addItem(str(o["label"]), o["value"])
            idx = w.findData(default)
            if idx >= 0:
                w.setCurrentIndex(idx)
            return w
        if q["kind"] == "multichoice":
            w = QListWidget()
            chosen = default if isinstance(default, list) else []
            for o in q.get("options", []):
                item = QListWidgetItem(str(o["label"]))
                item.setData(Qt.UserRole, o["value"])
                item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
                item.setCheckState(Qt.Checked if o["value"] in chosen else Qt.Unchecked)
                w.addItem(item)
            w.setMaximumHeight(min(110, 22 * max(1, w.count()) + 6))
            return w
        if q["kind"] in ("folder", "file", "path"):
            return PathPicker(q["kind"], "" if default is None else str(default))
        if q["kind"] == "number":
            w = QSpinBox()
            w.setRange(0, 2_000_000_000)
            w.setValue(int(default) if str(default).isdigit() else 0)
            return w
        return QLineEdit("" if default is None else str(default))

    def values(self) -> dict:
        out = {}
        for key, (q, w) in self.widgets.items():
            if isinstance(w, QComboBox):
                out[key] = w.currentData() if w.currentData() is not None else w.currentText()
            elif isinstance(w, QListWidget):
                out[key] = [w.item(i).data(Qt.UserRole) for i in range(w.count())
                            if w.item(i).checkState() == Qt.Checked]
            elif isinstance(w, QSpinBox):
                out[key] = w.value()
            elif isinstance(w, PathPicker):
                out[key] = w.text()
            else:
                out[key] = w.text().strip()
        return out


class ChatPage(QWidget):
    def __init__(self, pool, conn, on_activity, on_open_script):
        super().__init__()
        self.pool, self.conn = pool, conn
        self.on_activity, self.on_open_script = on_activity, on_open_script
        self.history: list[dict] = []
        self.blocks: list[tuple[str, str]] = []
        self.conversation_id = None
        self.pending_task: dict | None = None
        self.attachments: list[dict] = []
        self.setAcceptDrops(True)

        self.view = QTextBrowser()
        self.view.setOpenExternalLinks(True)
        self.view.setAcceptDrops(False)
        self.cards_box = QVBoxLayout()
        self.cards_box.addStretch()
        cards_w = QWidget()
        cards_w.setLayout(self.cards_box)
        self.cards = QScrollArea()
        self.cards.setWidget(cards_w)
        self.cards.setWidgetResizable(True)
        self.cards.setMaximumHeight(130)
        self.cards.hide()

        self.input = QLineEdit()
        self.input.setAcceptDrops(False)
        self.input.setPlaceholderText("Ask a question, or ask for a change (it becomes a script)...")
        self.send_btn = primary(QPushButton("Send"))
        self.input.setMinimumHeight(34)
        self.status = QLabel("")
        self.status.setStyleSheet(f"color: {MUTED};")
        attach_file = QPushButton("File...")
        attach_file.setToolTip("Attach files (a document, a Dockerfile, a key file...). Only the path is used.")
        attach_file.clicked.connect(self._pick_files)
        attach_dir = QPushButton("Folder...")
        attach_dir.setToolTip("Attach a folder (a website, app, Terraform or Lambda code)")
        attach_dir.clicked.connect(self._pick_folder)
        new_task = QPushButton("New task")
        new_task.setToolTip("Forget the earlier messages so the next request starts clean")
        new_task.clicked.connect(self.new_task)
        self.chips = QHBoxLayout()
        self.chips.addStretch()
        chips_w = QWidget()
        chips_w.setLayout(self.chips)
        self.chips_w = chips_w
        chips_w.hide()
        row = QHBoxLayout()
        row.addWidget(attach_file)
        row.addWidget(attach_dir)
        row.addWidget(self.input, 1)
        row.addWidget(self.send_btn)
        row.addWidget(new_task)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 12, 16, 12)
        lay.setSpacing(8)
        lay.addWidget(self.view, 1)
        lay.addWidget(self.cards)
        lay.addWidget(self.status)
        lay.addWidget(chips_w)
        lay.addLayout(row)

        self.input.returnPressed.connect(self.send)
        self.send_btn.clicked.connect(self.send)
        self._render()

    @staticmethod
    def _md_html(md: str) -> str:
        doc = QTextDocument()
        doc.setMarkdown(md)
        m = re.search(r"<body[^>]*>(.*)</body>", doc.toHtml(), re.S)
        return m.group(1) if m else html.escape(md)

    def _render(self):
        parts = []
        for role, md in self.blocks:
            who, bg = BUBBLE.get(role, BUBBLE["note"])
            color = ACCENT if role == "user" else MUTED
            head = f"<p style='color:{color}; font-size:9pt; font-weight:600; margin:0'>{who}</p>" if who else ""
            left = "14%" if role == "user" else "0"
            right = "14%" if role == "assistant" else "0"
            parts.append(f"<table width='100%' cellspacing='0' cellpadding='10' style='margin-bottom:10px'>"
                         f"<tr><td width='{left}'></td><td bgcolor='{bg}' style='border:1px solid {BORDER}'>"
                         f"{head}{self._md_html(md)}</td><td width='{right}'></td></tr></table>")
        self.view.setHtml("".join(parts))
        self.view.verticalScrollBar().setValue(self.view.verticalScrollBar().maximum())

    def append(self, md: str, role: str = "note"):
        self.blocks.append((role, md))
        self._render()

    def _busy(self, busy: bool, text: str = ""):
        self.input.setEnabled(not busy)
        self.send_btn.setEnabled(not busy)
        self.status.setText(text)
        if not busy:
            self.input.setFocus()

    def _pick_files(self):
        paths, _ = QFileDialog.getOpenFileNames(self, "Attach files")
        for p in paths:
            self.add_attachment(p)

    def _pick_folder(self):
        p = QFileDialog.getExistingDirectory(self, "Attach a folder")
        if p:
            self.add_attachment(p)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event):
        for url in event.mimeData().urls():
            if url.isLocalFile():
                self.add_attachment(url.toLocalFile())

    def add_attachment(self, path: str):
        path = str(Path(path).resolve())
        if any(a["path"] == path for a in self.attachments):
            return
        info = describe_attachment(path)
        self.attachments.append(info)
        chip = QPushButton(f"{Path(path).name}  x")
        chip.setToolTip(f"{path}\nClick to remove")
        chip.setStyleSheet(f"QPushButton {{ border: 1px solid {BORDER}; border-radius: 11px; padding: 3px 10px; "
                           f"background: #eef2ff; }}")
        chip.clicked.connect(lambda _=False, p=path, c=chip: self._remove_attachment(p, c))
        self.chips.insertWidget(self.chips.count() - 1, chip)
        self.chips_w.show()
        self.input.setFocus()

    def _remove_attachment(self, path: str, chip):
        self.attachments = [a for a in self.attachments if a["path"] != path]
        chip.setParent(None)
        chip.deleteLater()
        self.chips_w.setVisible(bool(self.attachments))

    def _clear_attachments(self):
        while self.chips.count() > 1:
            w = self.chips.takeAt(0).widget()
            if w:
                w.deleteLater()
        self.attachments = []
        self.chips_w.hide()

    def send(self):
        text = self.input.text().strip()
        if not text and not self.attachments:
            return
        attachments = list(self.attachments)
        if not text:
            text = "What can you do with these files?"
        self.input.clear()
        shown = "".join(f"\n\nAttached: `{a['path']}` ({a['kind']}, {a['type']})" for a in attachments)
        self.append(f"{text}{shown}", "user")
        self._clear_attachments()
        self._busy(True, "Thinking... (local LLM + AWS calls)")
        self.pool.start(self._ask, text, list(self.history), self.pending_task, attachments,
                        on_done=lambda res, t=text: self._on_answer(t, res), on_fail=self._on_fail)

    def _ask(self, text: str, history: list[dict], pending: dict | None,
             attachments: list[dict] | None = None) -> agent.AgentResult:
        """Worker thread: save the message, run the agent, save the answer."""
        if self.conversation_id is None:
            self.conversation_id = db.new_conversation(text)
        note = "".join(f"\n[attached: {a['path']}]" for a in attachments or [])
        db.save_message(self.conversation_id, "user", text + note)
        res = agent.run(text, ToolContext(conn=self.conn), history, pending_task=pending, attachments=attachments)
        db.save_message(self.conversation_id, "assistant", res.text)
        return res

    def _on_answer(self, question: str, res: agent.AgentResult):
        self._busy(False)
        meta = []
        if res.tools_used:
            meta.append("tools: " + ", ".join(res.tools_used))
        if res.used_fallback:
            meta.append("keyword router used")
        md = res.text
        if meta:
            md += f"\n\n*{' · '.join(meta)}*"
        self.append(md, "assistant")
        prev = self.pending_task
        same_task = bool(res.questions and prev and prev.get("template") == res.questions.get("template"))
        if res.questions and not same_task:
            self.history = []
        self.history += [{"role": "user", "content": question}, {"role": "assistant", "content": res.text}]
        if res.questions:
            req = prev.get("request", question) if same_task else question
            self._show_questions({**res.questions, "request": req})
        elif res.scripts:
            self._clear_question_cards()
        elif res.prerequisites:
            self._clear_question_cards()
            self._show_prereqs({**res.prerequisites, "request": question})
        if res.scripts:
            self.history = []
        for saved in res.scripts:
            self._add_script_card(saved)
        self.on_activity()

    def new_task(self):
        """Forget earlier messages and open questions (the chat text stays visible)."""
        self.history = []
        self._clear_question_cards()
        self._clear_prereq_cards()
        self.append("*New task: earlier messages will not be used.*")

    def _add_card(self, widget, tall: bool = False):
        self.cards_box.insertWidget(self.cards_box.count() - 1, widget)
        self.cards.setMaximumHeight(460 if tall or self.findChildren(QuestionCard) or self.findChildren(PrereqCard)
                                    else 130)
        self.cards.show()

    def _add_script_card(self, saved: dict):
        self._add_card(ScriptCard(saved, self.on_open_script))

    def _clear_question_cards(self):
        for c in self.findChildren(QuestionCard):
            c.setParent(None)
            c.deleteLater()
        self.pending_task = None
        self.cards.setMaximumHeight(130)

    def _show_questions(self, payload: dict):
        self._clear_question_cards()
        self._clear_prereq_cards()
        self.pending_task = payload
        self._add_card(QuestionCard(payload, self._submit_answers, self._cancel_questions), tall=True)

    def _submit_answers(self, card, values: dict):
        p = self.pending_task or card.payload
        inputs = {**p.get("inputs", {}), **values}
        self._busy(True, "Checking your answers and writing the script...")
        self.pool.start(templates.submit, self.conn.owner, p.get("request", ""), p["template"], inputs, self.conn,
                        on_done=lambda r: self._after_submit(p, r), on_fail=self._on_fail)

    def _show_prereqs(self, payload: dict):
        self._clear_prereq_cards()
        self._add_card(PrereqCard(payload, self._recheck_prereqs, self._close_prereqs), tall=True)

    def _clear_prereq_cards(self):
        for c in self.findChildren(PrereqCard):
            c.setParent(None)
            c.deleteLater()

    def _close_prereqs(self, card):
        self._clear_prereq_cards()

    def _recheck_prereqs(self, card):
        p = card.payload
        self._busy(True, "Checking the prerequisites again in your AWS account...")
        self.pool.start(prereqs.recheck, self.conn.owner, self.conn, p, p.get("request", ""),
                        on_done=lambda r: self._after_submit(p, r), on_fail=self._on_fail)

    def _after_submit(self, payload: dict, result: dict):
        self._busy(False)
        if "prerequisites" in result:
            self._clear_question_cards()
            r = result["prerequisites"]
            self.append(f"**Prerequisites still missing:** {', '.join(r['missing'])}. Create them first, then "
                        f"click **Check again**." if r["blocking"] else "**Prerequisites:** everything required "
                        "is in place.")
            self._show_prereqs({**r, "request": payload.get("request", "")})
            self.on_activity()
            return
        self._clear_prereq_cards()
        if "questions" in result:
            self.append("Some answers need another look. Please check the highlighted fields.")
            self._show_questions({**result["questions"], "request": payload.get("request", "")})
        else:
            saved = result["script"]
            self._clear_question_cards()
            self.history = []
            self.append(f"**Script #{saved['id']} saved:** {saved['title']}. Open it, read every step, then "
                        f"click **Approve** or **Deny**. After approving you can **Run now** or **Schedule** it.")
            self._add_script_card(saved)
        self.on_activity()

    def _cancel_questions(self, card):
        self._clear_question_cards()
        self.history = []
        self.append("Cancelled. No script was created.")

    def _on_fail(self, msg: str):
        self._busy(False)
        self.append(f"**Error:** {msg}")
        self.on_activity()
