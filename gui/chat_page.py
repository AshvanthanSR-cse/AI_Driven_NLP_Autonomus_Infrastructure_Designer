"""Chat page: questions are answered here directly; write requests become scripts (Scripts page)."""
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox, QFormLayout, QFrame, QGroupBox, QHBoxLayout, QLabel, QLineEdit, QListWidget, QListWidgetItem,
    QPushButton, QScrollArea, QSpinBox, QTextBrowser, QVBoxLayout, QWidget,
)

from core import agent, db, templates
from core.config import settings
from core.tools import ToolContext

WELCOME = f"""**CloudAI** — ask about your AWS account in plain language (region {settings.aws_region}, times in {settings.app_timezone}).

**Questions are answered here:** *What are the running instances?* · *What Lambda functions are scheduled to run after 10am?* · *Give me the URL of the ALB* · *Extract the lambda cloudai-demo-hello code* · *What did I spend in the last 30 days?*

**Building infrastructure asks you first:** *Create a VPC with 2 public and 2 private subnets and a NAT gateway* · *Create an EC2 instance* → CloudAI asks for the details (IP range, subnet, OS, security group…) with options from your account.

**Changes become scripts:** *Stop instance web-demo* → a script is saved on the **Scripts** page, where you read it and click **Approve** or **Deny** (or edit it); approved scripts can be **Run now** or **Scheduled**. The AI never sees your keys.

Some things need a human and cannot be automated: account creation, MFA, support cases, Marketplace subscriptions and quota increases.
"""


class ScriptCard(QFrame):
    def __init__(self, saved: dict, on_open):
        super().__init__()
        self.setFrameShape(QFrame.StyledPanel)
        self.setStyleSheet("ScriptCard { border: 1px solid #2e86c1; border-radius: 6px; }")
        lay = QHBoxLayout(self)
        warn = "  ⚠ destructive" if saved.get("destructive") else ""
        lay.addWidget(QLabel(f"📝 Script #{saved['id']} saved: <b>{saved['title']}</b>{warn} · "
                             f"<i>waiting for your Approve / Deny</i>"), 1)
        btn = QPushButton("Open script")
        btn.clicked.connect(lambda: on_open(saved["id"]))
        lay.addWidget(btn)


class QuestionCard(QGroupBox):
    """Form for the questions of a task template (VPC, EC2 ...). Options come from the user's AWS account."""

    def __init__(self, payload: dict, on_submit, on_cancel):
        super().__init__(f"📋 Details needed: {payload['title']}")
        self.payload, self.widgets = payload, {}
        self.setStyleSheet("QGroupBox { font-weight: bold; border: 1px solid #b9770e; border-radius: 6px; "
                           "margin-top: 10px; padding-top: 12px; }")
        lay = QVBoxLayout(self)
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
                hint = f"<span style='color:#c0392b'>⚠ {q['error']}</span>" + (f"<br>{hint}" if hint else "")
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
        ok.setStyleSheet("font-weight: bold;")
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
        if q["kind"] == "number":
            w = QSpinBox()
            w.setRange(0, 1000)
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
            else:
                out[key] = w.text().strip()
        return out


class ChatPage(QWidget):
    def __init__(self, pool, conn, on_activity, on_open_script):
        super().__init__()
        self.pool, self.conn = pool, conn
        self.on_activity, self.on_open_script = on_activity, on_open_script
        self.history: list[dict] = []
        self.blocks: list[str] = [WELCOME]
        self.conversation_id = None
        self.pending_task: dict | None = None   # open questions of a task template

        self.view = QTextBrowser()
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
        self.input.setPlaceholderText("Ask a question, or ask for a change (it becomes a script)…")
        self.send_btn = QPushButton("Send")
        self.status = QLabel("")
        row = QHBoxLayout()
        row.addWidget(self.input, 1)
        row.addWidget(self.send_btn)
        lay = QVBoxLayout(self)
        lay.addWidget(self.view, 1)
        lay.addWidget(self.cards)
        lay.addWidget(self.status)
        lay.addLayout(row)

        self.input.returnPressed.connect(self.send)
        self.send_btn.clicked.connect(self.send)
        self._render()

    def _render(self):
        self.view.setMarkdown("\n\n---\n\n".join(self.blocks))
        self.view.verticalScrollBar().setValue(self.view.verticalScrollBar().maximum())

    def append(self, md: str):
        self.blocks.append(md)
        self._render()

    def _busy(self, busy: bool, text: str = ""):
        self.input.setEnabled(not busy)
        self.send_btn.setEnabled(not busy)
        self.status.setText(text)
        if not busy:
            self.input.setFocus()

    def send(self):
        text = self.input.text().strip()
        if not text:
            return
        self.input.clear()
        self.append(f"**You:** {text}")
        self._busy(True, "Thinking… (local LLM + AWS calls)")
        self.pool.start(self._ask, text, list(self.history), self.pending_task,
                        on_done=lambda res, t=text: self._on_answer(t, res), on_fail=self._on_fail)

    def _ask(self, text: str, history: list[dict], pending: dict | None) -> agent.AgentResult:
        """Worker thread: save the message, run the agent, save the answer."""
        if self.conversation_id is None:
            self.conversation_id = db.new_conversation(text)
        db.save_message(self.conversation_id, "user", text)
        res = agent.run(text, ToolContext(conn=self.conn), history, pending_task=pending)
        db.save_message(self.conversation_id, "assistant", res.text)
        return res

    def _on_answer(self, question: str, res: agent.AgentResult):
        self._busy(False)
        meta = []
        if res.tools_used:
            meta.append("tools: " + ", ".join(res.tools_used))
        if res.used_fallback:
            meta.append("keyword router used")
        md = f"**CloudAI:** {res.text}"
        if meta:
            md += f"\n\n*{' · '.join(meta)}*"
        self.append(md)
        self.history += [{"role": "user", "content": question}, {"role": "assistant", "content": res.text}]
        if res.questions:
            req = self.pending_task.get("request", question) if self.pending_task else question
            self._show_questions({**res.questions, "request": req})
        elif res.scripts:
            self._clear_question_cards()
        for saved in res.scripts:
            self._add_script_card(saved)
        self.on_activity()

    # ---- cards ----
    def _add_card(self, widget, tall: bool = False):
        self.cards_box.insertWidget(self.cards_box.count() - 1, widget)
        self.cards.setMaximumHeight(460 if tall or self.findChildren(QuestionCard) else 130)
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
        self.pending_task = payload
        self._add_card(QuestionCard(payload, self._submit_answers, self._cancel_questions), tall=True)

    def _submit_answers(self, card, values: dict):
        p = self.pending_task or card.payload
        inputs = {**p.get("inputs", {}), **values}
        self._busy(True, "Checking your answers and writing the script…")
        self.pool.start(templates.submit, self.conn.owner, p.get("request", ""), p["template"], inputs, self.conn,
                        on_done=lambda r: self._after_submit(p, r), on_fail=self._on_fail)

    def _after_submit(self, payload: dict, result: dict):
        self._busy(False)
        if "questions" in result:
            self.append("Some answers need another look. Please check the highlighted fields.")
            self._show_questions({**result["questions"], "request": payload.get("request", "")})
        else:
            saved = result["script"]
            self._clear_question_cards()
            self.append(f"📝 **Script #{saved['id']} saved:** {saved['title']}. Open it, read every step, then "
                        f"click **Approve** or **Deny**. After approving you can **Run now** or **Schedule** it.")
            self._add_script_card(saved)
        self.on_activity()

    def _cancel_questions(self, card):
        self._clear_question_cards()
        self.append("Cancelled. No script was created.")

    def _on_fail(self, msg: str):
        self._busy(False)
        self.append(f"**Error:** {msg}")
        self.on_activity()
