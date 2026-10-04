"""Connections page: add AWS access like `aws configure` (name, access key, secret key, region)."""
from PySide6.QtWidgets import (
    QAbstractItemView, QCheckBox, QComboBox, QFormLayout, QGroupBox, QHBoxLayout, QHeaderView, QLabel, QLineEdit,
    QMessageBox, QPushButton, QTableWidget, QVBoxLayout, QWidget,
)

from core import vault
from core.config import settings
from gui.common import AWS_REGIONS, fill_table

USE_FOR = [
    ("Read — answer questions in chat", ["read"]),
    ("Write — run scripts (stop/start, changes)", ["operate"]),
    ("Read and Write", ["read", "operate"]),
]
PURPOSE_LABEL = {"read": "Read", "operate": "Write (scripts)", "deploy": "Deploy"}


class ConnectionsPage(QWidget):
    COLS = [("label", "Connection name"), ("purpose", "Used for"), ("auth_mode", "Type"),
            ("key_hint", "Access key"), ("region", "Region"), ("account_id", "AWS account"),
            ("verified_at", "Verified"), ("last_used_at", "Last used")]

    def __init__(self, pool, owner: str):
        super().__init__()
        self.pool, self.owner = pool, owner
        self.rows: list[dict] = []

        # --- simple form, like `aws configure` ---
        self.name = QLineEdit()
        self.name.setPlaceholderText("e.g. my-aws or cloudai-readonly")
        self.access_key = QLineEdit()
        self.access_key.setPlaceholderText("AKIA...  (IAM → Users → Security credentials → Create access key)")
        self.secret = QLineEdit()
        self.secret.setEchoMode(QLineEdit.Password)
        self.secret.setPlaceholderText("Secret access key — encrypted, never shown again after saving")
        self.show_secret = QCheckBox("show")
        self.show_secret.toggled.connect(
            lambda on: self.secret.setEchoMode(QLineEdit.Normal if on else QLineEdit.Password))
        secret_row = QHBoxLayout()
        secret_row.addWidget(self.secret, 1)
        secret_row.addWidget(self.show_secret)
        self.region = QComboBox()
        self.region.setEditable(True)
        self.region.addItems(AWS_REGIONS)
        self.region.setCurrentText(settings.aws_region)
        self.use_for = QComboBox()
        self.use_for.addItems([u[0] for u in USE_FOR])

        form = QFormLayout()
        form.addRow("Connection name", self.name)
        form.addRow("Access key ID", self.access_key)
        form.addRow("Secret access key", secret_row)
        form.addRow("Region", self.region)
        form.addRow("Use this connection for", self.use_for)

        # --- advanced: profile or assume-role instead of keys ---
        self.advanced = QGroupBox("Advanced: use a local AWS CLI profile or an IAM role instead of keys")
        self.advanced.setCheckable(True)
        self.advanced.setChecked(False)
        self.adv_mode = QComboBox()
        self.adv_mode.addItems(["profile", "assume_role"])
        self.profile = QLineEdit()
        self.profile.setPlaceholderText("profile name from `aws configure --profile NAME` (e.g. default)")
        self.role_arn = QLineEdit()
        self.role_arn.setPlaceholderText("arn:aws:iam::123456789012:role/cloudai-...")
        self.external_id = QLineEdit()
        adv = QFormLayout(self.advanced)
        adv.addRow("Type", self.adv_mode)
        adv.addRow("Profile name", self.profile)
        adv.addRow("Role ARN", self.role_arn)
        adv.addRow("External ID", self.external_id)
        self.advanced.toggled.connect(self._toggle_advanced)

        self.test_btn = QPushButton("Test connection")
        self.save_btn = QPushButton("Save connection")
        self.save_btn.setStyleSheet("font-weight: bold;")
        self.msg = QLabel("Keys are checked with AWS (sts get-caller-identity) before saving. Root keys are "
                          "rejected. The secret is encrypted before it reaches the database and is never "
                          "shown to the AI.")
        self.msg.setWordWrap(True)
        btns = QHBoxLayout()
        btns.addWidget(self.test_btn)
        btns.addWidget(self.save_btn)
        btns.addStretch()

        self.table = QTableWidget()
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.del_btn = QPushButton("Delete selected")
        self.refresh_btn = QPushButton("Refresh")

        lay = QVBoxLayout(self)
        lay.addWidget(QLabel("<h3>Add an AWS connection</h3>Same details you type in <code>aws configure</code>."))
        lay.addLayout(form)
        lay.addWidget(self.advanced)
        lay.addLayout(btns)
        lay.addWidget(self.msg)
        lay.addWidget(QLabel("<b>Your connections</b>"))
        lay.addWidget(self.table, 1)
        row = QHBoxLayout()
        row.addWidget(self.refresh_btn)
        row.addStretch()
        row.addWidget(self.del_btn)
        lay.addLayout(row)

        self.test_btn.clicked.connect(self.test)
        self.save_btn.clicked.connect(self.save)
        self.refresh_btn.clicked.connect(self.refresh)
        self.del_btn.clicked.connect(self.delete)

    def _toggle_advanced(self, on: bool):
        for w in (self.access_key, self.secret, self.show_secret):
            w.setEnabled(not on)

    def _fields(self) -> tuple[str, dict]:
        if self.advanced.isChecked():
            mode = self.adv_mode.currentText()
            return mode, dict(region=self.region.currentText(), profile_name=self.profile.text(),
                              role_arn=self.role_arn.text(), external_id=self.external_id.text())
        return "keys", dict(region=self.region.currentText(), access_key_id=self.access_key.text(),
                            secret=self.secret.text())

    def _busy(self, busy: bool, text: str = ""):
        self.test_btn.setEnabled(not busy)
        self.save_btn.setEnabled(not busy)
        if text:
            self.msg.setText(text)

    def test(self):
        mode, fields = self._fields()
        purposes = USE_FOR[self.use_for.currentIndex()][1]
        self._busy(True, "Checking with AWS…")
        self.pool.start(vault.test_credential, purposes[0], mode, **fields,
                        on_done=lambda ident: self._busy(False, f"✅ Works. Connected as {ident['arn']} "
                                                                f"(account {ident['account']}). Not saved yet."),
                        on_fail=lambda m: self._busy(False, f"❌ {m}"))

    def save(self):
        mode, fields = self._fields()
        name = self.name.text().strip()
        purposes = USE_FOR[self.use_for.currentIndex()][1]
        self.secret.clear()  # wipe the secret from the form immediately
        self.show_secret.setChecked(False)
        self._busy(True, "Checking with AWS and saving…")
        self.pool.start(self._save_all, name, purposes, mode, fields, on_done=self._saved, on_fail=self._failed)

    def _save_all(self, name, purposes, mode, fields):
        """Worker thread. 'Read and Write' saves two entries (one per purpose) with the same access."""
        saved = []
        for p in purposes:
            label = name if len(purposes) == 1 or p == "read" else f"{name} (write)"
            saved.append(vault.add_credential(self.owner, label, p, mode, **fields))
        return saved

    def _saved(self, saved):
        rec = saved[0]
        uses = " + ".join(PURPOSE_LABEL[s["purpose"]] for s in saved)
        self._busy(False, f"✅ Saved '{rec['label']}' for {uses}. Connected as {rec['arn']} "
                          f"(account {rec['account_id']}).")
        for w in (self.name, self.access_key, self.profile, self.role_arn, self.external_id):
            w.clear()
        self.refresh()

    def _failed(self, msg):
        self._busy(False, f"❌ Not saved: {msg}  (re-enter the secret key to try again)")

    def refresh(self):
        self.pool.start(vault.list_credentials, self.owner, on_done=self._show,
                        on_fail=lambda m: self.msg.setText(f"Cannot load connections: {m}"))

    def _show(self, rows):
        self.rows = rows
        fill_table(self.table, rows, self.COLS, fmt={
            "purpose": lambda r: PURPOSE_LABEL.get(r["purpose"], r["purpose"]),
            "key_hint": lambda r: f"****{r['key_hint']}" if r.get("key_hint") else (
                r.get("profile_name") or r.get("role_arn") or ""),
        })

    def delete(self):
        r = self.table.currentRow()
        if r < 0 or r >= len(self.rows):
            self.msg.setText("Select a connection in the table first.")
            return
        row = self.rows[r]
        if QMessageBox.question(self, "Delete connection",
                                f"Delete connection '{row['label']}'? The stored key is removed from "
                                f"CloudAI (it is not deleted in AWS).") != QMessageBox.Yes:
            return
        self.pool.start(vault.delete_credential, self.owner, row["id"],
                        on_done=lambda _: self.refresh(), on_fail=lambda m: self.msg.setText(m))
