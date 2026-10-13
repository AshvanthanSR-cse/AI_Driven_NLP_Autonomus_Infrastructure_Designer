"""Connections page: one form for every cloud. Pick AWS, Azure or Google Cloud at the top.
AWS like `aws configure` (name, access key, secret, region); Azure with the Azure CLI sign-in (az login) or a
service principal; Google Cloud with a service-account JSON key. Same rules for all: verified before saving,
secret encrypted, never shown again, never sent to the AI."""
from pathlib import Path

from PySide6.QtWidgets import (
    QAbstractItemView, QButtonGroup, QCheckBox, QComboBox, QFileDialog, QFormLayout, QFrame, QHBoxLayout,
    QHeaderView, QLabel, QLineEdit, QMessageBox, QPushButton, QScrollArea, QSizePolicy, QStackedWidget, QTableWidget,
    QVBoxLayout, QWidget,
)

from core import clouds, vault
from core.config import settings
from gui.common import AWS_REGIONS, fill_table, style_table
from gui.theme import CLOUD_COLORS, page_title, primary

USE_FOR = [
    ("Read - answer questions in chat", ["read"]),
    ("Write - run scripts (stop/start, changes)", ["operate"]),
    ("Read and Write", ["read", "operate"]),
]
PURPOSE_LABEL = {"read": "Read", "operate": "Write (scripts)", "deploy": "Deploy"}
CLOUDS = [("aws", "AWS"), ("azure", "Azure"), ("gcp", "Google Cloud")]
CLOUD_SHORT = dict(CLOUDS)
AZ_MODES = [("cli", "Azure CLI sign-in (az login) - recommended"), ("sp", "Service principal (client secret)")]


LABEL_WIDTH = 190


class _Form(QFormLayout):
    def addRow(self, label, field=None):
        if field is None:
            return super().addRow(label)
        lbl = QLabel(label) if isinstance(label, str) else label
        lbl.setFixedWidth(LABEL_WIDTH)
        return super().addRow(lbl, field)


def _form(widget: QWidget) -> QFormLayout:
    f = _Form(widget)
    f.setContentsMargins(0, 0, 0, 0)
    f.setHorizontalSpacing(14)
    f.setVerticalSpacing(8)
    return f


def _fit_stack(stack: QStackedWidget):
    for i in range(stack.count()):
        w = stack.widget(i)
        policy = QSizePolicy.Preferred if i == stack.currentIndex() else QSizePolicy.Ignored
        w.setSizePolicy(policy, policy)
        w.adjustSize()
    stack.adjustSize()


def _hint(text: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setObjectName("Muted")
    lbl.setWordWrap(True)
    return lbl


class ConnectionsPage(QWidget):
    COLS = [("provider", "Cloud"), ("label", "Connection name"), ("iam_user", "Owner (user name)"),
            ("purpose", "Used for"), ("auth_mode", "Type"),
            ("key_hint", "Key / identity"), ("region", "Region"), ("scope", "Account / subscription / project"),
            ("verified_at", "Verified"), ("last_used_at", "Last used")]

    def __init__(self, pool, owner: str):
        super().__init__()
        self.pool, self.owner = pool, owner
        self.rows: list[dict] = []
        self._provider_key = "aws"

        self.cloud_group = QButtonGroup(self)
        self.cloud_group.setExclusive(True)
        cloud_row = QHBoxLayout()
        cloud_row.setSpacing(6)
        for i, (key, label) in enumerate(CLOUDS):
            b = QPushButton(label)
            b.setCheckable(True)
            b.setProperty("segment", True)
            b.setStyleSheet(f"QPushButton:checked {{ border-left: 4px solid {CLOUD_COLORS[key]}; }}")
            self.cloud_group.addButton(b, i)
            cloud_row.addWidget(b)
        cloud_row.addStretch()
        self.cloud_group.button(0).setChecked(True)
        self.cloud_group.idClicked.connect(self._cloud_changed)

        self.name = QLineEdit()
        self.name.setPlaceholderText("e.g. my-aws, azure-dev or kintsugi-readonly")
        self.use_for = QComboBox()
        self.use_for.addItems([u[0] for u in USE_FOR])

        self.access_key = QLineEdit()
        self.access_key.setPlaceholderText("AKIA...  (IAM -> Users -> Security credentials -> Create access key)")
        self.secret = QLineEdit()
        self.secret.setEchoMode(QLineEdit.Password)
        self.secret.setPlaceholderText("Secret access key - encrypted, never shown again after saving")
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

        aws_w = QWidget()
        form = _form(aws_w)
        form.addRow("Access key ID", self.access_key)
        form.addRow("Secret access key", secret_row)
        form.addRow("Region", self.region)

        self.advanced = QCheckBox("Advanced: use a local AWS CLI profile or an IAM role instead of keys")
        self.adv_mode = QComboBox()
        self.adv_mode.addItems(["profile", "assume_role"])
        self.profile = QLineEdit()
        self.profile.setPlaceholderText("profile name from `aws configure --profile NAME` (e.g. default)")
        self.role_arn = QLineEdit()
        self.role_arn.setPlaceholderText("arn:aws:iam::123456789012:role/kintsugi-...")
        self.external_id = QLineEdit()
        self.adv_body = QWidget()
        adv = _form(self.adv_body)
        adv.addRow("Type", self.adv_mode)
        adv.addRow("Profile name", self.profile)
        adv.addRow("Role ARN", self.role_arn)
        adv.addRow("External ID", self.external_id)
        self.advanced.toggled.connect(self._toggle_advanced)
        self.adv_body.hide()

        az_w = QWidget()
        az_lay = QVBoxLayout(az_w)
        az_lay.setContentsMargins(0, 0, 0, 0)
        self.az_mode = QComboBox()
        for key, label in AZ_MODES:
            self.az_mode.addItem(label, key)
        mode_form = QWidget()
        _form(mode_form).addRow("Sign-in method", self.az_mode)
        az_lay.addWidget(mode_form)

        cli_w = QWidget()
        cli = _form(cli_w)
        self.az_cli_status = QLabel()
        self.az_cli_status.setWordWrap(True)
        self.az_login_btn = QPushButton("Sign in with az login")
        self.az_login_btn.setToolTip("Opens your browser to sign in to Azure (Azure CLI). No password is stored.")
        self.az_load_btn = QPushButton("Load subscriptions")
        self.az_tenant_hint = QLineEdit()
        self.az_tenant_hint.setPlaceholderText("Tenant ID (optional, only if you have several directories)")
        login_row = QHBoxLayout()
        login_row.addWidget(self.az_login_btn)
        login_row.addWidget(self.az_load_btn)
        login_row.addStretch()
        self.az_subs = QComboBox()
        self.az_subs.setEditable(True)
        self.az_subs.lineEdit().setPlaceholderText("Subscription ID - click Load subscriptions after signing in")
        cli.addRow("Azure CLI", self.az_cli_status)
        cli.addRow("Tenant", self.az_tenant_hint)
        cli.addRow("", login_row)
        cli.addRow("Subscription", self.az_subs)
        cli.addRow("", _hint("Kintsugi asks the Azure CLI for short-lived tokens; nothing secret is stored. Your Azure "
                         "role (Reader, Virtual Machine Contributor ...) decides what Kintsugi can do."))

        sp_w = QWidget()
        az = _form(sp_w)
        self.az_tenant, self.az_client, self.az_sub = QLineEdit(), QLineEdit(), QLineEdit()
        self.az_secret = QLineEdit()
        self.az_secret.setEchoMode(QLineEdit.Password)
        self.az_tenant.setPlaceholderText("Directory (tenant) ID - a GUID")
        self.az_client.setPlaceholderText("Application (client) ID of the service principal")
        self.az_sub.setPlaceholderText("Subscription ID")
        self.az_secret.setPlaceholderText("Client secret - encrypted, never shown again")
        az.addRow("Tenant ID", self.az_tenant)
        az.addRow("Client ID", self.az_client)
        az.addRow("Client secret", self.az_secret)
        az.addRow("Subscription ID", self.az_sub)
        az.addRow("", _hint("Create one with: az ad sp create-for-rbac --name kintsugi --role Reader --scopes "
                        "/subscriptions/<id> (use 'Virtual Machine Contributor' / 'Storage Blob Data "
                        "Contributor' for a Write connection)."))

        self.az_forms = QStackedWidget()
        self.az_forms.addWidget(cli_w)
        self.az_forms.addWidget(sp_w)
        az_lay.addWidget(self.az_forms)
        self.az_mode.currentIndexChanged.connect(self._az_mode_changed)
        self.az_login_btn.clicked.connect(self.az_login)
        self.az_load_btn.clicked.connect(self.az_load_subscriptions)

        self.gcp_key = QLineEdit()
        self.gcp_key.setPlaceholderText("Path to the service-account JSON key file")
        browse = QPushButton("Browse...")
        browse.clicked.connect(lambda: self.gcp_key.setText(
            QFileDialog.getOpenFileName(self, "Service-account key", "", "JSON key (*.json)")[0].replace("/", "\\")
            or self.gcp_key.text()))
        key_row = QHBoxLayout()
        key_row.addWidget(self.gcp_key, 1)
        key_row.addWidget(browse)
        gcp_w = QWidget()
        g = _form(gcp_w)
        g.addRow("Key file", key_row)
        g.addRow("", _hint("IAM & Admin -> Service accounts -> Keys -> Add key (JSON). The file's contents are "
                       "encrypted into Kintsugi; you can delete the file afterwards. Roles: Viewer for Read; "
                       "Compute Instance Admin / Storage Object Admin for Write."))

        self.cloud_forms = QStackedWidget()
        for w in (aws_w, az_w, gcp_w):
            self.cloud_forms.addWidget(w)

        self.test_btn = QPushButton("Test connection")
        self.save_btn = primary(QPushButton("Save connection"))
        self.msg = QLabel()
        self.msg.setWordWrap(True)
        btns = QHBoxLayout()
        btns.addWidget(self.test_btn)
        btns.addWidget(self.save_btn)
        btns.addStretch()

        card = QFrame()
        card.setObjectName("Card")
        cl = QVBoxLayout(card)
        cl.setContentsMargins(16, 14, 16, 14)
        cl.setSpacing(10)
        self.form_title = QLabel()
        self.form_title.setStyleSheet("font-weight: 600; font-size: 14px;")
        cl.addWidget(self.form_title)
        common = QWidget()
        cf = _form(common)
        cf.addRow("Connection name", self.name)
        cf.addRow("Use this connection for", self.use_for)
        cl.addWidget(common)
        cl.addWidget(self.cloud_forms)
        cl.addWidget(self.advanced)
        cl.addWidget(self.adv_body)
        cl.addLayout(btns)
        cl.addWidget(self.msg)

        self.table = QTableWidget()
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setMinimumHeight(170)
        style_table(self.table)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.del_btn = QPushButton("Delete selected")
        self.refresh_btn = QPushButton("Refresh")

        body = QWidget()
        lay = QVBoxLayout(body)
        lay.setContentsMargins(16, 14, 16, 14)
        lay.setSpacing(10)
        lay.addWidget(page_title("Connections", "Choose a cloud, enter its details, test, then save. Secrets are "
                                 "encrypted and never shown to the AI. AWS has full support; Azure and Google "
                                 "Cloud cover VMs and storage."))
        lay.addLayout(cloud_row)
        lay.addWidget(card)
        lay.addSpacing(6)
        head = QHBoxLayout()
        yours = QLabel("Your connections")
        yours.setStyleSheet("font-weight: 600; font-size: 14px;")
        head.addWidget(yours)
        head.addStretch()
        head.addWidget(self.refresh_btn)
        head.addWidget(self.del_btn)
        lay.addLayout(head)
        lay.addWidget(self.table, 1)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(body)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)

        self.test_btn.clicked.connect(self.test)
        self.save_btn.clicked.connect(self.save)
        self.refresh_btn.clicked.connect(self.refresh)
        self.del_btn.clicked.connect(self.delete)
        self._cloud_changed(0)

    def _provider(self) -> str:
        return self._provider_key

    def _az_cli(self) -> bool:
        return self._provider() == "azure" and self.az_mode.currentData() == "cli"

    def _az_mode_changed(self, idx: int):
        self.az_forms.setCurrentIndex(idx)
        _fit_stack(self.az_forms)
        _fit_stack(self.cloud_forms)

    def _cloud_changed(self, idx: int):
        self._provider_key = CLOUDS[idx][0]
        self.cloud_forms.setCurrentIndex(idx)
        _fit_stack(self.az_forms)
        _fit_stack(self.cloud_forms)
        self.advanced.setVisible(self._provider_key == "aws")
        self.adv_body.setVisible(self._provider_key == "aws" and self.advanced.isChecked())
        self.form_title.setText(f"Add {'a' if self._provider_key == 'gcp' else 'an'} {CLOUDS[idx][1]} connection")
        self.msg.setObjectName("Muted")
        self.msg.setText({
            "aws": "Keys are checked with AWS (sts get-caller-identity) before saving. Root keys are rejected.",
            "azure": "The connection is checked with Azure Resource Manager before saving.",
            "gcp": "The key is checked with Google Cloud before saving.",
        }[self._provider_key])
        if self._provider_key == "azure":
            path = clouds.az_path()
            self.az_cli_status.setText("installed" if path else
                                       "not installed - run: winget install -e --id Microsoft.AzureCLI "
                                       "(then restart Kintsugi)")
            self.az_login_btn.setEnabled(bool(path))
            self.az_load_btn.setEnabled(bool(path))
            if path and self.az_subs.count() == 0:
                self.az_load_subscriptions(quiet=True)

    def az_login(self):
        self._busy(True, "A browser window opens for the Azure sign-in. Finish it there...")
        self.pool.start(clouds.az_login, self.az_tenant_hint.text().strip(), on_done=self._show_subs,
                        on_fail=lambda m: self._busy(False, f"Sign-in failed: {m}"))

    def az_load_subscriptions(self, quiet: bool = False):
        if not quiet:
            self._busy(True, "Reading subscriptions from the Azure CLI...")
        self.pool.start(clouds.az_subscriptions, on_done=self._show_subs,
                        on_fail=lambda m: self._busy(False, "" if quiet else f"Error: {m}"))

    def _show_subs(self, subs: list[dict]):
        self.az_subs.clear()
        for s in subs:
            self.az_subs.addItem(f"{s['name']}  ({s['id']})", s["id"])
            if s["default"]:
                self.az_subs.setCurrentIndex(self.az_subs.count() - 1)
        user = next((s["user"] for s in subs if s["user"]), "")
        self._busy(False, f"Signed in as {user}: {len(subs)} subscription(s)." if subs else
                   "No subscriptions found. Click 'Sign in with az login'.")

    def _cloud_fields(self) -> dict:
        if self._az_cli():
            sub = self.az_subs.currentData()
            if not sub or self.az_subs.currentText() != self.az_subs.itemText(self.az_subs.currentIndex()):
                sub = self.az_subs.currentText().strip()
            return {"auth": "cli", "subscription_id": sub}
        if self._provider() == "azure":
            return {"tenant_id": self.az_tenant.text(), "client_id": self.az_client.text(),
                    "subscription_id": self.az_sub.text(), "secret": self.az_secret.text()}
        path = self.gcp_key.text().strip().strip('"')
        try:
            text = Path(path).read_text(encoding="utf-8") if path else ""
        except OSError:
            text = ""
        return {"secret": text}

    def _toggle_advanced(self, on: bool):
        self.adv_body.setVisible(on)
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
        for b in (self.test_btn, self.save_btn, self.az_login_btn, self.az_load_btn):
            b.setEnabled(not busy)
        if not busy and self._provider() == "azure" and not clouds.az_path():
            self.az_login_btn.setEnabled(False)
            self.az_load_btn.setEnabled(False)
        if text:
            self.msg.setText(text)

    def test(self):
        if self._provider() != "aws":
            self._busy(True, f"Checking with {CLOUD_SHORT[self._provider()]}...")
            self.pool.start(vault.test_cloud_credential, self._provider(), self._cloud_fields(),
                            on_done=lambda i: self._busy(False, f"Works. {i['identity']} · {i['scope']}. Not saved yet."),
                            on_fail=lambda m: self._busy(False, f"Error: {m}"))
            return
        mode, fields = self._fields()
        purposes = USE_FOR[self.use_for.currentIndex()][1]
        self._busy(True, "Checking with AWS...")
        self.pool.start(vault.test_credential, purposes[0], mode, **fields,
                        on_done=lambda ident: self._busy(False, f"Works. Owner: {ident['principal_type']} "
                                                                f"'{ident['user_name']}' (account {ident['account']}, "
                                                                f"{ident['arn']}). Not saved yet."),
                        on_fail=lambda m: self._busy(False, f"Error: {m}"))

    def save(self):
        if self._provider() != "aws":
            provider, fields = self._provider(), self._cloud_fields()
            purposes = USE_FOR[self.use_for.currentIndex()][1]
            name = self.name.text().strip()
            self.az_secret.clear()
            self._busy(True, f"Checking with {CLOUD_SHORT[provider]} and saving...")
            self.pool.start(self._save_cloud, name, provider, purposes, fields, on_done=self._saved_cloud,
                            on_fail=self._failed)
            return
        mode, fields = self._fields()
        name = self.name.text().strip()
        purposes = USE_FOR[self.use_for.currentIndex()][1]
        self.secret.clear()
        self.show_secret.setChecked(False)
        self._busy(True, "Checking with AWS and saving...")
        self.pool.start(self._save_all, name, purposes, mode, fields, on_done=self._saved, on_fail=self._failed)

    def _save_all(self, name, purposes, mode, fields):
        """Worker thread. 'Read and Write' saves two entries (one per purpose) with the same access."""
        saved = []
        for p in purposes:
            label = name if len(purposes) == 1 or p == "read" else f"{name} (write)"
            saved.append(vault.add_credential(self.owner, label, p, mode, **fields))
        return saved

    def _save_cloud(self, name, provider, purposes, fields):
        saved = []
        for p in purposes:
            label = name if len(purposes) == 1 or p == "read" else f"{name} (write)"
            saved.append(vault.add_cloud_credential(self.owner, label, provider, p, fields))
        return saved

    def _saved_cloud(self, saved):
        rec = saved[0]
        uses = " + ".join(PURPOSE_LABEL[s["purpose"]] for s in saved)
        self._busy(False, f"Saved '{rec['label']}' ({CLOUD_SHORT[rec['provider']]}) for {uses}. "
                          f"{rec['identity']} · {rec['scope']}.")
        for w in (self.name, self.az_tenant, self.az_client, self.az_sub, self.gcp_key):
            w.clear()
        self.refresh()

    def _saved(self, saved):
        rec = saved[0]
        uses = " + ".join(PURPOSE_LABEL[s["purpose"]] for s in saved)
        self._busy(False, f"Saved '{rec['label']}' for {uses}. Owner: {rec['principal_type']} "
                          f"'{rec['user_name']}' (account {rec['account_id']}).")
        for w in (self.name, self.access_key, self.profile, self.role_arn, self.external_id):
            w.clear()
        self.refresh()

    def _failed(self, msg):
        again = "" if self._az_cli() else "  (re-enter the secret key to try again)"
        self._busy(False, f"Not saved: {msg}{again}")

    def refresh(self):
        self.pool.start(vault.list_all_connections, self.owner, on_done=self._show,
                        on_fail=lambda m: self.msg.setText(f"Cannot load connections: {m}"))

    def _show(self, rows):
        self.rows = rows
        fill_table(self.table, rows, self.COLS, fmt={
            "provider": lambda r: CLOUD_SHORT.get(r["provider"], r["provider"]),
            "iam_user": lambda r: r.get("iam_user") or "(re-add to see)",
            "purpose": lambda r: PURPOSE_LABEL.get(r["purpose"], r["purpose"]),
            "key_hint": lambda r: (r["key_hint"] if r["provider"] == "gcp" or r["key_hint"] == "az login"
                                   else f"****{r['key_hint']}")
            if r.get("key_hint") else (
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
                                f"Kintsugi (it is not deleted in {CLOUD_SHORT[row['provider']]}).") != QMessageBox.Yes:
            return
        delete = vault.delete_credential if row["provider"] == "aws" else vault.delete_cloud_credential
        self.pool.start(delete, self.owner, row["id"],
                        on_done=lambda _: self.refresh(), on_fail=lambda m: self.msg.setText(m))
