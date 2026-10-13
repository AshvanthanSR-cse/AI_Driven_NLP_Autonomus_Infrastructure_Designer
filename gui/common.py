"""Small shared GUI helpers."""
import json
from zoneinfo import ZoneInfo

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QAbstractItemView, QTableWidget, QTableWidgetItem

from core.config import settings

LOCAL_TZ = ZoneInfo(settings.app_timezone)

AWS_REGIONS = [
    "ap-south-1", "ap-south-2", "us-east-1", "us-east-2", "us-west-1", "us-west-2", "eu-west-1", "eu-west-2",
    "eu-central-1", "eu-north-1", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "ap-northeast-2",
    "ca-central-1", "sa-east-1", "me-south-1", "af-south-1",
]


def fmt_time(value) -> str:
    if value is None:
        return ""
    if hasattr(value, "astimezone"):
        return value.astimezone(LOCAL_TZ).strftime("%Y-%m-%d %H:%M")
    return str(value)


def cell(value) -> QTableWidgetItem:
    if value is None:
        text = ""
    elif hasattr(value, "astimezone"):
        text = fmt_time(value)
    elif isinstance(value, bool):
        text = "yes" if value else ""
    elif isinstance(value, (dict, list)):
        text = json.dumps(value, default=str)
    else:
        text = str(value)
    it = QTableWidgetItem(text)
    it.setFlags(it.flags() & ~Qt.ItemIsEditable)
    return it


def fill_table(table: QTableWidget, rows: list[dict], cols: list[tuple[str, str]], fmt: dict | None = None):
    """cols = [(key, header)]; fmt = {key: fn(row) -> display value}"""
    fmt = fmt or {}
    table.setColumnCount(len(cols))
    table.setHorizontalHeaderLabels([c[1] for c in cols])
    table.setRowCount(len(rows))
    for r, row in enumerate(rows):
        for c, (key, _) in enumerate(cols):
            table.setItem(r, c, cell(fmt[key](row) if key in fmt else row.get(key)))


def style_table(table: QTableWidget):
    table.setAlternatingRowColors(True)
    table.setShowGrid(False)
    table.verticalHeader().setVisible(False)
    table.setSelectionBehavior(QAbstractItemView.SelectRows)
