"""Application look: Fusion style, a light palette and one stylesheet shared by every page."""
from pathlib import Path

from PySide6.QtGui import QColor, QFont, QIcon, QPalette
from PySide6.QtWidgets import QApplication

ACCENT = "#2563eb"
ACCENT_DARK = "#1d4ed8"
BG = "#f4f6fa"
SURFACE = "#ffffff"
BORDER = "#d9dee7"
TEXT = "#1f2937"
MUTED = "#6b7280"
DANGER = "#dc2626"
SUCCESS = "#15803d"
ASSETS = Path(__file__).parent / "assets"
CHEVRON = (ASSETS / "chevron-down.svg").as_posix()
LOGO = str(ASSETS / "logo.png")
LOGO_MARK = str(ASSETS / "logo_mark.png")
CLOUD_COLORS = {"aws": "#ff9900", "azure": "#0078d4", "gcp": "#34a853"}

STYLE = f"""
QWidget {{ color: {TEXT}; }}
QMainWindow {{ background: {BG}; }}
QTabWidget::pane {{ border: none; border-top: 1px solid {BORDER}; background: {BG}; }}
QTabBar::tab {{ background: transparent; color: {MUTED}; padding: 9px 18px; margin-right: 2px;
               border: none; border-bottom: 2px solid transparent; font-weight: 600; }}
QTabBar::tab:selected {{ color: {ACCENT}; border-bottom: 2px solid {ACCENT}; }}
QTabBar::tab:hover:!selected {{ color: {TEXT}; }}
QPushButton {{ background: {SURFACE}; border: 1px solid {BORDER}; border-radius: 6px; padding: 6px 14px; }}
QPushButton:hover {{ border-color: {ACCENT}; color: {ACCENT}; }}
QPushButton:pressed {{ background: #eef2ff; }}
QPushButton:disabled {{ color: #a0a7b4; background: #f1f3f6; border-color: #e3e6eb; }}
QPushButton[primary="true"] {{ background: {ACCENT}; color: white; border: 1px solid {ACCENT}; font-weight: 600; }}
QPushButton[primary="true"]:hover {{ background: {ACCENT_DARK}; color: white; }}
QPushButton[primary="true"]:disabled {{ background: #9db5ef; border-color: #9db5ef; color: #eef2ff; }}
QPushButton[segment="true"] {{ padding: 8px 18px; font-weight: 600; color: {MUTED}; }}
QPushButton[segment="true"]:checked {{ background: #eef2ff; color: {ACCENT}; border: 1px solid {ACCENT}; }}
QLineEdit, QComboBox, QSpinBox, QPlainTextEdit, QTextEdit, QDateTimeEdit {{
    background: {SURFACE}; border: 1px solid {BORDER}; border-radius: 6px; padding: 5px 8px;
    selection-background-color: {ACCENT}; }}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QPlainTextEdit:focus, QTextEdit:focus {{ border-color: {ACCENT}; }}
QComboBox::drop-down {{ border: none; width: 24px; }}
QComboBox::down-arrow {{ image: url("{CHEVRON}"); width: 12px; height: 12px; }}
QComboBox QAbstractItemView {{ background: {SURFACE}; border: 1px solid {BORDER}; selection-background-color: #dbe6ff;
    selection-color: {TEXT}; outline: none; }}
QLineEdit:disabled {{ background: #f1f3f6; color: #a0a7b4; }}
QTextBrowser {{ background: {SURFACE}; border: 1px solid {BORDER}; border-radius: 8px; padding: 6px; }}
QTableWidget, QListWidget {{ background: {SURFACE}; border: 1px solid {BORDER}; border-radius: 8px;
    gridline-color: #eceff3; selection-background-color: #dbe6ff; selection-color: {TEXT};
    alternate-background-color: #f8f9fc; }}
QHeaderView::section {{ background: #f1f4f9; color: {MUTED}; border: none; border-bottom: 1px solid {BORDER};
    padding: 6px 8px; font-weight: 600; }}
QGroupBox {{ background: {SURFACE}; border: 1px solid {BORDER}; border-radius: 8px; margin-top: 14px;
    padding: 14px 10px 10px 10px; font-weight: 600; }}
QGroupBox::title {{ subcontrol-origin: margin; left: 12px; padding: 0 4px; color: {TEXT}; }}
QScrollArea {{ border: none; background: transparent; }}
QStatusBar {{ background: {SURFACE}; border-top: 1px solid {BORDER}; color: {MUTED}; }}
QFrame#Header {{ background: {SURFACE}; border-bottom: 1px solid {BORDER}; }}
QLabel#AppTitle {{ font-size: 18px; font-weight: 700; color: {TEXT}; }}
QLabel#AppSub {{ color: {MUTED}; }}
QLabel#PageTitle {{ font-size: 16px; font-weight: 700; }}
QLabel#Muted {{ color: {MUTED}; }}
QFrame#Card {{ background: {SURFACE}; border: 1px solid {BORDER}; border-radius: 8px; }}
QToolTip {{ background: {TEXT}; color: white; border: none; padding: 4px 6px; }}
"""


def apply(app: QApplication) -> None:
    app.setStyle("Fusion")
    app.setWindowIcon(QIcon(LOGO_MARK))
    pal = app.palette()
    pal.setColor(QPalette.Window, QColor(BG))
    pal.setColor(QPalette.Base, QColor(SURFACE))
    pal.setColor(QPalette.AlternateBase, QColor("#f8f9fc"))
    pal.setColor(QPalette.Text, QColor(TEXT))
    pal.setColor(QPalette.WindowText, QColor(TEXT))
    pal.setColor(QPalette.ButtonText, QColor(TEXT))
    pal.setColor(QPalette.Button, QColor(SURFACE))
    pal.setColor(QPalette.Highlight, QColor(ACCENT))
    pal.setColor(QPalette.Link, QColor(ACCENT))
    app.setPalette(pal)
    font = QFont("Segoe UI", 10)
    app.setFont(font)
    app.setStyleSheet(STYLE)


def primary(button):
    button.setProperty("primary", True)
    return button


def page_title(text: str, sub: str = ""):
    from PySide6.QtWidgets import QLabel, QVBoxLayout, QWidget
    w = QWidget()
    lay = QVBoxLayout(w)
    lay.setContentsMargins(0, 0, 0, 4)
    lay.setSpacing(2)
    t = QLabel(text)
    t.setObjectName("PageTitle")
    lay.addWidget(t)
    if sub:
        s = QLabel(sub)
        s.setObjectName("Muted")
        s.setWordWrap(True)
        lay.addWidget(s)
    return w
