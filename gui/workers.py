"""Run slow core calls (LLM, boto3, DB) off the GUI thread."""
import traceback

from PySide6.QtCore import QThread, Signal

from core.db import DatabaseError
from core.scripts import ScriptError
from core.templates import TemplateError
from core.tools import ToolError
from core.vault import VaultError

EXPECTED_ERRORS = (VaultError, ToolError, DatabaseError, ScriptError, TemplateError)


class FuncWorker(QThread):
    """Runs fn(*args, **kwargs) in a background thread; emits done(result) or failed(message)."""
    done = Signal(object)
    failed = Signal(str)

    def __init__(self, fn, *args, **kwargs):
        super().__init__()
        self.fn, self.args, self.kwargs = fn, args, kwargs

    def run(self):
        try:
            self.done.emit(self.fn(*self.args, **self.kwargs))
        except EXPECTED_ERRORS as e:
            # Validation / permission problems: the message is shown in the GUI, no traceback needed.
            self.failed.emit(str(e))
        except Exception as e:
            # Unexpected bug: messages from core are secret-free; tracebacks go to the console only.
            traceback.print_exc()
            self.failed.emit(f"{type(e).__name__}: {e}")


class WorkerPool:
    """Keeps references to running workers so Qt does not destroy them mid-run."""

    def __init__(self):
        self._running: set[FuncWorker] = set()

    def start(self, fn, *args, on_done=None, on_fail=None, **kwargs) -> FuncWorker:
        w = FuncWorker(fn, *args, **kwargs)
        if on_done:
            w.done.connect(on_done)
        if on_fail:
            w.failed.connect(on_fail)
        w.finished.connect(lambda: self._running.discard(w))
        self._running.add(w)
        w.start()
        return w
