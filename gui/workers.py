"""Run slow core calls (LLM, boto3, DB) off the GUI thread."""
import traceback

from PySide6.QtCore import QThread, Signal

from core.clouds import CloudError
from core.db import DatabaseError
from core.local_steps import StepError
from core.scripts import ScriptError
from core.templates import TemplateError
from core.tools import ToolError
from core.vault import VaultError
from core.workspace import WorkspaceError

EXPECTED_ERRORS = (VaultError, ToolError, DatabaseError, ScriptError, TemplateError, StepError, WorkspaceError, CloudError)


class FuncWorker(QThread):
    """Runs fn(*args, **kwargs) in a background thread; emits done(result) or failed(message).
    With on_progress, fn also gets progress=<callable> whose lines arrive on the GUI thread."""
    done = Signal(object)
    failed = Signal(str)
    progress = Signal(str)

    def __init__(self, fn, *args, **kwargs):
        super().__init__()
        self.fn, self.args, self.kwargs = fn, args, kwargs

    def run(self):
        try:
            self.done.emit(self.fn(*self.args, **self.kwargs))
        except EXPECTED_ERRORS as e:
            self.failed.emit(str(e))
        except Exception as e:
            traceback.print_exc()
            self.failed.emit(f"{type(e).__name__}: {e}")


class WorkerPool:
    """Keeps references to running workers so Qt does not destroy them mid-run."""

    def __init__(self):
        self._running: set[FuncWorker] = set()

    def start(self, fn, *args, on_done=None, on_fail=None, on_progress=None, **kwargs) -> FuncWorker:
        w = FuncWorker(fn, *args, **kwargs)
        if on_progress:
            w.kwargs["progress"] = w.progress.emit
            w.progress.connect(on_progress)
        if on_done:
            w.done.connect(on_done)
        if on_fail:
            w.failed.connect(on_fail)
        w.finished.connect(lambda: self._running.discard(w))
        self._running.add(w)
        w.start()
        return w
