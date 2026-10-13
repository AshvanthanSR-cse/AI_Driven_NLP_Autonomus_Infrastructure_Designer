"""Local workspace for recipes: scanning user folders, staging a filtered copy, zips, generated files.

The app only reads the folder the user named. Secret-looking files (.env, *.pem, keys, Terraform state) and
heavy folders (.git, node_modules, venv) are never copied, zipped, uploaded or shown to the LLM.
"""
import fnmatch
import os
import re
import shutil
import zipfile
from datetime import datetime
from pathlib import Path

from core.config import PROJECT_ROOT

WORKSPACE = PROJECT_ROOT / "workspace"
MAX_FOLDER_MB = 50

EXCLUDE_DIRS = {".git", ".hg", ".svn", "node_modules", "__pycache__", "venv", ".venv", "env", ".terraform",
                ".idea", ".vscode", ".pytest_cache", ".mypy_cache", "dist-newstyle"}
EXCLUDE_FILES = (".env", ".env.*", "*.pem", "*.key", "*.ppk", "id_rsa*", "id_ed25519*", "id_ecdsa*", "*.pfx",
                 "*.p12", "*.tfstate", "*.tfstate.*", "credentials", ".aws", "*.kubeconfig", "kubeconfig",
                 "tfplan", ".DS_Store", "Thumbs.db")
SECRET_WORDS = re.compile(r"(secret|password|passwd|credential|token|private)", re.I)


class WorkspaceError(ValueError):
    """Safe-to-display problem with a local folder or file."""


def new_task_dir(kind: str) -> Path:
    d = WORKSPACE / f"{kind}-{datetime.now():%Y%m%d-%H%M%S}"
    d.mkdir(parents=True, exist_ok=True)
    return d


def in_workspace(path: str | Path) -> bool:
    try:
        Path(path).resolve().relative_to(WORKSPACE.resolve())
        return True
    except ValueError:
        return False


def user_folder(value) -> Path:
    """A folder the user typed (quotes allowed). Must exist."""
    p = Path(str(value).strip().strip('"').strip("'")).expanduser()
    if not str(p) or not p.is_absolute():
        raise WorkspaceError("give the full folder path, e.g. D:\\projects\\mysite")
    if not p.is_dir():
        raise WorkspaceError(f"folder not found: {p}")
    return p.resolve()


def user_file(value, suffixes: tuple[str, ...] = ()) -> Path:
    p = Path(str(value).strip().strip('"').strip("'")).expanduser()
    if not p.is_absolute():
        raise WorkspaceError("give the full file path, e.g. D:\\keys\\my-key.pem")
    if not p.is_file():
        raise WorkspaceError(f"file not found: {p}")
    if suffixes and p.suffix.lower() not in suffixes:
        raise WorkspaceError(f"expected a {' or '.join(suffixes)} file")
    return p.resolve()


def _excluded_file(name: str) -> bool:
    return any(fnmatch.fnmatch(name.lower(), pat.lower()) for pat in EXCLUDE_FILES)


def scan_folder(folder: Path, max_mb: int = MAX_FOLDER_MB) -> dict:
    """Walk the folder: files to include, excluded names, warnings. Raises if the folder is too big."""
    files, excluded, warnings = [], [], []
    for root, dirs, names in os.walk(folder):
        dirs[:] = sorted(d for d in dirs if d not in EXCLUDE_DIRS)
        for name in sorted(names):
            _scan_file(folder, Path(root) / name, files, excluded, warnings)
    total = sum(size for _, size in files)
    if total > max_mb * 1024 * 1024:
        raise WorkspaceError(f"the folder is {total / 1048576:.0f} MB; the limit is {max_mb} MB "
                             f"(node_modules, .git, venv are already skipped)")
    if not files:
        raise WorkspaceError(f"no usable files in {folder}")
    if excluded:
        warnings.append("Skipped secret files (never uploaded): " + ", ".join(excluded[:10]))
    return {"files": files, "excluded": excluded, "warnings": warnings, "bytes": total}


def _scan_file(folder: Path, path: Path, files: list, excluded: list, warnings: list) -> None:
    rel = path.relative_to(folder)
    if _excluded_file(path.name):
        excluded.append(str(rel))
        return
    files.append((rel.as_posix(), path.stat().st_size))
    if SECRET_WORDS.search(path.name):
        warnings.append(f"'{rel}' looks like it may contain secrets; it WILL be included. Remove it if so.")


def stage_folder(src: Path, dest: Path) -> dict:
    """Copy the filtered folder contents to dest. Returns the scan result."""
    scan = scan_folder(src)
    for rel, _ in scan["files"]:
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src / rel, target)
    return scan


def zip_folder(src: Path, zip_path: Path) -> dict:
    scan = scan_folder(src)
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for rel, _ in scan["files"]:
            zf.write(src / rel, rel)
    return scan


def detect_project(folder: Path) -> str:
    names = {p.name.lower() for p in folder.iterdir()}
    if "dockerfile" in names:
        return "docker"
    if any(n.endswith(".tf") for n in names):
        return "terraform"
    if "package.json" in names:
        return "node"
    if "requirements.txt" in names or "app.py" in names or any(n.endswith(".py") for n in names):
        return "python"
    if "index.html" in names:
        return "static"
    return "unknown"


def find_dockerfile(folder: Path) -> Path:
    for name in ("Dockerfile", "dockerfile"):
        if (folder / name).is_file():
            return folder / name
    raise WorkspaceError(f"no Dockerfile in {folder}")


_DOCKER_SECRET_RE = re.compile(r"^\s*(ENV|ARG)\s+\S*(SECRET|PASSWORD|TOKEN|ACCESS_KEY|PRIVATE)\S*[ =]\S+", re.I)


def dockerfile_info(folder: Path, name: str | None = None) -> dict:
    """Exposed port and safety warnings from a Dockerfile (never sent to the LLM)."""
    path = folder / name if name else find_dockerfile(folder)
    text = path.read_text(encoding="utf-8", errors="replace")
    port, warnings = None, []
    for n, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if m := re.match(r"EXPOSE\s+(\d+)", s, re.I):
            port = port or int(m.group(1))
        if re.match(r"(COPY|ADD)\s+.*\.env\b", s, re.I):
            warnings.append(f"Dockerfile line {n} copies a .env file into the image (secrets would be baked in)")
        if _DOCKER_SECRET_RE.match(s):
            warnings.append(f"Dockerfile line {n} sets a secret-looking value in the image")
    return {"port": port, "warnings": warnings}


def write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")
    return path
