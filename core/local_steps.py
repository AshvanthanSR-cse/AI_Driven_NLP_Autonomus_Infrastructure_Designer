"""Script steps that are not a single boto3 call: local tools, ECR login, Ansible, and URL checks.

Step kinds (field "kind"; a step without it is a boto3 call handled in core/scripts.py):
  command   {"tool": "docker|terraform|kubectl|eksctl|helm|aws", "args": [...], "cwd": "...", "timeout": s}
  ecr_login {"repository_uri": "<acct>.dkr.ecr.<region>.amazonaws.com/<repo>"}
  ansible   {"workdir": "...", "playbook": "site.yml", "inventory": "inventory.ini", "ssh_key_path": "...",
             "extra_args": [...]}   (runs ansible-playbook inside a local Docker container; no WSL needed)
  check     {"check": "http|ec2_url|ecs_url|k8s_url", "params": {...}, "timeout": s}
  s3_upload {"source": "<local file or folder>", "bucket": "...", "prefix": "docs/", "flatten": false}
            (SSE-S3 encrypted; flatten=true puts a folder's contents at the prefix, e.g. index.html at the root)
  s3_empty  {"bucket": "..."}  (deletes every object version; only buckets tagged CreatedBy=kintsugi)
  cloud     {"provider": "azure|gcp", "action": "vm_start|vm_stop|upload", "params": {...}}  (core/clouds.py)

Safety: only allowlisted tools and sub-commands; no shell (argument lists only); AWS credentials of the
script's identity go only into the child process environment and are never logged; output lines are
scrubbed of key-like strings; secrets (ECR password, SSH key) are passed on stdin, never as arguments.
"""
import base64
import json
import os
import re
import shutil
import subprocess
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

from core import workspace

KINDS = ("command", "ecr_login", "ansible", "check", "s3_upload", "s3_empty", "cloud")
COMMON_KEYS = {"kind", "description", "region", "save_as", "undo", "pause_after", "timeout"}
KIND_KEYS = {"command": {"tool", "args", "cwd"}, "ecr_login": {"repository_uri"},
             "ansible": {"workdir", "playbook", "inventory", "ssh_key_path", "extra_args"},
             "check": {"check", "params"}, "s3_upload": {"source", "bucket", "prefix", "flatten"},
             "s3_empty": {"bucket"},
             "cloud": {"provider", "action", "params"}}
CLOUD_ACTIONS = ("vm_start", "vm_stop", "upload")
S3_MAX_MB = 5000
CHECKS = ("http", "ec2_url", "ecs_url", "k8s_url")
MAX_TIMEOUT_S = 90 * 60
MAX_PAUSE_S = 300

TOOLS = {
    "docker": {"build", "push", "tag", "pull", "rmi", "image", "images", "run", "ps", "logs", "stop", "rm"},
    "terraform": {"init", "validate", "plan", "apply", "destroy", "output", "show", "fmt", "providers"},
    "kubectl": {"apply", "delete", "get", "describe", "rollout", "wait", "scale", "create", "set", "label",
                "annotate", "logs", "version", "cluster-info", "top"},
    "eksctl": {"create", "delete", "get", "scale", "upgrade", "utils", "version"},
    "helm": {"install", "upgrade", "uninstall", "delete", "repo", "list", "status", "template", "dependency",
             "version", "rollback"},
    "aws": {"eks"},
}
DESTRUCTIVE_SUBCOMMANDS = {"docker": {"rmi", "rm"}, "terraform": {"destroy"}, "kubectl": {"delete"},
                           "eksctl": {"delete"}, "helm": {"uninstall", "delete"}}
INSTALL_HINT = {
    "docker": "Install Docker Desktop and start it (the whale icon must say 'Engine running').",
    "terraform": "Install Terraform: winget install Hashicorp.Terraform",
    "kubectl": "Install kubectl: winget install Kubernetes.kubectl",
    "eksctl": "Install eksctl: winget install eksctl.eksctl",
    "helm": "Install Helm: winget install Helm.Helm",
    "aws": "Install AWS CLI v2: winget install Amazon.AWSCLI",
    "az": "Install Azure CLI: winget install -e --id Microsoft.AzureCLI, then reopen Kintsugi and run az login",
}
ANSIBLE_IMAGE = "kintsugi-ansible:1"
ANSIBLE_DOCKERFILE = """FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends openssh-client \\
 && rm -rf /var/lib/apt/lists/* \\
 && pip install --no-cache-dir "ansible-core>=2.17,<2.20"
ENV ANSIBLE_HOST_KEY_CHECKING=True ANSIBLE_NOCOLOR=1 ANSIBLE_FORCE_COLOR=0 ANSIBLE_RETRY_FILES_ENABLED=0
WORKDIR /work
"""

_SCRUB_RES = [re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b"),
              re.compile(r"(?i)(secret|password|token)([\"']?\s*[:=]\s*[\"']?)[^\s\"',]{8,}"),
              re.compile(r"\b[A-Za-z0-9/+]{40}\b")]


class StepError(Exception):
    """Safe-to-display error."""


def kind_of(step: dict) -> str:
    return step.get("kind") or "aws"


def scrub(line: str) -> str:
    line = _SCRUB_RES[0].sub("[key]", line)
    line = _SCRUB_RES[1].sub(lambda m: m.group(1) + m.group(2) + "***", line)
    return _SCRUB_RES[2].sub("[redacted]", line)


def _subcommand(step: dict) -> str:
    return next((a for a in step.get("args", []) if not str(a).startswith("-")), "")


def validate(step: dict) -> None:
    kind = kind_of(step)
    if kind not in KINDS:
        raise StepError(f"unknown step kind '{kind}'")
    extra = set(step) - COMMON_KEYS - KIND_KEYS[kind]
    if extra:
        raise StepError(f"unknown field(s) for a {kind} step: {', '.join(sorted(extra))}")
    t = step.get("timeout", 0)
    if not isinstance(t, int) or not 0 <= t <= MAX_TIMEOUT_S:
        raise StepError(f"timeout must be 0..{MAX_TIMEOUT_S} seconds")
    {"command": _validate_command, "ecr_login": _validate_ecr_login, "ansible": _validate_ansible,
     "check": _validate_check, "s3_upload": _validate_s3_upload, "s3_empty": _validate_s3_empty,
     "cloud": _validate_cloud}[kind](step)


_BUCKET_RE = re.compile(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]")


def check_prefix(prefix: str) -> str:
    prefix = (prefix or "").replace("\\", "/").lstrip("/")
    if ".." in prefix.split("/") or len(prefix) > 900:
        raise StepError("the S3 prefix (folder) may not contain '..'")
    return prefix


def _validate_s3_upload(step: dict) -> None:
    src = step.get("source", "")
    if not src or "{{" not in src and not Path(src).exists():
        raise StepError(f"file or folder not found: {src}")
    b = step.get("bucket", "")
    if "{{" not in b and not _BUCKET_RE.fullmatch(b or ""):
        raise StepError(f"'{b}' is not a valid S3 bucket name")
    check_prefix(step.get("prefix", ""))
    if not isinstance(step.get("flatten", False), bool):
        raise StepError("'flatten' must be true or false")
    if src and Path(src).is_file() and workspace._excluded_file(Path(src).name):
        raise StepError(f"{Path(src).name} looks like a secret file (key, .env, state); it is never uploaded")


def _validate_s3_empty(step: dict) -> None:
    b = step.get("bucket", "")
    if "{{" not in b and not _BUCKET_RE.fullmatch(b or ""):
        raise StepError(f"'{b}' is not a valid S3 bucket name")


def _validate_cloud(step: dict) -> None:
    from core.clouds import OTHER_PROVIDERS
    if step.get("provider") not in OTHER_PROVIDERS:
        raise StepError(f"provider must be one of {', '.join(OTHER_PROVIDERS)}")
    if step.get("action") not in CLOUD_ACTIONS:
        raise StepError(f"action must be one of {', '.join(CLOUD_ACTIONS)}")
    p = step.get("params", {})
    if not isinstance(p, dict):
        raise StepError("cloud 'params' must be an object")
    if step["action"] == "upload":
        if not Path(str(p.get("source", ""))).exists():
            raise StepError(f"file or folder not found: {p.get('source')}")
        if not p.get("bucket"):
            raise StepError("upload needs a bucket (Azure: account/container)")
        check_prefix(p.get("prefix", ""))
    elif not p.get("vm"):
        raise StepError("VM actions need params.vm (name or id)")


def _validate_args(args) -> list[str]:
    if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
        raise StepError("'args' must be a list of strings")
    for a in args:
        if "\x00" in a or len(a) > 4000:
            raise StepError("an argument is too long or has invalid characters")
    return args


def _validate_command(step: dict) -> None:
    tool = step.get("tool", "")
    if tool not in TOOLS:
        raise StepError(f"tool '{tool}' is not allowed (allowed: {', '.join(sorted(TOOLS))})")
    args = _validate_args(step.get("args", []))
    sub = _subcommand(step)
    if sub not in TOOLS[tool]:
        raise StepError(f"'{tool} {sub}' is not allowed (allowed: {', '.join(sorted(TOOLS[tool]))})")
    low = [a.lower() for a in args]
    if tool == "aws" and low[:2] != ["eks", "update-kubeconfig"]:
        raise StepError("only 'aws eks update-kubeconfig' may run as a command (use AWS steps for the rest)")
    if tool == "docker" and sub == "run":
        _check_docker_run(low)
    if tool == "terraform" and sub in ("apply", "destroy") and "-input=false" not in low:
        raise StepError(f"terraform {sub} must include -input=false (it runs without a terminal)")
    cwd = step.get("cwd")
    if cwd is not None and (not isinstance(cwd, str) or "{{" not in cwd and not Path(cwd).is_dir()):
        raise StepError(f"working folder not found: {cwd}")


_HOST_ROOT_RE = re.compile(r"^([a-z]:\\?|/)(:|$)")


def _check_docker_run(low: list[str]) -> None:
    """No host privileges, no mounting a whole drive / the root filesystem / the Docker socket."""
    for i, a in enumerate(low):
        if a == "--privileged" or a.startswith(("--cap-add", "--pid", "--ipc", "--userns", "--security-opt",
                                                "--device")):
            raise StepError(f"docker run {a} (host privileges) is blocked")
        vol = None
        if a in ("-v", "--volume", "--mount") and i + 1 < len(low):
            vol = low[i + 1]
        elif a.startswith(("--volume=", "--mount=")):
            vol = a.split("=", 1)[1]
        if vol is None:
            continue
        src = vol
        for part in vol.split(","):
            if part.startswith(("source=", "src=")):
                src = part.split("=", 1)[1]
        if "docker.sock" in vol or _HOST_ROOT_RE.match(src):
            raise StepError("docker run may not mount a whole drive, the root filesystem or the Docker socket")


_ECR_RE = re.compile(r"\d{12}\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com(/[a-z0-9._/-]+)?")


def _validate_ecr_login(step: dict) -> None:
    uri = step.get("repository_uri", "")
    if not isinstance(uri, str) or ("{{" not in uri and not _ECR_RE.fullmatch(uri)):
        raise StepError("repository_uri must look like 123456789012.dkr.ecr.<region>.amazonaws.com/<repo>")


def _validate_ansible(step: dict) -> None:
    wd = step.get("workdir", "")
    if not wd or not Path(wd).is_dir():
        raise StepError(f"Ansible working folder not found: {wd}")
    for key in ("playbook", "inventory"):
        name = step.get(key, "")
        if not re.fullmatch(r"[\w./-]+\.(ya?ml|ini|cfg)", name or "") or ".." in name:
            raise StepError(f"{key} must be a file name inside the working folder")
        if not (Path(wd) / name).is_file():
            raise StepError(f"{key} file not found: {name}")
    _validate_args(step.get("extra_args", []))
    for a in step.get("extra_args", []):
        if a.split("=")[0] not in ("--syntax-check", "--check", "--diff", "--tags", "--skip-tags", "-v", "-vv",
                                   "--list-tasks", "--limit") and not re.fullmatch(r"[\w,.-]+", a):
            raise StepError(f"ansible option '{a}' is not allowed")
    if key := step.get("ssh_key_path"):
        if not Path(key).is_file():
            raise StepError(f"SSH key file not found: {key}")


def _validate_check(step: dict) -> None:
    if step.get("check") not in CHECKS:
        raise StepError(f"check must be one of {', '.join(CHECKS)}")
    if not isinstance(step.get("params", {}), dict):
        raise StepError("check 'params' must be an object")


def is_destructive(step: dict) -> bool:
    if kind_of(step) == "s3_empty":
        return True
    return kind_of(step) == "command" and _subcommand(step) in DESTRUCTIVE_SUBCOMMANDS.get(step.get("tool"), set())


def tools_needed(step: dict) -> set[str]:
    kind = kind_of(step)
    if kind == "command":
        return {step["tool"]} | ({"aws"} if step["tool"] == "kubectl" else set())
    if kind in ("ecr_login", "ansible"):
        return {"docker"}
    if kind == "check" and step.get("check") == "k8s_url":
        return {"kubectl", "aws"}
    return set()


def _q(a: str) -> str:
    return a if re.fullmatch(r"[\w./:=@,+{}-]+", a) else '"' + a.replace('"', '\\"') + '"'


def render(step: dict, region: str) -> str:
    kind = kind_of(step)
    if (more := _render_more(step, region)) is not None:
        return more
    if kind == "command":
        cmd = " ".join([step["tool"], *map(_q, step.get("args", []))])
        return f'cd {_q(step["cwd"])} && {cmd}' if step.get("cwd") else cmd
    if kind == "ecr_login":
        uri = step["repository_uri"]
        reg = step.get("region") or region
        return (f"aws ecr get-login-password --region {reg} | docker login --username AWS --password-stdin "
                f"{uri.split('/')[0]}")
    if kind == "ansible":
        key = " --private-key <your key, passed on stdin, deleted after the run>" if step.get("ssh_key_path") else ""
        extra = " ".join(map(_q, step.get("extra_args", [])))
        return (f"# runs in the local Docker image {ANSIBLE_IMAGE} with {_q(step['workdir'])} mounted at /work\n"
                f"ansible-playbook -i {step['inventory']} {step['playbook']}{key} {extra}").rstrip()
    p = step.get("params", {})
    what = {"http": f"HTTP GET {p.get('url')}",
            "ec2_url": f"HTTP GET http://<public IP of {p.get('instance_id')}>:{p.get('port', 80)}{p.get('path', '/')}",
            "ecs_url": f"HTTP GET http://<public IP of a task of {p.get('service')}>:{p.get('port', 80)}{p.get('path', '/')}",
            "k8s_url": f"HTTP GET http://<load balancer of Kubernetes service {p.get('service')}>{p.get('path', '/')}",
            }[step["check"]]
    return f"# Check: {what} (waits until it answers HTTP {p.get('expect', 200)})"


def _render_more(step: dict, region: str) -> str | None:
    kind = kind_of(step)
    if kind == "s3_upload":
        src = step["source"]
        dest = f"s3://{step['bucket']}/{check_prefix(step.get('prefix', ''))}"
        is_dir = Path(src).is_dir()
        rec = " --recursive" if is_dir else ""
        if is_dir and not step.get("flatten"):
            dest += Path(src).name + "/"
        return (f'aws s3 cp "{src}" {dest}{rec} --sse AES256 --region {step.get("region") or region}'
                f"   # secret files (.env, keys) are skipped")
    if kind == "s3_empty":
        return (f"aws s3api delete-objects --bucket {step['bucket']} ...   "
                f"# every object version and delete marker (needed before a versioned bucket can be deleted)")
    if kind == "cloud":
        p = step.get("params", {})
        if step["action"] == "upload":
            return f'# {step["provider"]}: upload "{p["source"]}" to {p["bucket"]}/{p.get("prefix", "")}'
        verb = {"vm_start": "start", "vm_stop": "stop (Azure: deallocate, so compute is not billed)"}[step["action"]]
        return f"# {step['provider']}: {verb} VM {p['vm']}"
    return None


def which(tool: str) -> str | None:
    return shutil.which(tool)


def tool_status() -> list[dict]:
    """Version of each local tool (for the Tools page and recipe checks). Never raises."""
    rows = []
    cmds = {"docker": ["docker", "version", "--format", "{{.Server.Version}}"],
            "terraform": ["terraform", "version"], "kubectl": ["kubectl", "version", "--client"],
            "eksctl": ["eksctl", "version"], "helm": ["helm", "version", "--short"], "aws": ["aws", "--version"],
            "az": ["az", "version", "--output", "json"]}
    for tool, cmd in cmds.items():
        path = which(tool)
        row = {"tool": tool, "installed": bool(path), "version": "", "ok": False, "hint": ""}
        if path:
            try:
                r = subprocess.run([path, *cmd[1:]], capture_output=True, text=True, timeout=20, **_no_window())
                out = (r.stdout or r.stderr).strip().splitlines()
                row["version"] = out[0][:80] if out else ""
                if tool == "az" and r.returncode == 0:
                    row["version"] = "azure-cli " + str(json.loads(r.stdout or "{}").get("azure-cli", ""))
                row["ok"] = r.returncode == 0
                if tool == "docker" and not row["ok"]:
                    row["version"], row["hint"] = "installed, engine NOT running", "Start Docker Desktop."
            except Exception as e:
                row["version"] = f"error: {type(e).__name__}"
        if not row["ok"] and not row["hint"]:
            row["hint"] = INSTALL_HINT.get(tool, "")
        rows.append(row)
    return rows


def _no_window() -> dict:
    return {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {}


def aws_env(conn, purpose: str, region: str) -> dict:
    """Environment for a child process: the script identity's (temporary or stored) credentials only."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("AWS_")}
    creds = conn.get_session(purpose, region).get_credentials()
    if creds is None:
        raise StepError("the Write connection has no usable credentials")
    c = creds.get_frozen_credentials()
    env.update({"AWS_ACCESS_KEY_ID": c.access_key, "AWS_SECRET_ACCESS_KEY": c.secret_key,
                "AWS_REGION": region, "AWS_DEFAULT_REGION": region, "AWS_PAGER": "",
                "TF_IN_AUTOMATION": "1", "TF_INPUT": "0", "CHECKPOINT_DISABLE": "1"})
    if c.token:
        env["AWS_SESSION_TOKEN"] = c.token
    return env


def run_process(argv: list[str], *, env: dict | None = None, cwd: str | None = None, stdin: bytes | None = None,
                timeout: int = 1800, progress=None) -> tuple[int, list[str]]:
    """Run without a shell; stream scrubbed output lines to progress(); return (exit code, all lines)."""
    exe = which(argv[0])
    if not exe:
        raise StepError(f"'{argv[0]}' is not installed. {INSTALL_HINT.get(argv[0], '')}")
    try:
        proc = subprocess.Popen([exe, *argv[1:]], cwd=cwd, env=env, stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, **_no_window())
    except OSError as e:
        raise StepError(f"could not start {argv[0]}: {e.strerror}") from None
    lines: list[str] = []

    def pump():
        for raw in iter(proc.stdout.readline, b""):
            line = scrub(raw.decode("utf-8", errors="replace").rstrip())
            lines.append(line)
            if progress and line:
                progress(line)

    reader = threading.Thread(target=pump, daemon=True)
    reader.start()
    try:
        if stdin:
            proc.stdin.write(stdin)
        proc.stdin.close()
    except OSError:
        pass
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        raise StepError(f"{argv[0]} did not finish within {max(1, timeout // 60)} minute(s) and was stopped")
    finally:
        reader.join(5)
        proc.stdout.close()
    return proc.returncode, lines


def _tail(lines: list[str], n: int = 12) -> str:
    keep = [l for l in lines if l.strip()][-n:]
    return "\n      ".join(keep)


def _step_timeout(step: dict, default: int) -> int:
    return step.get("timeout") or default


def run(step: dict, conn, purpose: str, region: str, progress=None) -> dict:
    """Execute one local step. Returns its output (for save_as) and a one-line summary."""
    kind = kind_of(step)
    if kind == "command":
        return _run_command(step, conn, purpose, region, progress)
    if kind == "ecr_login":
        return _run_ecr_login(step, conn, purpose, region, progress)
    if kind == "ansible":
        return _run_ansible(step, progress)
    if kind == "s3_upload":
        return _run_s3_upload(step, conn, purpose, region, progress)
    if kind == "s3_empty":
        return _run_s3_empty(step, conn, purpose, region, progress)
    if kind == "cloud":
        return _run_cloud(step, conn, purpose, progress)
    return _run_check(step, conn, purpose, region, progress)


def upload_plan(source: Path, prefix: str, max_mb: int = S3_MAX_MB,
                flatten: bool = False) -> list[tuple[Path, str, int]]:
    """[(local file, object key, size)] for a file or a folder (secret files and .git/node_modules skipped).
    A folder keeps its own name: D:\\docs + prefix 'backup/' -> backup/docs/<files>; flatten=True drops it."""
    prefix = check_prefix(prefix)
    if prefix and not prefix.endswith("/"):
        prefix += "/"
    if source.is_file():
        if workspace._excluded_file(source.name):
            raise StepError(f"{source.name} looks like a secret file; it is never uploaded")
        return [(source, prefix + source.name, source.stat().st_size)]
    try:
        scan = workspace.scan_folder(source, max_mb=max_mb)
    except workspace.WorkspaceError as e:
        raise StepError(str(e)) from None
    base = prefix if flatten else prefix + source.name + "/"
    return [(source / rel, base + rel, size) for rel, size in scan["files"]]


def _run_s3_upload(step, conn, purpose, region, progress):
    import mimetypes
    s3 = conn.client("s3", purpose, region)
    files = upload_plan(Path(step["source"]), step.get("prefix", ""), flatten=bool(step.get("flatten")))
    total = 0
    for n, (path, key, size) in enumerate(files, 1):
        extra = {"ServerSideEncryption": "AES256"}
        if ctype := mimetypes.guess_type(path.name)[0]:
            extra["ContentType"] = ctype
        s3.upload_file(str(path), step["bucket"], key, ExtraArgs=extra)
        total += size
        if progress and (n <= 20 or n % 25 == 0 or n == len(files)):
            progress(f"  uploaded {n}/{len(files)}: s3://{step['bucket']}/{key}")
    one = f" (s3://{step['bucket']}/{files[0][1]})" if len(files) == 1 else ""
    return {"output": {"bucket": step["bucket"], "keys": [k for _, k, _ in files]},
            "summary": f"{len(files)} file(s), {total / 1048576:.1f} MB uploaded{one}"}


def _run_s3_empty(step, conn, purpose, region, progress):
    s3 = conn.client("s3", purpose, region)
    bucket = step["bucket"]
    try:
        tags = {t["Key"]: t["Value"] for t in s3.get_bucket_tagging(Bucket=bucket).get("TagSet", [])}
    except Exception:
        tags = {}
    if tags.get("CreatedBy") != "kintsugi":
        raise StepError(f"{bucket} was not created by Kintsugi (tag CreatedBy=kintsugi missing); empty it yourself")
    deleted = 0
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
        objs = [{"Key": v["Key"], "VersionId": v["VersionId"]}
                for v in page.get("Versions", []) + page.get("DeleteMarkers", [])]
        for i in range(0, len(objs), 1000):
            s3.delete_objects(Bucket=bucket, Delete={"Objects": objs[i:i + 1000], "Quiet": True})
            deleted += len(objs[i:i + 1000])
            if progress:
                progress(f"  deleted {deleted} object version(s)")
    return {"output": {"bucket": bucket, "deleted": deleted},
            "summary": f"{deleted} object version(s) deleted from {bucket}"}


def _run_cloud(step, conn, purpose, progress):
    from core import clouds
    c = clouds.connector(conn.owner, step["provider"], "read" if purpose == "read" else "operate")
    p = step.get("params", {})
    try:
        if step["action"] == "upload":
            files = upload_plan(Path(p["source"]), p.get("prefix", ""), max_mb=2000)
            for path, key, size in files:
                if size > clouds.MAX_UPLOAD_BYTES:
                    raise StepError(f"{path.name} is larger than 256 MB; use the provider's CLI for big files")
                c.upload_file(path, p["bucket"], key)
                if progress:
                    progress(f"  uploaded {key}")
            return {"output": {"keys": [k for _, k, _ in files]},
                    "summary": f"{len(files)} file(s) uploaded to {p['bucket']}"}
        res = c.vm_action(p["vm"], "start" if step["action"] == "vm_start" else "stop")
        return {"output": res, "summary": f"{res['action']} accepted for {res['vm']}"}
    except clouds.CloudError as e:
        raise StepError(f"{clouds.PROVIDERS[step['provider']]}: {e}") from None


def _run_command(step, conn, purpose, region, progress):
    env = aws_env(conn, purpose, region)
    code, lines = run_process([step["tool"], *step.get("args", [])], env=env, cwd=step.get("cwd"),
                              timeout=_step_timeout(step, 1800), progress=progress)
    if code != 0:
        raise StepError(f"{step['tool']} {_subcommand(step)} failed (exit code {code}):\n      {_tail(lines)}")
    text = "\n".join(lines)[-200_000:]
    out = {"stdout": text}
    try:
        out["json"] = json.loads(text)
    except ValueError:
        pass
    return {"output": out, "summary": _tail(lines, 2).replace("\n      ", " | ")[:200] or "done"}


def _run_ecr_login(step, conn, purpose, region, progress):
    uri = step["repository_uri"]
    if not _ECR_RE.fullmatch(uri):
        raise StepError(f"not an ECR repository URI: {uri}")
    registry = uri.split("/")[0]
    ecr_region = registry.split(".")[3]
    data = conn.client("ecr", purpose, ecr_region).get_authorization_token()["authorizationData"][0]
    user, password = base64.b64decode(data["authorizationToken"]).decode().split(":", 1)
    code, lines = run_process(["docker", "login", "--username", user, "--password-stdin", registry],
                              stdin=password.encode(), timeout=120, progress=progress)
    password = None
    if code != 0:
        raise StepError(f"docker login to {registry} failed: {_tail(lines, 3)}")
    return {"output": {"registry": registry}, "summary": f"logged in to {registry}"}


def ensure_ansible_image(progress=None) -> None:
    code, _ = run_process(["docker", "image", "inspect", ANSIBLE_IMAGE], timeout=60)
    if code == 0:
        return
    if progress:
        progress(f"Building the Ansible runner image {ANSIBLE_IMAGE} (first time only, 1-3 minutes)...")
    d = workspace.WORKSPACE / "_tools" / "ansible"
    workspace.write(d / "Dockerfile", ANSIBLE_DOCKERFILE)
    code, lines = run_process(["docker", "build", "-t", ANSIBLE_IMAGE, str(d)], timeout=900, progress=progress)
    if code != 0:
        raise StepError(f"could not build the Ansible runner image: {_tail(lines, 5)}")


_ANSIBLE_SH = ('umask 077; cat > /tmp/ssh_key; inv="$1"; pb="$2"; shift 2; '
               'ansible-playbook -i "$inv" "$pb" --private-key /tmp/ssh_key "$@"; rc=$?; rm -f /tmp/ssh_key; exit $rc')


def _run_ansible(step, progress):
    ensure_ansible_image(progress)
    key = Path(step["ssh_key_path"]).read_bytes() if step.get("ssh_key_path") else b""
    argv = ["docker", "run", "--rm", "-i", "-v", f"{step['workdir']}:/work", "-w", "/work", ANSIBLE_IMAGE,
            "sh", "-c", _ANSIBLE_SH, "ansible", step["inventory"], step["playbook"], *step.get("extra_args", [])]
    code, lines = run_process(argv, stdin=key, timeout=_step_timeout(step, 1800), progress=progress)
    key = None
    recap = [l for l in lines if re.search(r"\bok=\d+", l)]
    if code != 0:
        raise StepError(f"ansible-playbook failed (exit code {code}):\n      {_tail(lines)}")
    return {"output": {"recap": recap}, "summary": "; ".join(recap)[:200] or _tail(lines, 1)}


def http_get(url: str, timeout: float = 10) -> int:
    req = urllib.request.Request(url, headers={"User-Agent": "Kintsugi-check"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


def _wait_for(fn, deadline: float, delay: float, what: str, progress=None):
    """Call fn() until it returns a truthy value or the deadline passes."""
    last = None
    while True:
        try:
            v = fn()
            if v:
                return v
        except StepError:
            raise
        except Exception as e:
            last = f"{type(e).__name__}: {str(e)[:120]}"
        if time.monotonic() > deadline:
            raise StepError(f"timed out waiting for {what}" + (f" (last error: {last})" if last else ""))
        if progress:
            progress(f"waiting for {what}...")
        time.sleep(delay)


def _run_check(step, conn, purpose, region, progress):
    p = step.get("params", {})
    deadline = time.monotonic() + _step_timeout(step, 600)
    expect = int(p.get("expect", 200))
    path = p.get("path", "/")
    if step["check"] == "http":
        url = p["url"]
    elif step["check"] == "ec2_url":
        ec2 = conn.client("ec2", "read", region)

        def ip():
            res = ec2.describe_instances(InstanceIds=[p["instance_id"]])["Reservations"]
            return res[0]["Instances"][0].get("PublicIpAddress")
        url = f"http://{_wait_for(ip, deadline, 10, 'a public IP', progress)}:{p.get('port', 80)}{path}"
    elif step["check"] == "ecs_url":
        url = f"http://{_wait_for(lambda: _ecs_task_ip(conn, region, p), deadline, 10, 'the task IP', progress)}" \
              f":{p.get('port', 80)}{path}"
    else:
        host = _wait_for(lambda: _k8s_lb_host(conn, purpose, region, p), deadline, 15,
                         "the load balancer address", progress)
        url = f"http://{host}{':' + str(p['port']) if p.get('port') not in (None, 80) else ''}{path}"
    status = {}

    def probe():
        status["code"] = http_get(url)
        return status["code"] == expect
    try:
        _wait_for(probe, deadline, 10, f"{url} to answer HTTP {expect}", progress)
    except StepError as e:
        got = f" (last answer: HTTP {status['code']})" if "code" in status else ""
        raise StepError(f"{e}{got}") from None
    return {"output": {"url": url, "status": expect}, "summary": f"{url} answered HTTP {expect}"}


def _ecs_task_ip(conn, region, p):
    ecs = conn.client("ecs", "read", region)
    arns = ecs.list_tasks(cluster=p["cluster"], serviceName=p["service"], desiredStatus="RUNNING")["taskArns"]
    if not arns:
        return None
    for task in ecs.describe_tasks(cluster=p["cluster"], tasks=arns)["tasks"]:
        if task.get("lastStatus") != "RUNNING":
            continue
        for att in task.get("attachments", []):
            eni = next((d["value"] for d in att.get("details", []) if d["name"] == "networkInterfaceId"), None)
            if eni:
                nif = conn.client("ec2", "read", region).describe_network_interfaces(
                    NetworkInterfaceIds=[eni])["NetworkInterfaces"][0]
                ip = nif.get("Association", {}).get("PublicIp")
                if ip:
                    return ip
    return None


def _k8s_lb_host(conn, purpose, region, p):
    env = aws_env(conn, purpose, region)
    code, lines = run_process(["kubectl", "--kubeconfig", p["kubeconfig"], "get", "service", p["service"],
                               "-n", p.get("namespace", "default"), "-o", "json"], env=env, timeout=120)
    if code != 0:
        return None
    ing = json.loads("\n".join(lines)).get("status", {}).get("loadBalancer", {}).get("ingress", [])
    return (ing[0].get("hostname") or ing[0].get("ip")) if ing else None
