"""Other cloud providers behind one small connector interface (AWS stays the main, full-featured provider).

Connector (per owner + purpose, credentials from the vault, never seen by the LLM):
    verify() -> {"identity", "scope"}
    list_vms() -> [{name, id, location, state, size, provider fields...}]
    vm_action(vm, action)            action: start | stop
    list_storage() -> [{name, location, kind}]
    upload_file(path, bucket, key)   bucket = Azure "account/container" or GCS bucket name

Azure: Azure CLI sign-in (az login; tokens come from `az account get-access-token`, nothing is stored), or a
       service principal (tenant ID, client ID, client secret, subscription ID), OAuth client-credentials.
GCP:   service-account JSON key, OAuth JWT-bearer signed locally with the key (cryptography package).
Plain HTTPS (urllib) so no extra SDKs are needed. Adding a provider = one more Connector subclass.
"""
import base64
import json
import mimetypes
import os
import re
import shutil
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

PROVIDERS = {"aws": "Amazon Web Services", "azure": "Microsoft Azure", "gcp": "Google Cloud"}
OTHER_PROVIDERS = ("azure", "gcp")
MAX_UPLOAD_BYTES = 256 * 1024 * 1024


class CloudError(Exception):
    """Safe-to-display error (never contains tokens or secrets)."""


def http(method: str, url: str, *, token: str | None = None, body=None, form: dict | None = None,
         headers: dict | None = None, timeout: int = 60) -> dict:
    hdrs = dict(headers or {})
    data = None
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        hdrs["Content-Type"] = "application/x-www-form-urlencoded"
    elif isinstance(body, (bytes, bytearray)):
        data = bytes(body)
    elif body is not None:
        data = json.dumps(body).encode()
        hdrs["Content-Type"] = "application/json"
    elif method in ("POST", "PUT"):
        data = b""
    if token:
        hdrs["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=data, method=method, headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            return json.loads(raw) if raw.strip().startswith((b"{", b"[")) else {"status": r.status}
    except urllib.error.HTTPError as e:
        raise CloudError(_error_text(e)) from None
    except urllib.error.URLError as e:
        raise CloudError(f"network error: {e.reason}") from None


def _error_text(e: urllib.error.HTTPError) -> str:
    try:
        payload = json.loads(e.read() or b"{}")
    except ValueError:
        payload = {}
    err = payload.get("error")
    if isinstance(err, dict):
        msg = err.get("message") or err.get("code") or ""
        code = err.get("code") or err.get("status") or e.code
    else:
        msg, code = payload.get("error_description") or str(err or ""), e.code
    msg = re.sub(r"(?i)(secret|token|assertion)[^\s,]*", "[hidden]", str(msg))[:300]
    if e.code in (401, 403):
        return f"HTTP {e.code} {code}: not allowed (check the role assigned to this identity). {msg}".strip()
    return f"HTTP {e.code} {code}: {msg}".strip()


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


class Connector:
    provider = ""

    def __init__(self, config: dict, secret: str):
        self.config = config
        self._secret = secret
        self._tokens: dict[str, tuple[float, str]] = {}
        self._lock = threading.Lock()

    def _token(self, scope: str) -> str:
        with self._lock:
            hit = self._tokens.get(scope)
            if hit and hit[0] > time.time() + 60:
                return hit[1]
            tok, expires_in = self._fetch_token(scope)
            self._tokens[scope] = (time.time() + expires_in, tok)
            return tok

    def _fetch_token(self, scope: str) -> tuple[str, int]:
        raise NotImplementedError

    def verify(self) -> dict:
        raise NotImplementedError

    def list_vms(self) -> list[dict]:
        raise NotImplementedError

    def vm_action(self, vm: str, action: str) -> dict:
        raise NotImplementedError

    def list_storage(self) -> list[dict]:
        raise NotImplementedError

    def upload_file(self, path: Path, bucket: str, key: str) -> dict:
        raise NotImplementedError

    def find_vm(self, ref: str) -> dict:
        vms = [v for v in self.list_vms() if ref in (v["name"], v["id"])]
        if not vms:
            raise CloudError(f"no {PROVIDERS[self.provider]} VM named '{ref}'")
        if len(vms) > 1:
            raise CloudError(f"'{ref}' matches several VMs: {', '.join(v['id'] for v in vms)}; use the full id")
        return vms[0]


_AZURE_ARM = "https://management.azure.com"
_AZ_COMPUTE_API, _AZ_STORAGE_API, _AZ_BLOB_VERSION = "2024-07-01", "2023-05-01", "2023-11-03"
_GUID = re.compile(r"[0-9a-fA-F-]{36}")


class AzureConnector(Connector):
    provider = "azure"

    @staticmethod
    def check_fields(tenant_id: str, client_id: str, subscription_id: str, secret: str) -> None:
        for name, v in (("Tenant ID", tenant_id), ("Client (application) ID", client_id),
                        ("Subscription ID", subscription_id)):
            if not _GUID.fullmatch(v or ""):
                raise CloudError(f"{name} must be a GUID like 00000000-0000-0000-0000-000000000000")
        if len(secret or "") < 8:
            raise CloudError("client secret looks invalid")

    def _fetch_token(self, scope):
        r = http("POST", f"https://login.microsoftonline.com/{self.config['tenant_id']}/oauth2/v2.0/token",
                 form={"client_id": self.config["client_id"], "client_secret": self._secret,
                       "grant_type": "client_credentials", "scope": scope})
        return r["access_token"], int(r.get("expires_in", 3600))

    def _arm(self, method, path, **kw):
        return http(method, _AZURE_ARM + path, token=self._token(f"{_AZURE_ARM}/.default"), **kw)

    def _pages(self, path):
        out, url = [], _AZURE_ARM + path
        while url:
            r = http("GET", url, token=self._token(f"{_AZURE_ARM}/.default"))
            out += r.get("value", [])
            url = r.get("nextLink")
        return out

    def verify(self):
        sub = self._arm("GET", f"/subscriptions/{self.config['subscription_id']}?api-version=2022-12-01")
        return {"identity": f"app {self.config['client_id']}",
                "scope": f"subscription {sub.get('displayName', '')} ({self.config['subscription_id']})"}

    def list_vms(self):
        sub = self.config["subscription_id"]
        vms = self._pages(f"/subscriptions/{sub}/providers/Microsoft.Compute/virtualMachines"
                          f"?api-version={_AZ_COMPUTE_API}&statusOnly=true")
        rows = []
        for v in vms:
            statuses = (v.get("properties", {}).get("instanceView") or {}).get("statuses", [])
            power = next((s["code"].split("/", 1)[1] for s in statuses if s.get("code", "").startswith("PowerState/")), "")
            rg = v["id"].split("/resourceGroups/")[1].split("/")[0]
            rows.append({"name": v["name"], "id": v["id"], "resource_group": rg, "location": v.get("location"),
                         "state": power, "size": v.get("properties", {}).get("hardwareProfile", {}).get("vmSize", ""),
                         "tags": v.get("tags") or {}})
        return rows

    def vm_action(self, vm, action):
        op = {"start": "start", "stop": "deallocate"}[action]
        v = self.find_vm(vm)
        self._arm("POST", f"{v['id']}/{op}?api-version={_AZ_COMPUTE_API}")
        return {"vm": v["name"], "action": op, "accepted": True}

    def list_storage(self):
        sub = self.config["subscription_id"]
        out = []
        for a in self._pages(f"/subscriptions/{sub}/providers/Microsoft.Storage/storageAccounts"
                             f"?api-version={_AZ_STORAGE_API}"):
            for c in self._pages(f"{a['id']}/blobServices/default/containers?api-version={_AZ_STORAGE_API}"):
                out.append({"name": f"{a['name']}/{c['name']}", "location": a.get("location"), "kind": "blob container"})
        return out

    def upload_file(self, path, bucket, key):
        account, _, container = bucket.partition("/")
        if not account or not container:
            raise CloudError("for Azure use 'storageaccount/container' as the bucket")
        url = f"https://{account}.blob.core.windows.net/{container}/{urllib.parse.quote(key)}"
        ctype = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        http("PUT", url, token=self._token("https://storage.azure.com/.default"), body=path.read_bytes(),
             headers={"x-ms-blob-type": "BlockBlob", "x-ms-version": _AZ_BLOB_VERSION, "Content-Type": ctype},
             timeout=600)
        return {"url": url}


_GCE = "https://compute.googleapis.com/compute/v1"
_GCS = "https://storage.googleapis.com"


class GcpConnector(Connector):
    provider = "gcp"
    SCOPE = "https://www.googleapis.com/auth/cloud-platform"

    @staticmethod
    def parse_key(text: str) -> dict:
        try:
            key = json.loads(text)
        except ValueError:
            raise CloudError("the key file is not valid JSON (download a JSON key for a service account)") from None
        if key.get("type") != "service_account" or not all(key.get(k) for k in
                                                           ("client_email", "private_key", "project_id")):
            raise CloudError("not a service-account JSON key (needs type, client_email, private_key, project_id)")
        return key

    def _fetch_token(self, scope):
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
        key = json.loads(self._secret)
        now = int(time.time())
        token_uri = key.get("token_uri", "https://oauth2.googleapis.com/token")
        head = _b64url(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
        claims = _b64url(json.dumps({"iss": key["client_email"], "scope": scope, "aud": token_uri,
                                     "iat": now, "exp": now + 3600}).encode())
        pk = serialization.load_pem_private_key(key["private_key"].encode(), password=None)
        sig = _b64url(pk.sign(f"{head}.{claims}".encode(), padding.PKCS1v15(), hashes.SHA256()))
        r = http("POST", token_uri, form={"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                                          "assertion": f"{head}.{claims}.{sig}"})
        return r["access_token"], int(r.get("expires_in", 3600))

    def _get_all(self, url, key):
        out, token = [], None
        while True:
            sep = "&" if "?" in url else "?"
            r = http("GET", url + (f"{sep}pageToken={urllib.parse.quote(token)}" if token else ""),
                     token=self._token(self.SCOPE))
            items = r.get(key, [])
            if isinstance(items, dict):
                for scoped in items.values():
                    out += scoped.get("instances", [])
            else:
                out += items
            token = r.get("nextPageToken")
            if not token:
                return out

    def verify(self):
        self._token(self.SCOPE)
        http("GET", f"{_GCS}/storage/v1/b?project={self.config['project_id']}&maxResults=1",
             token=self._token(self.SCOPE))
        return {"identity": self.config["client_email"], "scope": f"project {self.config['project_id']}"}

    def list_vms(self):
        rows = []
        for i in self._get_all(f"{_GCE}/projects/{self.config['project_id']}/aggregated/instances", "items"):
            zone = i.get("zone", "").rsplit("/", 1)[-1]
            rows.append({"name": i["name"], "id": f"{zone}/{i['name']}", "zone": zone, "location": zone,
                         "state": i.get("status", ""), "size": i.get("machineType", "").rsplit("/", 1)[-1],
                         "tags": i.get("labels") or {}})
        return rows

    def vm_action(self, vm, action):
        v = self.find_vm(vm)
        http("POST", f"{_GCE}/projects/{self.config['project_id']}/zones/{v['zone']}/instances/{v['name']}/{action}",
             token=self._token(self.SCOPE))
        return {"vm": v["name"], "action": action, "accepted": True}

    def list_storage(self):
        return [{"name": b["name"], "location": b.get("location"), "kind": b.get("storageClass", "bucket")}
                for b in self._get_all(f"{_GCS}/storage/v1/b?project={self.config['project_id']}", "items")]

    def upload_file(self, path, bucket, key):
        url = (f"{_GCS}/upload/storage/v1/b/{urllib.parse.quote(bucket)}/o?uploadType=media"
               f"&name={urllib.parse.quote(key, safe='')}")
        ctype = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        http("POST", url, token=self._token(self.SCOPE), body=path.read_bytes(), headers={"Content-Type": ctype},
             timeout=600)
        return {"url": f"gs://{bucket}/{key}"}


def az_path() -> str | None:
    return shutil.which("az")


def az_run(args: list[str], timeout: int = 60):
    exe = az_path()
    if not exe:
        raise CloudError("Azure CLI is not installed. Install it with: winget install -e --id Microsoft.AzureCLI")
    flags = {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {}
    try:
        r = subprocess.run([exe, *args, "--output", "json"], capture_output=True, text=True, timeout=timeout,
                           **flags)
    except subprocess.TimeoutExpired:
        raise CloudError(f"az {args[0]} timed out after {timeout} s") from None
    if r.returncode != 0:
        err = (r.stderr or "").strip().splitlines()
        msg = next((l for l in err if l.startswith("ERROR")), err[0] if err else f"exit code {r.returncode}")
        msg = re.sub(r"(?i)(secret|token|password)\S*", "[hidden]", msg)[:300]
        if "az login" in (r.stderr or ""):
            msg += " (click 'Sign in with az login' first)"
        raise CloudError(msg)
    out = (r.stdout or "").strip()
    return json.loads(out) if out else {}


def az_login(tenant_id: str = "") -> list[dict]:
    az_run(["login"] + (["--tenant", tenant_id] if tenant_id else []), timeout=300)
    return az_subscriptions()


def az_subscriptions() -> list[dict]:
    return [{"id": a["id"], "name": a.get("name", ""), "tenant_id": a.get("tenantId", ""),
             "user": (a.get("user") or {}).get("name", ""), "default": bool(a.get("isDefault"))}
            for a in az_run(["account", "list"]) if a.get("state", "Enabled") == "Enabled"]


class AzureCliConnector(AzureConnector):

    @staticmethod
    def check_cli_fields(subscription_id: str) -> None:
        if not _GUID.fullmatch(subscription_id or ""):
            raise CloudError("choose a subscription (Subscription ID must be a GUID)")
        if not az_path():
            raise CloudError("Azure CLI is not installed. Install it with: winget install -e --id Microsoft.AzureCLI")

    def _fetch_token(self, scope):
        resource = scope.removesuffix(".default")
        r = az_run(["account", "get-access-token", "--resource", resource,
                    "--subscription", self.config["subscription_id"]])
        expires = int(r.get("expires_on") or 0) - int(time.time()) if r.get("expires_on") else 1800
        return r["accessToken"], max(120, min(expires, 3600))

    def verify(self):
        acct = az_run(["account", "show", "--subscription", self.config["subscription_id"]])
        user = (acct.get("user") or {}).get("name", "")
        self._arm("GET", f"/subscriptions/{self.config['subscription_id']}?api-version=2022-12-01")
        return {"identity": f"az login {user}".strip(),
                "scope": f"subscription {acct.get('name', '')} ({self.config['subscription_id']})",
                "user": user, "tenant_id": acct.get("tenantId", "")}


CONNECTORS = {"azure": AzureConnector, "gcp": GcpConnector}
_cache: dict[tuple, tuple[float, Connector]] = {}


def connector(owner: str, provider: str, purpose: str) -> Connector:
    """Connector for a stored connection (the vault decrypts the secret; tokens are cached in memory only)."""
    from core import vault
    if provider not in CONNECTORS:
        raise CloudError(f"unknown cloud provider '{provider}' (supported: {', '.join(CONNECTORS)})")
    key = (owner, provider, purpose)
    hit = _cache.get(key)
    if hit and time.time() - hit[0] < 1800:
        return hit[1]
    config, secret = vault.get_cloud_secret(owner, provider, purpose)
    c = make_connector(provider, config, secret)
    _cache[key] = (time.time(), c)
    return c


def make_connector(provider: str, config: dict, secret: str) -> Connector:
    if provider == "azure" and config.get("auth") == "cli":
        return AzureCliConnector(config, secret)
    return CONNECTORS[provider](config, secret)


def forget(owner: str | None = None) -> None:
    for k in [k for k in _cache if owner is None or k[0] == owner]:
        _cache.pop(k, None)
