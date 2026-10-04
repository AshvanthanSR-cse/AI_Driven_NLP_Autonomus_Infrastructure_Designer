"""Credential vault: the ONLY place AWS secrets are decrypted.

Auth modes (preferred first): assume_role, profile, keys.
Rules: verify with sts:GetCallerIdentity before saving, reject root, encrypt before DB write,
show only the last 4 chars afterwards, per-owner isolation.
"""
import re
import time

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from cryptography.fernet import Fernet, InvalidToken

from core import db
from core.config import settings

PURPOSES = ("read", "operate", "deploy")
AUTH_MODES = ("assume_role", "profile", "keys")

_ACCESS_KEY_RE = re.compile(r"^(AKIA|ASIA)[A-Z0-9]{16}$")
_ROLE_ARN_RE = re.compile(r"^arn:aws[a-z-]*:iam::\d{12}:role/[\w+=,.@/-]+$")

_SESSION_TTL_S = 45 * 60  # assumed-role creds last 1h; refresh well before that
_session_cache: dict[tuple[str, str], tuple[float, boto3.Session]] = {}


class VaultError(Exception):
    """Safe-to-display error. Never contains secret values."""


# ---- encryption -----------------------------------------------------------------

def _fernet() -> Fernet:
    if not settings.app_secret_key:
        raise VaultError("APP_SECRET_KEY is not set in .env")
    try:
        return Fernet(settings.app_secret_key.encode())
    except Exception:
        raise VaultError("APP_SECRET_KEY in .env is not a valid Fernet key") from None


def encrypt(secret: str) -> str:
    return _fernet().encrypt(secret.encode()).decode()


def decrypt(token: str) -> str:
    try:
        return _fernet().decrypt(token.encode()).decode()
    except InvalidToken:
        raise VaultError("Stored secret cannot be decrypted (APP_SECRET_KEY changed?)") from None


def key_hint(access_key_id: str) -> str:
    return access_key_id[-4:] if access_key_id else ""


# ---- session building -------------------------------------------------------------

def _base_session_for_assume_role(region: str) -> boto3.Session:
    """Source identity used to call sts:AssumeRole: the local read profile."""
    if not settings.aws_read_profile:
        raise VaultError("assume_role needs AWS_READ_PROFILE in .env as the source identity")
    return boto3.Session(profile_name=settings.aws_read_profile, region_name=region)


def _build_session(*, auth_mode, region, access_key_id=None, secret=None,
                   profile_name=None, role_arn=None, external_id=None, purpose="read") -> boto3.Session:
    region = region or settings.aws_region
    try:
        if auth_mode == "keys":
            return boto3.Session(aws_access_key_id=access_key_id, aws_secret_access_key=secret, region_name=region)
        if auth_mode == "profile":
            return boto3.Session(profile_name=profile_name, region_name=region)
        if auth_mode == "assume_role":
            sts = _base_session_for_assume_role(region).client("sts")
            kwargs = dict(RoleArn=role_arn, RoleSessionName=f"cloudai-{purpose}", DurationSeconds=3600)
            if external_id:
                kwargs["ExternalId"] = external_id
            c = sts.assume_role(**kwargs)["Credentials"]
            return boto3.Session(
                aws_access_key_id=c["AccessKeyId"],
                aws_secret_access_key=c["SecretAccessKey"],
                aws_session_token=c["SessionToken"],
                region_name=region,
            )
    except ClientError as e:
        raise VaultError(f"AWS rejected the credential: {e.response['Error'].get('Code', 'error')}") from None
    except BotoCoreError as e:
        raise VaultError(f"Could not build AWS session: {type(e).__name__}") from None
    raise VaultError(f"Unknown auth mode '{auth_mode}'")


def verify_identity(session: boto3.Session) -> dict:
    """Call sts:GetCallerIdentity. Rejects root. Returns {'account', 'arn'}."""
    try:
        ident = session.client("sts").get_caller_identity()
    except ClientError as e:
        raise VaultError(f"Verification failed: {e.response['Error'].get('Code', 'error')}") from None
    except BotoCoreError as e:
        raise VaultError(f"Verification failed: {type(e).__name__}") from None
    arn = ident.get("Arn", "")
    if arn.endswith(":root"):
        raise VaultError("Root account credentials are not allowed. Create a least-privilege IAM user or role.")
    return {"account": ident.get("Account", ""), "arn": arn}


# ---- public API -------------------------------------------------------------------

def _check_and_verify(purpose, auth_mode, region, access_key_id, secret, profile_name, role_arn, external_id):
    """Validate inputs, then verify with sts:GetCallerIdentity. Returns (identity, normalized fields)."""
    access_key_id, profile_name, role_arn = (x.strip() for x in (access_key_id, profile_name, role_arn))
    secret = secret.strip()
    region = (region or settings.aws_region).strip()
    if purpose not in PURPOSES:
        raise VaultError(f"Purpose must be one of {PURPOSES}")
    if auth_mode not in AUTH_MODES:
        raise VaultError(f"Auth mode must be one of {AUTH_MODES}")
    if auth_mode == "keys":
        if not _ACCESS_KEY_RE.match(access_key_id):
            raise VaultError("Access key ID looks invalid (expected AKIA... with 20 characters)")
        if access_key_id.startswith("ASIA"):
            raise VaultError("Temporary (ASIA...) keys expire; use a long-lived IAM user key or assume_role")
        if len(secret) < 30:
            raise VaultError("Secret access key looks invalid")
    elif auth_mode == "profile" and not profile_name:
        raise VaultError("Profile name is required")
    elif auth_mode == "assume_role" and not _ROLE_ARN_RE.match(role_arn):
        raise VaultError("Role ARN looks invalid (arn:aws:iam::<12 digits>:role/<name>)")

    session = _build_session(auth_mode=auth_mode, region=region, access_key_id=access_key_id, secret=secret,
                             profile_name=profile_name, role_arn=role_arn, external_id=external_id, purpose=purpose)
    ident = verify_identity(session)
    return ident, dict(region=region, access_key_id=access_key_id, secret=secret, profile_name=profile_name,
                       role_arn=role_arn, external_id=external_id)


def test_credential(purpose: str, auth_mode: str, *, region: str = "", access_key_id: str = "", secret: str = "",
                    profile_name: str = "", role_arn: str = "", external_id: str = "") -> dict:
    """Verify only (nothing is saved). Returns {'account', 'arn'}."""
    ident, _ = _check_and_verify(purpose, auth_mode, region, access_key_id, secret, profile_name, role_arn,
                                 external_id)
    return ident


def add_credential(owner: str, label: str, purpose: str, auth_mode: str, *, region: str = "",
                   access_key_id: str = "", secret: str = "", profile_name: str = "",
                   role_arn: str = "", external_id: str = "") -> dict:
    """Verify, then encrypt and store. Returns the masked record. The caller must wipe its secret field."""
    label = label.strip()
    if not label:
        raise VaultError("Connection name is required")
    ident, f = _check_and_verify(purpose, auth_mode, region, access_key_id, secret, profile_name, role_arn,
                                 external_id)
    region, access_key_id, secret = f["region"], f["access_key_id"], f["secret"]
    profile_name, role_arn, external_id = f["profile_name"], f["role_arn"], f["external_id"]

    try:
        new_id = db.execute(
            """INSERT INTO aws_credentials
                 (owner, label, purpose, auth_mode, access_key_id, key_hint, secret_enc,
                  role_arn, external_id, profile_name, region, account_id, verified_at)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s, now()) RETURNING id""",
            (
                owner, label, purpose, auth_mode,
                access_key_id or None,
                key_hint(access_key_id) or None,
                encrypt(secret) if auth_mode == "keys" else None,
                role_arn or None, external_id or None, profile_name or None,
                region, ident["account"],
            ),
        )
    except Exception as e:
        if "aws_credentials_owner_label_key" in str(e) or "duplicate key" in str(e):
            raise VaultError(f"A connection named '{label}' already exists") from None
        raise VaultError(f"Could not save connection: {type(e).__name__}") from None
    _session_cache.pop((owner, purpose), None)
    return {"id": new_id, "label": label, "purpose": purpose, "auth_mode": auth_mode,
            "account_id": ident["account"], "arn": ident["arn"]}


def list_credentials(owner: str) -> list[dict]:
    """Masked view for the Connections page. Never returns secret_enc or the full access key."""
    return db.fetch_all(
        """SELECT id, label, purpose, auth_mode, key_hint, role_arn, profile_name, region,
                  account_id, verified_at, last_used_at, created_at
           FROM aws_credentials WHERE owner = %s ORDER BY purpose, label""",
        (owner,),
    )


def delete_credential(owner: str, cred_id: int) -> bool:
    _session_cache.clear()
    with db.cursor() as cur:
        cur.execute("DELETE FROM aws_credentials WHERE id = %s AND owner = %s", (cred_id, owner))
        return cur.rowcount == 1


def get_session(owner: str, purpose: str, region: str | None = None) -> boto3.Session:
    """Return a boto3 Session for this owner and purpose (read|operate|deploy).

    Picks the most recently verified stored connection for that purpose. For 'read' only, falls back
    to AWS_READ_PROFILE from .env. Write purposes never fall back: they need an explicit task identity.
    """
    if purpose not in PURPOSES:
        raise VaultError(f"Unknown purpose '{purpose}'")
    region = region or settings.aws_region
    cache_key = (owner, purpose)
    cached = _session_cache.get(cache_key)
    if cached and time.time() - cached[0] < _SESSION_TTL_S and cached[1].region_name == region:
        return cached[1]

    try:
        row = db.fetch_one(
            """SELECT id, auth_mode, access_key_id, secret_enc, role_arn, external_id, profile_name
               FROM aws_credentials WHERE owner = %s AND purpose = %s
               ORDER BY verified_at DESC NULLS LAST, id DESC LIMIT 1""",
            (owner, purpose),
        )
    except db.DatabaseError:
        row = None
        if purpose != "read":
            raise

    if row:
        session = _build_session(
            auth_mode=row["auth_mode"], region=region, access_key_id=row["access_key_id"],
            secret=decrypt(row["secret_enc"]) if row["secret_enc"] else None,
            profile_name=row["profile_name"], role_arn=row["role_arn"], external_id=row["external_id"],
            purpose=purpose,
        )
        try:
            db.execute("UPDATE aws_credentials SET last_used_at = now() WHERE id = %s", (row["id"],))
        except Exception:
            pass
    elif purpose == "read" and settings.aws_read_profile:
        session = boto3.Session(profile_name=settings.aws_read_profile, region_name=region)
    else:
        use_for = {"read": "Read", "operate": "Write", "deploy": "Deploy"}[purpose]
        raise VaultError(
            f"No {use_for} connection yet. Add an IAM user's keys on the Connections page with "
            f"'Use this connection for' = {use_for} (or Read and Write)."
        )
    _session_cache[cache_key] = (time.time(), session)
    return session
