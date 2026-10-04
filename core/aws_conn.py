"""Connection manager: one interface for tools, whatever auth mode is behind it.

Tools never touch credentials; they ask for a client by purpose (read | operate | deploy).
The purpose comes from the tool's declared risk, chosen by code, never by the LLM.
"""
from botocore.config import Config

from core import vault
from core.config import settings

_BOTO_CONFIG = Config(retries={"max_attempts": 3, "mode": "standard"}, connect_timeout=10, read_timeout=30)

RISK_TO_PURPOSE = {"read": "read", "operate": "operate", "deploy": "deploy"}


class AwsConnection:
    def __init__(self, owner: str | None = None):
        self.owner = owner or settings.app_user

    def get_session(self, purpose: str, region: str | None = None):
        return vault.get_session(self.owner, purpose, region)

    def client(self, service: str, purpose: str = "read", region: str | None = None):
        session = self.get_session(purpose, region)
        return session.client(service, region_name=region or session.region_name or settings.aws_region,
                              config=_BOTO_CONFIG)
