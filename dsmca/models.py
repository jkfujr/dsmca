from pydantic import BaseModel, Field
from typing import Dict, List, Optional
from datetime import datetime


class SynologyConfig(BaseModel):
    """群晖DSM配置"""
    scheme: str = "http"
    hostname: str = "localhost"
    port: int = 5000
    username: Optional[str] = None
    password: Optional[str] = None
    device_id: Optional[str] = None
    device_name: Optional[str] = "CertRenewal"
    certificate_desc: Optional[str] = None
    create_cert: bool = False
    disable_cert_verify: bool = False


class WebhookConfig(BaseModel):
    """Webhook配置"""
    enabled: bool = False
    port: int = 18102
    path: str = "/webhook"
    auth_token: Optional[str] = None


class CertificateInfo(BaseModel):
    """证书信息"""
    domain: str
    domains: List[str]
    certificate: str
    private_key: str
    expiry_date: Optional[datetime] = None
    last_updated: Optional[datetime] = None


class WebhookPayload(BaseModel):
    """Webhook回调数据"""
    name: str
    cert: str
    privkey: str


class Config(BaseModel):
    """全局配置"""
    synology: SynologyConfig = Field(default_factory=SynologyConfig)
    webhook: WebhookConfig = Field(default_factory=WebhookConfig)
    certificates: Dict[str, CertificateInfo] = {} 