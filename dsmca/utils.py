import os
import yaml
import secrets
import logging
from datetime import datetime
from typing import Dict, Optional

from models import Config, CertificateInfo

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("dsmca")


def load_config(config_path: str = "config.yaml") -> Config:
    """从YAML文件加载配置"""
    try:
        if os.path.exists(config_path):
            with open(config_path, 'r', encoding='utf-8') as f:
                config_data = yaml.safe_load(f)
                if not config_data:
                    logger.warning("配置文件为空，使用默认配置")
                    return Config()
                return Config.model_validate(config_data)
        else:
            logger.warning(f"配置文件 {config_path} 不存在，使用默认配置")
            return Config()
    except Exception as e:
        logger.error(f"加载配置文件失败: {str(e)}")
        return Config()


def save_config(config: Config, config_path: str = "config.yaml") -> bool:
    """保存配置到YAML文件"""
    try:
        os.makedirs(os.path.dirname(os.path.abspath(config_path)), exist_ok=True)
        
        with open(config_path, 'w', encoding='utf-8') as f:
            yaml.safe_dump(config.model_dump(exclude_none=True), f, default_flow_style=False, allow_unicode=True)
        return True
    except Exception as e:
        logger.error(f"保存配置文件失败: {str(e)}")
        return False


def generate_auth_token() -> str:
    """生成webhook认证令牌"""
    return secrets.token_urlsafe(32)


def save_certificate_files(cert_info: CertificateInfo, cert_dir: str = "certs") -> Dict[str, str]:
    """保存证书文件到本地"""
    os.makedirs(cert_dir, exist_ok=True)
    
    domain = cert_info.domain
    domain_dir = os.path.join(cert_dir, domain)
    os.makedirs(domain_dir, exist_ok=True)
    
    cert_path = os.path.join(domain_dir, "cert.pem")
    key_path = os.path.join(domain_dir, "privkey.pem")
    
    with open(cert_path, "w") as f:
        f.write(cert_info.certificate)
    
    with open(key_path, "w") as f:
        f.write(cert_info.private_key)
    
    domains_path = os.path.join(domain_dir, "domains.txt")
    with open(domains_path, "w") as f:
        f.write("\n".join(cert_info.domains))
    
    return {
        "cert": cert_path,
        "key": key_path,
        "domains": domains_path
    }


def load_certificate_from_files(domain: str, cert_dir: str = "certs") -> Optional[CertificateInfo]:
    """从本地文件加载证书信息"""
    domain_dir = os.path.join(cert_dir, domain)
    
    if not os.path.exists(domain_dir):
        return None
    
    cert_path = os.path.join(domain_dir, "cert.pem")
    key_path = os.path.join(domain_dir, "privkey.pem")
    domains_path = os.path.join(domain_dir, "domains.txt")
    
    if not all(os.path.exists(p) for p in [cert_path, key_path]):
        return None
    
    try:
        with open(cert_path, "r") as f:
            cert = f.read()
        
        with open(key_path, "r") as f:
            key = f.read()
        
        domains = [domain]
        if os.path.exists(domains_path):
            with open(domains_path, "r") as f:
                domain_list = f.read().splitlines()
                if domain_list:
                    domains = domain_list
        
        return CertificateInfo(
            domain=domain,
            domains=domains,
            certificate=cert,
            private_key=key,
            last_updated=datetime.fromtimestamp(os.path.getmtime(cert_path))
        )
    except Exception as e:
        logger.error(f"从文件加载证书失败: {str(e)}")
        return None 