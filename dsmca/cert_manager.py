import os, shutil, logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from models import CertificateInfo
from synology import SynologyClient
from utils import load_config, save_config, save_certificate_files, load_certificate_from_files, clean_filename

logger = logging.getLogger("dsmca.cert_manager")


class CertificateManager:
    """证书管理器"""
    
    def __init__(self, config_path: str = "config.yaml", cert_dir: str = "certs"):
        """初始化证书管理器"""
        self.config_path = config_path
        self.cert_dir = cert_dir
        self.config = load_config(config_path)
        os.makedirs(cert_dir, exist_ok=True)
    
    def update_certificate(self, domain: str, certificate: str, private_key: str, domains: Optional[List[str]] = None) -> bool:
        """更新证书信息"""
        if not domains:
            domains = [domain]
        cert_info = CertificateInfo(
            domain=domain,
            domains=domains,
            certificate=certificate,
            private_key=private_key,
            last_updated=datetime.now()
        )
        try:
            save_certificate_files(cert_info, self.cert_dir)
            self.config.certificates[domain] = cert_info
            save_config(self.config, self.config_path)
            
            logger.info(f"已更新证书: {domain}")
            return True
        except Exception as e:
            logger.error(f"更新证书失败: {str(e)}")
            return False
    
    def deploy_certificate(self, domain: str) -> bool:
        """部署证书到DSM"""
        try:
            cert_info = self.config.certificates.get(domain)
            if not cert_info:
                cert_info = load_certificate_from_files(domain, self.cert_dir)
            if not cert_info:
                logger.error(f"无法找到证书: {domain}")
                return False
            with SynologyClient(self.config.synology) as client:
                if not client.sid:
                    logger.error("登录DSM失败")
                    return False
                
                result = client.deploy_certificate(cert_info)
                return result
        
        except Exception as e:
            logger.error(f"部署证书失败: {str(e)}")
            return False
    
    def get_certificate(self, domain: str) -> Optional[CertificateInfo]:
        """获取证书信息"""
        cert_info = self.config.certificates.get(domain)
        if not cert_info:
            cert_info = load_certificate_from_files(domain, self.cert_dir)
            if cert_info:
                self.config.certificates[domain] = cert_info
                save_config(self.config, self.config_path)
        
        return cert_info
    
    def get_all_certificates(self) -> Dict[str, CertificateInfo]:
        """获取所有证书信息"""
        certs = {}
        for domain, cert_info in self.config.certificates.items():
            certs[domain] = cert_info
        if os.path.exists(self.cert_dir):
            for item in os.listdir(self.cert_dir):
                domain_dir = os.path.join(self.cert_dir, item)
                if os.path.isdir(domain_dir) and item not in certs:
                    cert_info = load_certificate_from_files(item, self.cert_dir)
                    if cert_info:
                        certs[cert_info.domain] = cert_info
                        self.config.certificates[cert_info.domain] = cert_info
                save_config(self.config, self.config_path)
        
        return certs
    
    def delete_certificate(self, domain: str) -> bool:
        """删除证书"""
        try:
            if domain in self.config.certificates:
                del self.config.certificates[domain]
                save_config(self.config, self.config_path)
            safe_domain = clean_filename(domain)
            domain_dir = os.path.join(self.cert_dir, safe_domain)
            if os.path.exists(domain_dir):
                shutil.rmtree(domain_dir)
            
            logger.info(f"已删除证书: {domain}")
            return True
        except Exception as e:
            logger.error(f"删除证书失败: {str(e)}")
            return False
    
    def check_certificates_expiry(self, days: int = 30) -> Dict[str, timedelta]:
        """检查证书到期时间"""
        expiry_info = {}
        certs = self.get_all_certificates()
        
        for domain, cert_info in certs.items():
            if cert_info.expiry_date:
                remaining = cert_info.expiry_date - datetime.now()
                expiry_info[domain] = remaining
                if remaining.days <= days:
                    logger.warning(f"证书即将过期: {domain}, 剩余 {remaining.days} 天")
        
        return expiry_info


def process_webhook_payload(payload: Dict, cert_manager: CertificateManager) -> bool:
    """处理Webhook回调数据"""
    try:
        logger.info(f"处理Webhook数据: {payload.keys()}")
        
        domain = payload.get("name", "").strip()
        cert = payload.get("cert", "").strip()
        privkey = payload.get("privkey", "").strip()
        
        if not domain or not cert or not privkey:
            logger.error("Webhook数据不完整")
            return False
        
        domains = [d.strip() for d in domain.split(",")]
        primary_domain = domains[0]
        logger.info(f"更新域名证书: {primary_domain}")
        safe_domain = clean_filename(primary_domain)
        if safe_domain != primary_domain:
            logger.info(f"域名包含特殊字符，已清理为: {safe_domain}")
        
        result = cert_manager.update_certificate(
            domain=primary_domain,
            certificate=cert,
            private_key=privkey,
            domains=domains
        )
        
        if result:
            deploy_result = cert_manager.deploy_certificate(primary_domain)
            if deploy_result:
                logger.info(f"证书已成功更新并部署: {primary_domain}")
            else:
                logger.error(f"证书已更新但部署失败: {primary_domain}")
            return deploy_result
        
        return False
    
    except Exception as e:
        logger.error(f"处理Webhook数据失败: {str(e)}")
        return False 