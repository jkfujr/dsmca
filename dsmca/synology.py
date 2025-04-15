import logging, requests, urllib3
from typing import Dict, List, Optional
from urllib.parse import quote

from models import SynologyConfig, CertificateInfo
from utils import clean_filename

logger = logging.getLogger("dsmca.synology")


class SynologyClient:
    """群晖DSM API客户端"""
    
    def __init__(self, config: SynologyConfig):
        """初始化客户端"""
        self.config = config
        self.base_url = f"{config.scheme}://{config.hostname}:{config.port}"
        self.session = requests.Session()
        
        if config.disable_cert_verify:
            self.session.verify = False
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            logger.info("已禁用SSL证书验证")
            
        self.sid = None
        self.syno_token = None
        self.api_path = None
        self.api_version = None
    
    def login(self) -> bool:
        """登录到DSM"""
        try:
            logger.info(f"获取DSM API信息: {self.base_url}")
            api_info_url = f"{self.base_url}/webapi/query.cgi?api=SYNO.API.Info&version=1&method=query&query=SYNO.API.Auth"
            response = self.session.get(api_info_url)
            if response.status_code != 200:
                logger.error(f"获取API信息失败: HTTP {response.status_code}")
                return False
            
            api_info = response.json()
            self.api_path = api_info.get("data", {}).get("SYNO.API.Auth", {}).get("path")
            self.api_version = api_info.get("data", {}).get("SYNO.API.Auth", {}).get("maxVersion")
            
            if not self.api_path or not self.api_version:
                logger.error("无法解析API路径或版本")
                return False
            
            logger.debug(f"API路径: {self.api_path}, 版本: {self.api_version}")
            
            return self._do_login()
        
        except Exception as e:
            logger.error(f"登录过程中发生错误: {str(e)}")
            return False
    
    def _do_login(self) -> bool:
        """执行登录请求"""
        encoded_username = quote(self.config.username)
        encoded_password = quote(self.config.password)
        
        # 直接登录
        login_url = (
            f"{self.base_url}/webapi/{self.api_path}?"
            f"api=SYNO.API.Auth&version={self.api_version}&method=login&format=sid"
            f"&account={encoded_username}&passwd={encoded_password}&enable_syno_token=yes"
        )
        
        response = self.session.get(login_url)
        response_data = response.json()
        
        # 检查是否需要OTP
        if "error" in response_data and response_data.get("error", {}).get("code") == 403:
            logger.info("账户启用了2FA验证，需要OTP代码")
            if not self.config.device_id:
                # 没有device_id，需要OTP代码
                if not self._handle_otp_login(encoded_username, encoded_password):
                    return False
            else:
                device_login_url = (
                    f"{self.base_url}/webapi/{self.api_path}?"
                    f"api=SYNO.API.Auth&version={self.api_version}&method=login&format=sid"
                    f"&account={encoded_username}&passwd={encoded_password}&enable_syno_token=yes"
                    f"&device_name={self.config.device_name}&device_id={self.config.device_id}"
                )
                response = self.session.get(device_login_url)
                response_data = response.json()
                
                if "error" in response_data:
                    logger.error(f"登录失败，设备ID可能已过期: {response_data}")
                    self.config.device_id = None
                    if not self._handle_otp_login(encoded_username, encoded_password):
                        return False
        
        if "error" in response_data:
            error_code = response_data.get("error", {}).get("code")
            logger.error(f"登录失败，错误代码: {error_code}")
            if error_code == 400:
                logger.error("账户不存在或密码错误")
            elif error_code in [408, 409, 410]:
                logger.error("账户密码已过期或需要修改")
            return False
        
        self.sid = response_data.get("data", {}).get("sid")
        self.syno_token = response_data.get("data", {}).get("synotoken")
        
        if not self.sid or not self.syno_token:
            logger.error("无法获取会话ID或令牌")
            return False
        
        logger.info("登录成功")
        self.session.headers.update({"X-SYNO-TOKEN": self.syno_token})
        return True
    
    def _handle_otp_login(self, username: str, password: str) -> bool:
        """处理OTP验证登录"""
        device_name = self.config.device_name or "CertRenewal"
        otp_code = input(f"请输入用户 '{self.config.username}' 的OTP验证码: ")
        
        if not otp_code:
            logger.error("未提供OTP验证码")
            return False
        
        otp_login_url = (
            f"{self.base_url}/webapi/{self.api_path}?"
            f"api=SYNO.API.Auth&version={self.api_version}&method=login&format=sid"
            f"&account={username}&passwd={password}&enable_syno_token=yes&enable_device_token=yes"
            f"&device_name={device_name}&otp_code={otp_code}"
        )
        
        response = self.session.get(otp_login_url)
        response_data = response.json()
        
        if "error" in response_data:
            logger.error(f"OTP验证失败: {response_data}")
            return False
        
        self.sid = response_data.get("data", {}).get("sid")
        self.syno_token = response_data.get("data", {}).get("synotoken")
        if int(self.api_version) > 6:
            device_id_key = "device_id"
        else:
            device_id_key = "did"
        
        self.config.device_id = response_data.get("data", {}).get(device_id_key)
        
        if not self.sid or not self.syno_token:
            logger.error("无法获取会话ID或令牌")
            return False
        
        logger.info(f"OTP验证成功，设备ID: {self.config.device_id}")
        # 设置会话头部
        self.session.headers.update({"X-SYNO-TOKEN": self.syno_token})
        return True

    def logout(self) -> bool:
        """注销会话"""
        try:
            if self.sid:
                logout_url = (
                    f"{self.base_url}/webapi/{self.api_path}?"
                    f"api=SYNO.API.Auth&version={self.api_version}&method=logout&_sid={self.sid}"
                )
                self.session.get(logout_url)
                logger.info("已注销会话")
            
            return True
        except Exception as e:
            logger.error(f"注销失败: {str(e)}")
            return False
    
    def __enter__(self):
        """上下文管理器入口"""
        self.login()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """上下文管理器退出"""
        self.logout()
    
    def get_certificates(self) -> List[Dict]:
        """获取所有证书"""
        try:
            url = f"{self.base_url}/webapi/entry.cgi"
            params = {
                'api': 'SYNO.Core.Certificate.CRT',
                'method': 'list',
                'version': '1',
                '_sid': self.sid
            }
            
            logger.info("获取DSM证书列表...")
            response = self.session.post(url, data=params)
            response_data = response.json()
            
            # logger.info("原始数据:")
            # logger.info(f"{response_data}")
            
            if "error" in response_data:
                error_code = response_data.get("error", {}).get("code")
                logger.error(f"获取证书列表失败，错误代码: {error_code}")
                if error_code == 103:
                    logger.error("当前用户可能没有足够的权限查看证书")
                return []
            
            certificates = response_data.get("data", {}).get("certificates", [])
            logger.info(f"找到 {len(certificates)} 个证书")
            return certificates
        
        except Exception as e:
            logger.error(f"获取证书列表失败: {str(e)}")
            return []
    
    def find_certificate(self, desc: str) -> Optional[Dict]:
        """根据描述查找证书"""
        certs = self.get_certificates()
        safe_desc = clean_filename(desc)
        
        for cert in certs:
            cert_desc = cert.get("desc", "")
            if cert_desc == desc or cert_desc == safe_desc:
                return cert
        
        return None
    
    def deploy_certificate(self, cert_info: CertificateInfo) -> bool:
        """部署证书到DSM"""
        try:
            if not self.sid:
                logger.error("未登录，无法部署证书")
                return False
            
            cert_desc = self.config.certificate_desc
            cert = None
            
            if cert_desc:
                cert = self.find_certificate(cert_desc)
                if not cert and not self.config.create_cert:
                    logger.error(f"未找到证书 '{cert_desc}'，且未启用创建选项")
                    return False
            else:
                cert_desc = cert_info.domain
                cert = self.find_certificate(cert_desc)
            
            original_desc = cert_desc
            safe_cert_desc = clean_filename(cert_desc)
            
            url = f"{self.base_url}/webapi/entry.cgi"
            cert_id = cert.get("id", "") if cert else ""
            is_default = cert.get("is_default", False) if cert else False
            files = {
                'key': (f"{cert_info.domain}.key", cert_info.private_key, 'application/octet-stream'),
                'cert': (f"{cert_info.domain}.crt", cert_info.certificate, 'application/octet-stream'),
                'id': (None, cert_id),
                'desc': (None, safe_cert_desc),
            }
            
            if is_default:
                files['as_default'] = (None, 'true')
            logger.info(f"正在上传证书 '{original_desc}'...")
            params = {
                'api': 'SYNO.Core.Certificate',
                'method': 'import',
                'version': '1',
                'SynoToken': self.syno_token,
                '_sid': self.sid
            }
            
            response = self.session.post(url, params=params, files=files)
            response_data = response.json()
            
            if "error" in response_data:
                logger.error(f"上传证书失败: {response_data}")
                return False
            
            logger.info(f"证书 '{original_desc}' 上传成功")
            return True
            
        except Exception as e:
            logger.error(f"部署证书失败: {str(e)}")
            return False 