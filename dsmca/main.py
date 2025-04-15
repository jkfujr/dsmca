import os, argparse, logging, uvicorn, requests
from typing import  Optional
from fastapi import FastAPI, Depends, HTTPException, Header, Body
from fastapi.responses import JSONResponse

from utils import save_config, generate_auth_token
from cert_manager import CertificateManager, process_webhook_payload
from synology import SynologyClient

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("dsmca")

app = FastAPI()

CONFIG_PATH = os.environ.get("DSMCA_CONFIG", "config.yaml")
CERT_DIR = os.environ.get("DSMCA_CERT_DIR", "certs")
AUTO_ENABLE_WEBHOOK = os.environ.get("DSMCA_AUTO_ENABLE_WEBHOOK", "1") == "1"

cert_manager = CertificateManager(CONFIG_PATH, CERT_DIR)
config = cert_manager.config

async def verify_token(authorization: Optional[str] = Header(None)):
    """验证认证令牌"""
    if not config.webhook.enabled:
        return True
    
    if not config.webhook.auth_token:
        return True
    
    if not authorization:
        raise HTTPException(status_code=401, detail="未提供认证令牌")
    
    token = None
    if authorization.startswith("Bearer "):
        token = authorization.replace("Bearer ", "")
    else:
        token = authorization
    
    if token != config.webhook.auth_token:
        raise HTTPException(status_code=403, detail="认证令牌无效")
    
    return True


@app.get("/", tags=["健康检查"])
async def root():
    """服务健康检查"""
    return {"status": "online", "webhook_enabled": config.webhook.enabled}


@app.post("/webhook", tags=["Webhook"])
async def webhook_handler(
    payload: dict = Body(...),
    authorized: bool = Depends(verify_token)
):
    """接收证书更新的Webhook"""
    try:
        logger.info(f"收到Webhook请求: {payload.keys()}")
        result = process_webhook_payload(payload, cert_manager)
        
        if result:
            return JSONResponse(
                status_code=200,
                content={"status": "success", "message": "证书已更新并部署"}
            )
        else:
            return JSONResponse(
                status_code=400,
                content={"status": "error", "message": "处理证书失败"}
            )
    
    except Exception as e:
        logger.error(f"处理Webhook请求失败: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={"status": "error", "message": str(e)}
        )


def start_webhook_server():
    """启动Webhook服务器"""
    if not config.webhook.enabled:
        logger.warning("Webhook服务未启用，请在配置中启用")
        return
    
    port = config.webhook.port
    
    logger.info(f"启动Webhook服务器，监听端口: {port}")
    uvicorn.run(app, host="0.0.0.0", port=port)


def initialize_config():
    """初始化配置文件"""
    if os.path.exists(CONFIG_PATH):
        logger.info("配置文件已存在，跳过初始化")
        return
    
    logger.info("初始化配置文件...")
    
    # 初始化
    config.synology.hostname = input("请输入群晖DSM主机地址 [localhost]: ") or "localhost"
    config.synology.port = int(input("请输入群晖DSM端口 [5000]: ") or "5000")
    use_https = input("是否使用HTTPS连接? (y/n) [n]: ").lower() == 'y'
    if use_https:
        config.synology.scheme = "https"
        disable_cert_verify = input("是否禁用SSL证书验证? (y/n) [y]: ").lower() != 'n'
        config.synology.disable_cert_verify = disable_cert_verify
    config.synology.username = input("请输入群晖DSM管理员用户名: ")
    config.synology.password = input("请输入群晖DSM管理员密码: ")
    config.synology.certificate_desc = input("请输入要更新的证书描述 (留空则使用域名): ")
    enable_webhook = input("是否启用Webhook服务? (y/n) [y]: ").lower() != 'n'
    
    if enable_webhook:
        config.webhook.enabled = True
        config.webhook.port = int(input("请输入Webhook监听端口 [8000]: ") or "8000")
        
        use_auth = input("是否启用Webhook认证? (y/n) [y]: ").lower() != 'n'
        if use_auth:
            config.webhook.auth_token = generate_auth_token()
            logger.info(f"已生成认证令牌: {config.webhook.auth_token}")
            
    save_config(config, CONFIG_PATH)
    logger.info(f"配置已保存到: {CONFIG_PATH}")


def deploy_command(args):
    """执行证书部署命令"""
    domain = args.domain
    
    if not domain:
        logger.error("必须指定域名")
        return False
    
    result = cert_manager.deploy_certificate(domain)
    
    if result:
        logger.info(f"证书部署成功: {domain}")
    else:
        logger.error(f"证书部署失败: {domain}")
    
    return result


def list_command(args):
    """列出所有本地证书"""
    certs = cert_manager.get_all_certificates()
    
    if not certs:
        logger.info("未找到任何本地证书")
        return True
    
    logger.info(f"找到 {len(certs)} 个本地证书:")
    for domain, cert_info in certs.items():
        last_updated = cert_info.last_updated.strftime("%Y-%m-%d %H:%M:%S") if cert_info.last_updated else "未知"
        expiry = cert_info.expiry_date.strftime("%Y-%m-%d %H:%M:%S") if cert_info.expiry_date else "未知"
        
        print(f"域名: {domain}")
        print(f"  子域名: {', '.join(cert_info.domains)}")
        print(f"  更新时间: {last_updated}")
        print(f"  过期时间: {expiry}")
        print("---")
    
    return True


def list_dsm_certificates(args):
    """列出DSM系统上的所有证书"""
    logger.info("获取DSM系统上的证书...")
    
    show_raw_data = os.environ.get("DSMCA_SHOW_RAW_DATA", "0") == "1"
    
    try:
        if config.synology.scheme == "https" and not config.synology.disable_cert_verify:
            logger.warning("正在使用HTTPS但未禁用证书验证，如遇SSL错误请在配置文件中设置disable_cert_verify=true")
        if not config.synology.username or not config.synology.password:
            logger.error("未配置DSM用户名或密码，请在配置文件中设置")
            return False
            
        with SynologyClient(config.synology) as client:
            if not client.sid:
                logger.error("登录DSM失败，请检查用户名和密码是否正确")
                return False
                
            dsm_certs = client.get_certificates()
            
            if not dsm_certs:
                logger.info("DSM系统上未找到任何证书，可能是权限不足或没有可用证书")
                logger.info("请确保使用的账户拥有管理员权限")
                return True
            
            logger.info(f"在DSM系统上找到 {len(dsm_certs)} 个证书:")
            
            for cert in dsm_certs:
                try:
                    desc = cert.get("desc", "")
                    common_name = cert.get("subject", {}).get("common_name", "")
                    cert_name = desc if desc else common_name if common_name else "未知"
                    
                    is_default = "是" if cert.get("is_default", False) else "否"
                    user_deletable = "是" if cert.get("user_deletable", False) else "否"
                    
                    # 证书有效期
                    valid_from = cert.get("valid_from", "未知")
                    valid_till = cert.get("valid_till", "未知")
                    
                    # 签发者信息
                    issuer = cert.get("issuer", {})
                    issuer_cn = issuer.get("common_name", "未知")
                    issuer_org = issuer.get("organization", "")
                    is_lets_encrypt = "Let's Encrypt" in str(issuer)
                    
                    # 证书域名
                    subject = cert.get("subject", {})
                    domains = subject.get("sub_alt_name", [])
                    domains_str = ", ".join(domains) if domains else common_name
                    
                    # 证书使用的服务
                    services = cert.get("services", [])
                    service_names = []
                    for service in services:
                        if isinstance(service, dict) and "display_name" in service:
                            service_names.append(service["display_name"])
                    services_str = ", ".join(service_names) if service_names else "无"
                    
                    print(f"证书: {cert_name}")
                    print(f"  域名: {domains_str}")
                    print(f"  签发者: {issuer_cn} {issuer_org}")
                    print(f"  有效期: {valid_from} - {valid_till}")
                    print(f"  默认证书: {is_default}")
                    print(f"  可删除: {user_deletable}")
                    
                    if service_names:
                        print(f"  应用于服务: {services_str}")
                    
                    if is_lets_encrypt:
                        print(f"  【Let's Encrypt 证书】")
                    
                    # 原始证书数据
                    if show_raw_data:
                        print("  原始数据:")
                        for key, value in cert.items():
                            print(f"    {key}: {value}")
                    
                    print("---")
                except Exception as e:
                    logger.error(f"处理证书数据时出错: {str(e)}")
                    logger.debug(f"证书数据: {cert}")
            
            return True
    except requests.exceptions.SSLError as e:
        logger.error(f"SSL证书验证失败: {str(e)}")
        logger.error("请在配置文件中设置 synology.disable_cert_verify = true 来禁用证书验证")
        return False
    except requests.exceptions.ConnectionError as e:
        logger.error(f"连接DSM失败: {str(e)}")
        logger.error("请检查DSM地址和端口是否正确")
        return False
    except Exception as e:
        logger.error(f"获取DSM证书失败: {str(e)}")
        logger.debug(f"错误详情: {e}", exc_info=True)
        return False


def main():
    """主程序入口"""
    parser = argparse.ArgumentParser(description="DSM证书自动化")
    subparsers = parser.add_subparsers(dest="command", help="子命令")
    list_parser = subparsers.add_parser("list", help="列出所有本地证书")
    list_dsm_parser = subparsers.add_parser("list-dsm", help="列出DSM系统上的所有证书")
    
    args = parser.parse_args()
    
    # 检查配置
    if not os.path.exists(CONFIG_PATH):
        initialize_config()
    
    if not args.command:
        if AUTO_ENABLE_WEBHOOK:
            if not config.webhook.enabled:
                logger.info("自动启用Webhook服务")
                config.webhook.enabled = True
                config.webhook.port = int(os.environ.get("DSMCA_WEBHOOK_PORT", "8000"))
                if not config.webhook.auth_token:
                    config.webhook.auth_token = generate_auth_token()
                save_config(config, CONFIG_PATH)
            
            start_webhook_server()
        else:
            parser.print_help()
    elif args.command == "list":
        list_command(args)
    elif args.command == "list-dsm":
        list_dsm_certificates(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main() 