# DSMCA

一个基于接收 Webhook 用于自动化部署/更新群晖DSM SSL证书的工具。

## 安装

```bash
# 克隆仓库
git clone https://github.com/jkfujr/dsmca
cd dsmca

# 安装依赖
pip install -r requirements.txt
```

## 使用方法

### 快速开始

直接运行即可启动Webhook服务:

```bash
python main.py
```

首次运行时会自动初始化配置文件。

### 查看证书

```bash
# 列出本地所有证书
python main.py list
# 列出DSM上所有证书
python main.py list-dsm
```

### 配置说明

`config.yaml`的配置项:

#### Synology 配置
- `scheme`: 连接协议, 可选`http`或`https`
- `hostname`: DSM主机地址
- `port`: DSM端口
- `username`: 管理员用户名
- `password`: 管理员密码
- `disable_cert_verify`: 是否禁用SSL证书验证

#### Webhook 配置
- `enabled`: 是否启用webhook
- `port`: webhook监听端口
- `path`: webhook路径
- `auth_token`: 认证令牌

### 环境变量

- `DSMCA_CONFIG`: 配置文件路径, 默认为`config.yaml`
- `DSMCA_CERT_DIR`: 证书存储目录, 默认为`certs`
- `DSMCA_AUTO_ENABLE_WEBHOOK`: 是否自动启用Webhook, 默认为`1`
- `DSMCA_WEBHOOK_PORT`: Webhook监听端口, 默认为`8000`
- `DSMCA_SHOW_RAW_DATA`: 设置为`1`时, 列出DSM证书时显示原始数据

## Webhook请求格式

webhook接收, 请求体格式:

```json
{
  "name": "example.com",  // 证书域名
  "cert": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",  // 证书内容
  "privkey": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"  // 私钥内容
}
```

## 许可证

MIT 