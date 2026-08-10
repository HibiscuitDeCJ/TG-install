# TG-install

Trojan-Go 安全部署脚本，适用于 Ubuntu 24.04 amd64。

```bash
curl -fsSL -o U24amd.sh https://raw.githubusercontent.com/HibiscuitDeCJ/TG-install/main/U24amd.sh && chmod +x U24amd.sh && sudo bash U24amd.sh
```

## 命令

| 命令 | 作用 |
|---|---|
| `./U24amd.sh install --mode tcp\|ws\|fallback --domain DOMAIN --email EMAIL` | 全新安装 |
| `./U24amd.sh test` | 安装前环境检测 |
| `./U24amd.sh audit` | 安装后安全审计 |
| `./U24amd.sh status` | 查看运行状态 |

## 模式

| 模式 | 说明 |
|---|---|
| `tcp` | Trojan-Go TCP + TLS，无 Nginx |
| `ws` | Trojan-Go WebSocket + TLS，无 Nginx |
| `fallback` | Trojan-Go TCP + TLS + Nginx 伪装回退 |

## 示例

```bash
# 安装前检测
sudo bash U24amd.sh test

# 安装（fallback 模式含 Nginx 伪装）
sudo bash U24amd.sh install --mode fallback --domain vps.example.com --email admin@example.com

# 查看状态
bash U24amd.sh status

# 安全审计
sudo bash U24amd.sh audit
```

## 安全原则

- 禁止 `curl | bash`（先下载到磁盘再执行）
- 锁定 Trojan-Go 版本，SHA256 强制校验
- 非 root 用户运行，systemd 沙盒加固
- Cloudflare DNS-01 自动签发 Let's Encrypt 证书
- UFW 不 reset，不覆盖已有 Nginx 配置
- 密码和 Token 不写入日志、不出现在 `ps` 中
