# 🍯 Portsentry Defense & Apple-Style WebUI

> **轻量、极速、无侵入的 Linux 蜜罐诱捕与 Linux 内核级主动防御系统**  
> 专为 Linux 云服务器打造，内置 **Abit 官方苹果原生设计语言 (Apple UI)** 交互控制台，具备毫秒级端口扫描感知、iptables 硬件级丢包阻断、内核黑洞路由、全球威胁情报画像与安全白名单防误封机制。

---

## ⚡ 一行命令极速全自动部署

在任意 Linux 服务器（Ubuntu / Debian / CentOS / RHEL / Alibaba Cloud Linux / Rocky Linux）终端中，直接复制并执行下方**一行命令**即可完成全自动部署：

```bash
curl -fsSL https://raw.githubusercontent.com/Level6me/portsentry-ui/main/install.sh | bash
```

> **或者使用 wget 一行命令：**
> ```bash
> wget -qO- https://raw.githubusercontent.com/Level6me/portsentry-ui/main/install.sh | bash
> ```

部署完成后，即可在浏览器中打开：  
👉 **`http://<您的服务器IP>:9099`**

---

## ✨ 核心特性

- 🚀 **内核级毫秒阻断**：基于 `iptables INPUT` 首行丢弃 + `ip route blackhole` 路由黑洞双重丢弃机制，0 CPU 额外消耗。
- 🍯 **智能蜜罐与业务避让**：默认监听 10+ 典型黑客探针端口（FTP/SSH/RDP/SMB/MSSQL/MySQL/Redis/VNC/ES/MongoDB等），自动避开服务器真实业务端口，互不干扰。
- 🛡️ **智能白名单防误封**：部署时自动捕获当前 SSH 运维来源 IP、网卡内网 IP 与本机回环，杜绝管理员被误封。
- 🍏 **Abit 苹果原生标准 WebUI**：
  - 浮动毛玻璃 iOS Dock 底栏与分段控制器
  - iOS 胶囊 Toast 全局通知系统（告别原生 alert）
  - 暗黑 (Dark) / 明亮 (Light) 双主题无缝切换与 Chart.js 毫秒级重绘
  - 手机移动端与桌面多端 100% 弹性流体自适应
- 🌍 **全球 ASN / 威胁画像**：自动异步查询攻击者国家、城市、ISP 并生成地域攻击热力排行。
- 📥 **审计报表一键导出**：支持一键导出完整的 CSV 安全事件审计清单。

---

## ⚙️ 运维管理常用命令

```bash
# 查看防御服务状态
systemctl status portsentry-ui.service

# 查看实时拦截日志流
journalctl -u portsentry-ui.service -f

# 重启防御系统
systemctl restart portsentry-ui.service

# 停止防御系统
systemctl stop portsentry-ui.service
```

---

## 📁 目录结构

```text
/opt/portsentry-ui/
├── sentry_daemon.py      # 蜜罐监听引擎、内核阻断核心、SQLite 事件存储与 ASN 识别
├── web_server.py         # Apple-Style 响应式控制台服务端 (纯 Python 原生无重型依赖)
├── config.json           # 诱饵策略、白名单与防火墙动作配置文件
└── data.db               # SQLite 本地轻量化事件审计与黑白名单库
```

---

## 🛡️ 常见问题 (FAQ)

1. **为什么外部扫描无法触发拦截？**
   - 请确保在阿里云 / 腾讯云 / 华为云控制台的 **「安全组」** 中放行了诱饵端口（例如 `21, 135, 445, 1433, 3389, 5900, 6379, 8888, 9200, 27017` 等）。
2. **误封了管理员 IP 如何解除？**
   - 方式一：在 Web 控制台「内核黑名单池」或「拦截日志」中点击 **「一键解封」**；
   - 方式二：在服务器终端执行 `iptables -D INPUT -s <IP> -j DROP` 和 `ip route del blackhole <IP>/32`。
