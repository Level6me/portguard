# 🛡️ PortGuard (端口卫士)

> **轻量级 Linux 智能端口诱捕、全端口扫描感知与内核级主动防御系统**  
> 专为 Linux 云服务器打造的低资源消耗边界防御工具。支持多端口与大范围诱饵监听，一旦捕获非白名单主机的未授权端口扫描或恶意嗅探，直接联动 Linux 内核下发 `iptables` / `ip route blackhole` 进行毫秒级硬丢包阻断，并提供轻量纯原生的响应式 Web 控制台与威胁溯源大屏。

---

## ⚡ 一行命令极速全自动部署

在任意 Linux 服务器（Ubuntu / Debian / CentOS / RHEL / Alibaba Cloud Linux / Rocky Linux）终端中，直接复制并执行下方**一行命令**即可完成全自动部署：

```bash
curl -fsSL https://raw.githubusercontent.com/Level6me/portguard/main/install.sh | bash
```

> **或者使用 wget 一行命令：**
> ```bash
> wget -qO- https://raw.githubusercontent.com/Level6me/portguard/main/install.sh | bash
> ```

部署完成后，即可在浏览器中打开：  
👉 **`http://<您的服务器IP>:9099`**

---

## ✨ 核心特性

- 🚀 **内核级毫秒阻断**：基于 `iptables INPUT` 首行丢弃 + `ip route blackhole` 路由黑洞双重丢弃机制，拦截后攻击流量直接在内核层丢弃，0 额外 CPU 消耗。
- ⚡ **自研 Raw Socket 嗅探引擎**：毫秒级解析 TCP 握手数据包，零外部重型依赖，资源占用极低（内存通常小于 30MB）。
- 🍯 **多层级端口诱捕**：支持单独设置典型高危端口（FTP/SSH/RDP/SMB/MSSQL/Redis/VNC/ES/MongoDB等），亦支持配置 `1-60000` 大范围诱捕探针。
- 🏢 **正常业务端口绝对优先级**：四级防御架构确保用户业务端口（如 Web 80/443、自定义隧道端口等）100% 绝对放行，绝不误阻断。
- 🛡️ **智能运维白名单防误封**：部署时自动捕获当前 SSH 运维来源 IP、网卡内网 IP 与本机回环，杜绝管理员误操作被拉黑。
- 🌐 **轻量现代化 Web 控制台**：
  - 纯原生 Python 服务端驱动，零第三方重量级框架依赖
  - 弹性流体响应式布局，完美适配手机移动端与桌面大屏
  - 暗黑 (Dark) / 明亮 (Light) 双主题无缝切换与 Chart.js 图表实时重绘
- 🌍 **全球威胁画像与 ASN 识别**：自动异步查询攻击者国家、城市、ISP 运营商，生成地域攻击热力排行。
- 🙈 **审计隐藏与多维过滤**：支持在 IP 详情卡片一键全局隐藏指定 IP 的所有日志与统计，便于过滤内部测试流量。
- 📥 **审计报表一键导出**：支持一键导出完整的 CSV / JSON 安全事件清单与访问审计日志。

---

## ⚙️ 运维管理、一键平滑更新与卸载

### 常用运维命令
```bash
# 查看防御服务状态
systemctl status portguard.service

# 查看实时拦截日志流
journalctl -u portguard.service -f

# 重启防御系统
systemctl restart portguard.service

# 停止防御系统
systemctl stop portguard.service
```

### 🔄 一键平滑热更新命令
在终端执行以下命令，会自动拉取最新版本程序并平滑热重载，**100% 完整保留您现有的策略配置 (`config.json`) 和黑名单/事件数据库 (`data.db`)**：

```bash
curl -fsSL https://raw.githubusercontent.com/Level6me/portguard/main/update.sh | bash
```

> **或者使用部署脚本的更新参数：**
> ```bash
> curl -fsSL https://raw.githubusercontent.com/Level6me/portguard/main/install.sh | bash -s -- update
> ```

### 🗑️ 一键完全卸载命令
在终端执行以下命令即可将 PortGuard 防御服务、后台进程、systemd 服务单元及安装目录完全彻底删除：

```bash
curl -fsSL https://raw.githubusercontent.com/Level6me/portguard/main/uninstall.sh | bash
```

> **或者使用已安装目录自带的卸载脚本：**
> ```bash
> sudo bash /opt/portguard/uninstall.sh
> ```

---

## 📁 目录结构

```text
/opt/portguard/
├── sentry_daemon.py      # 蜜罐监听引擎、内核阻断核心、SQLite 事件存储与 ASN 识别
├── web_server.py         # 响应式控制台服务端 (纯 Python 原生无重型依赖)
├── config.json           # 诱饵策略、白名单与防火墙动作配置文件
└── data.db               # SQLite 本地轻量化事件审计与黑白名单库
```

---

## 🛡️ 常见问题 (FAQ)

1. **为什么外部扫描无法触发拦截？**
   - 请确保在云服务商控制台的 **「安全组」** 中放行了诱饵端口（例如 `21, 135, 445, 1433, 3389, 5900, 6379, 8888, 9200, 27017` 等）。
2. **如何确保自己的业务端口不被误封？**
   - 在 Web 控制台「策略中心」-「正常业务」中添加您的业务端口（如 `80`, `443`, `4212` 等），系统将绝对放行外部合法访问。
2. **误封了管理员 IP 如何解除？**
   - 方式一：在 Web 控制台「内核黑名单池」或「拦截日志」中点击 **「一键解封」**；
   - 方式二：在服务器终端执行 `iptables -D INPUT -s <IP> -j DROP` 和 `ip route del blackhole <IP>/32`。
