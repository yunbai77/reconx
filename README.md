# reconx

一个面向**授权**红队/渗透前期信息收集的隐蔽侦察工具。把子域名枚举、DNS 解析、
端口扫描、HTTP 存活探测串成一条"低速+随机化"的流水线，提供命令行和 Textual TUI
两种使用方式。

> ⚠️ **仅限授权使用。** 请只对你拥有或已获得书面授权的系统使用 reconx。
> 作者不对任何滥用行为负责。

## 功能

- **被动优先的子域名枚举**：基于证书透明（CT）日志，crt.sh 为主、Cert Spotter 兜底。
- **DNS 解析**：记录类型分组（A/AAAA/CNAME/NS/MX/TXT），并发解析。
- **低速端口扫描**：共享令牌桶限速、端口顺序随机化、随机抖动延迟。
- **HTTP 存活探测**：状态码、Server 头、网页标题、跳转；走 `StealthSession`，
  带限速、随机延迟、UA 轮换、代理轮换。
- **Textual TUI**：交互式实时扫描界面。
- **导出 JSON / CSV**。

## 安装

```bash
git clone https://github.com/<你的用户名>/reconx.git
cd reconx
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
使用
命令行：
python -m reconx.main scan example.com              # 完整流程
python -m reconx.main scan example.com --no-ports   # 跳过端口扫描
python -m reconx.main scan example.com --no-http    # 跳过 HTTP 探测
python -m reconx.main env                           # 打印解析后的配置
交互界面：
python -m reconx.main tui
TUI 流程：Scan（枚举 + DNS + HTTP）→ Ports → Export（Ctrl+E）。
结果写入 results/ 目录。
配置
编辑 config.yaml：
- network：timeout、retries、rate_limit、delay_min/max、concurrency、
代理和 User-Agent 轮换池。
- portscan：ports（common 或 1-1024 这类范围）、scan_type、randomize。
- http：follow_redirects、verify_tls、max_body_size。
- general：output_dir、log_level、log_file。
项目结构
reconx/
  main.py            命令行入口
  config.py          分层 dataclass 配置 + load_config()
  core/
    logger.py        rich 控制台 + 文件日志
    ratelimit.py     令牌桶限速器
    session.py       StealthSession（httpx）
    export.py        JSON / CSV 导出
  modules/
    subdomain.py     crt.sh + Cert Spotter
    dns.py           dnspython 解析
    portscan.py      多线程 connect 扫描
    httpprobe.py     HTTP 存活探测
  ui/
    tui.py           Textual 界面
config.yaml
requirements.txt
免责声明
本项目仅用于授权范围内的安全测试与学习。使用者须自行确保目标授权合规，
并遵守当地法律法规。作者不承担任何后果。
许可证
MIT（如需以 MIT 发布，请自行添加 LICENSE 文件）。
