# Mail

## 一键安装

服务器上直接执行：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/SIJULY/mail-all/main/install.sh)
```

如果你已经先把仓库拉到本地，也可以执行：

```bash
bash install.sh
```

## 启动方式

入口文件：`app.py`

```bash
python3 app.py
```

也可先验证 Flask 应用可导入：

```bash
python3 -c "from app import app; print(app)"
```

## 主要环境变量

可选，未设置时使用源码默认值：

- `MAIL_SECRET_KEY`
- `MAIL_DB_FILE`
- `MAIL_LAST_CLEANUP_FILE`
- `MAIL_ADMIN_USERNAME`
- `MAIL_ADMIN_PASSWORD_HASH`
- `MAIL_SYSTEM_TITLE`
- `MAIL_SPECIAL_VIEW_TOKEN`
- `MAIL_SERVER_PUBLIC_IP`
- `MAIL_MOEMAIL_API_KEY`
- `MAIL_MOEMAIL_API_KEY_HEADER`
- `MAIL_MOEMAIL_DEFAULT_EXPIRY`
- `MAIL_MOEMAIL_DEFAULT_ROLE`
- `MAIL_SMTP_SERVER`
- `MAIL_SMTP_PORT`
- `MAIL_SMTP_USERNAME`
- `MAIL_SMTP_PASSWORD`
- `MAIL_DEFAULT_SENDER`
- `MAIL_IMAP_PORT`（默认 143，IMAP 明文 + STARTTLS）
- `MAIL_IMAPS_PORT`（默认 993，IMAP 隐式 TLS，需证书）
- `MAIL_SUBMISSION_PORT`（默认 587，SMTP 提交口 + STARTTLS）
- `MAIL_SUBMISSION_TLS_PORT`（默认 465，SMTP 提交隐式 TLS，需证书）
- `MAIL_IMAP_CERT` / `MAIL_IMAP_KEY`（未设置时沿用 `MAIL_SMTP_CERT` / `MAIL_SMTP_KEY`）

## 重构后项目结构

说明：
- `app.py` 仍是主入口，直接运行时会启动 Web、SMTP 收信、IMAP 与 SMTP 提交口
- `app/` 是拆分后的主应用目录，负责 Flask 应用组装、路由、服务、仓储与 UI
- 本次重构以“功能不变、UI 不变、路由不变、SMTP 外部行为不变”为原则

```text README.md
mail/
├── app.py                    # 项目主入口，直接运行时启动 Web 与 SMTP
├── install.sh                # 一键安装部署脚本
├── requirements.txt          # Python 运行依赖清单
├── README.md                 # 项目说明文档
└── app/
    ├── __init__.py           # Flask 应用创建与总注册入口
    ├── config.py             # 全局配置与环境变量读取
    ├── constants.py          # 常量定义
    ├── repositories/
    │   ├── __init__.py       # 仓储包初始化
    │   ├── auth_repo.py      # 用户认证相关数据库访问
    │   ├── db.py             # SQLite 连接与数据库初始化
    │   ├── mail_repo.py      # 邮件、域名、邮箱等数据访问
    │   └── settings_repo.py  # 系统设置项数据访问
    ├── routes/
    │   ├── __init__.py       # 路由统一注册入口
    │   ├── admin_routes.py   # 后台管理相关路由
    │   ├── api_routes.py     # 聚合 API 路由
    │   ├── mail_routes.py    # 邮件查看、token 访问等路由
    │   ├── moemail_routes.py # MoeMail 相关接口路由
    │   └── ui_routes.py      # 登录、首页、撰写等 UI 路由
    ├── services/
    │   ├── __init__.py       # 服务层包初始化
    │   ├── auth_service.py   # 登录、退出、鉴权视图逻辑
    │   ├── cleanup_service.py# 邮件清理相关服务
    │   ├── inbound_service.py# 入站 SMTP 处理服务
    │   ├── imap_service.py   # IMAP 服务（143/993，供邮件客户端读信）
    │   ├── submission_service.py # SMTP 提交服务（587/465，供邮件客户端发信）
    │   ├── message_service.py# 邮件解析、序列化、入库处理
    │   ├── settings_service.py # 设置与域名选择逻辑
    │   ├── smtp_service.py   # SMTP 配置读取与发信逻辑
    │   └── view_service.py   # 邮件列表/详情查询与页面上下文构建
    ├── ui/
    │   ├── __init__.py       # UI 包初始化
    │   ├── html_pages.py     # HTML 模板字符串
    │   └── page_builders.py  # 页面渲染与页面构造辅助
    └── utils/
        ├── __init__.py       # 工具包初始化
        ├── decorators.py     # 登录、管理员、API 鉴权装饰器
        ├── mail_utils.py     # 邮件文本、地址、域名辅助函数
        ├── response.py       # 响应参数辅助函数
        ├── text_utils.py     # 文本处理辅助函数
        └── time_utils.py     # 时间解析与转换辅助函数
```

## iPhone 邮件 App 接入（IMAP + SMTP 提交）

服务器上跑四个服务：Web、25 端口收信、IMAP（143/993）、SMTP 提交（587/465）。
iPhone 上“设置 → 邮件 → 账户 → 添加账户 → 其他 → 添加邮件账户”，按下面填：

- 收件服务器：主机名填邮件服务器域名或 IP，用户名填邮局登录邮箱，
  密码填该邮箱的登录密码，端口 **993**（SSL 打开）；没有有效证书时改用
  端口 **143** 并把 SSL 关掉（明文，不推荐长期用）。
- 发件服务器：主机名同上，用户名和密码同上，端口 **465**（SSL 打开）；
  没有有效证书时改用端口 **587** 并把 SSL 关掉。
- 文件夹对应：收件箱 = INBOX，已发送 = Sent，草稿 = Drafts，回收站 = Trash；
  iPhone 上标已读/星标/删信会同步回网页版。
- 注意三点：① 登录账号必须是网页版的登录账号（管理员或管理用户里的邮箱
  密码），随机生成的 MoeMail 地址没有密码，登不上 IMAP，要先在网页管理用户
  里给它设密码；② 发件的 MAIL FROM 必须等于登录邮箱，管理员只能用系统
  设置里的默认发件人，否则提交口会拒收（防开放中继）；③ iPhone 对通用
  IMAP 是定时拉取，不是 iCloud 那种即时推送，新邮件按你设的获取频率到达。

## 说明

- Web 入口与路由组装位于 `app/`
- SMTP 接收启动入口保留在 `app.py`
- IMAP 与 SMTP 提交口的启动入口分别是 `app/services/imap_service.py`、
  `app/services/submission_service.py`，`app.py` 直接运行时也会一并启动
- 推荐使用上方一键安装脚本部署

## 轮询邮箱生成 API

管理员登录后进入“管理域名”，在“邮箱生成 API”区域生成密钥。程序携带该密钥请求查信地址模板时，系统会按 ID 顺序轮询所有已启用域名，并创建一个随机邮箱地址。

```bash
curl -H "X-API-Key: 管理页面生成的密钥" 'http://服务器IP:2099/Mail?token=2088&mail={mail}'
```

也支持 `Authorization: Bearer 密钥`，或在地址末尾追加 `&api_key=密钥`。生成响应中的 `email`（同时兼容字段 `mail`）可替换 `{mail}`；不携带 API 密钥并传入真实邮箱地址时，仍按原规则查信：

```text
http://服务器IP:2099/Mail?token=2088&mail={mail}
```
