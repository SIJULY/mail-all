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

## 重构后项目结构

说明：
- `app.py` 仍是主入口，直接运行时会启动 Web 与 SMTP
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

## 说明

- Web 入口与路由组装位于 `app/`
- SMTP 接收启动入口保留在 `app.py`
- 推荐使用上方一键安装脚本部署
