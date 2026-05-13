## 项目说明

### 项目名称
WebGuardian 网站安全检测工具

---

## 一、项目简介

`WebGuardian` 是一个基于 Python 开发的网站基础安全检测工具。

项目通过输入目标网站地址，对网站进行基础安全检查，包括 HTTPS、SSL 证书、HTTP 安全响应头、TRACE 方法、敏感路径、常见端口和信息泄露等检测项，并根据检测结果生成安全评分和安全等级。

该项目采用分层架构设计，将检测逻辑、页面展示和程序入口进行拆分，便于后续维护和功能扩展。

---

## 二、项目功能

当前版本主要包含以下功能：

### 1. HTTPS 检测

判断目标网站是否使用 HTTPS 协议。

检测内容：

- 是否以 `https://` 开头
- HTTPS 使用情况是否符合基础安全要求

---

### 2. SSL 证书检测

检测目标网站的 SSL/TLS 证书状态。

检测内容：

- SSL 证书是否有效
- 证书剩余有效天数
- 证书是否即将过期

---

### 3. HTTP 安全响应头检测

检测网站是否配置常见安全响应头。

检测项包括：

- `Content-Security-Policy`
- `Strict-Transport-Security`
- `X-Frame-Options`
- `X-Content-Type-Options`
- `Referrer-Policy`
- `Permissions-Policy`

这些响应头可以帮助网站降低 XSS、点击劫持、MIME 类型嗅探等常见安全风险。

---

### 4. TRACE 方法检测

检测目标网站是否启用了 HTTP TRACE 方法。

如果 TRACE 方法开启，可能会增加跨站追踪攻击风险，因此通常建议关闭。

---

### 5. 敏感路径检测

检测网站是否存在常见敏感路径。

默认检测路径包括：

- `/admin`
- `/backup`
- `/test`

如果这些路径可以直接访问，可能存在后台入口暴露、测试环境暴露或备份文件泄露风险。

---

### 6. 常见端口检测

检测目标主机常见端口开放情况。

当前检测端口：

- `80`
- `443`

用于判断网站 HTTP 和 HTTPS 服务的开放情况。

---

### 7. 信息泄露检测

检测响应头中是否包含可能泄露服务器或技术栈的信息。

检测字段：

- `Server`
- `X-Powered-By`

如果这些字段存在，可能暴露服务器类型、框架信息或运行环境信息。

---

### 8. 安全评分与等级

系统会根据各检测项结果生成安全评分，满分为 `100` 分。

安全等级划分：

| 分数范围 | 安全等级 |
|---|---|
| 85 - 100 | A级 |
| 70 - 84 | B级 |
| 0 - 69 | C级 |

---

## 三、项目架构

项目采用三层结构：

```text
wid/
│
├── main.py
│
├── scanner/
│   ├── __init__.py
│   └── scanner.py
│
└── ui/
    ├── __init__.py
    └── app.py
```

---

## 四、目录说明

### 1. `main.py`

项目启动入口。

职责：

- 引入 UI 层入口函数
- 启动 Streamlit 页面

示例：

```python
from ui.app import run_app


if __name__ == "__main__":
    run_app()
```

---

### 2. `scanner/scanner.py`

核心检测层。

职责：

- HTTPS 检测
- SSL 证书检测
- HTTP 安全头检测
- TRACE 方法检测
- 敏感路径检测
- 端口检测
- 信息泄露检测
- 评分计算
- 返回统一格式的检测结果

设计原则：

- 不写 `print`
- 不写 `input`
- 不包含 UI 逻辑
- 只负责检测和返回数据

---

### 3. `ui/app.py`

页面展示层。

职责：

- 使用 Streamlit 构建页面
- 接收用户输入的网站地址
- 调用 `scanner.scanner.scan`
- 展示检测结果
- 展示评分、等级、风险提示和原始 JSON 数据

设计原则：

- 只负责交互和展示
- 不实现具体检测逻辑
- 不直接处理底层网络检测细节

---

### 4. `__init__.py`

包初始化文件。

用于让 Python 将 `scanner` 和 `ui` 识别为模块包。

通常可以为空。

---

## 五、技术栈

### 后端检测

- Python
- requests
- socket
- ssl
- datetime
- urllib.parse

### 前端展示

- Streamlit

---

## 六、安装依赖

建议使用虚拟环境。

### 1. 创建虚拟环境

```bash
python -m venv venv
```

### 2. 激活虚拟环境

Windows：

```bash
venv\Scripts\activate
```

macOS / Linux：

```bash
source venv/bin/activate
```

### 3. 安装依赖

```bash
pip install streamlit requests
```

也可以创建 `requirements.txt`：

```txt
streamlit
requests
```

然后执行：

```bash
pip install -r requirements.txt
```

---

## 七、运行项目

在项目根目录执行：

```bash
streamlit run main.py
```

启动后，终端会显示本地访问地址，例如：

```text
Local URL: http://localhost:8501
```

打开浏览器访问该地址即可使用。

---

## 八、使用方式

1. 启动项目：

```bash
streamlit run main.py
```

2. 在页面输入网站地址，例如：

```text
https://example.com
```

3. 点击：

```text
开始检测
```

4. 查看检测结果：

- 安全评分
- 安全等级
- HTTPS 状态
- SSL 证书状态
- 安全响应头情况
- TRACE 方法状态
- 敏感路径检测结果
- 开放端口
- 信息泄露情况

---

## 九、返回结果示例

`scanner.scan(url)` 会返回一个字典，示例结构如下：

```python
{
    "ok": True,
    "url": "https://example.com",
    "host": "example.com",
    "score": 85,
    "level": "A级",
    "https": True,
    "ssl_valid": True,
    "ssl_days_left": 120,
    "security_header_score": 20,
    "missing_security_headers": [
        "Permissions-Policy"
    ],
    "trace_enabled": False,
    "sensitive_paths": [],
    "open_ports": [80, 443],
    "info_leak": {
        "server_header_exists": True,
        "x_powered_by_exists": False
    },
    "errors": []
}
```

---

## 十、评分规则说明

| 检测项 | 加分 |
|---|---:|
| 使用 HTTPS | 10 |
| SSL 证书有效 | 10 |
| SSL 证书剩余时间大于 7 天 | 10 |
| 每个安全响应头存在 | 5 |
| 不存在 Server 响应头 | 10 |
| 不存在 X-Powered-By 响应头 | 10 |
| TRACE 方法未启用 | 10 |
| 未发现敏感路径 | 10 |
| 443 端口开放 | 5 |
| 80 端口开放 | 5 |

总分最高限制为 `100` 分。

---

## 十一、设计特点

### 1. 分层清晰

项目分为：

- 入口层
- UI 层
- 扫描层

各层职责明确，方便维护。

---

### 2. 易于扩展

后续可以在 `scanner/scanner.py` 中继续增加检测函数，例如：

- SQL 注入基础检测
- XSS 反射检测
- 目录遍历检测
- robots.txt 检测
- sitemap.xml 检测
- Cookie 安全属性检测
- DNS 安全检测

---

### 3. 页面可替换

当前 UI 使用 Streamlit。

如果后续需要改为：

- Flask
- FastAPI
- Vue + API
- 命令行 CLI

只需要替换 UI 层，不需要重写核心扫描逻辑。

---

### 4. 输出统一

核心扫描函数 `scan(url)` 统一返回 `dict`，方便：

- UI 页面展示
- JSON 序列化
- 日志记录
- API 接口返回
- 测试用例断言

---

## 十二、注意事项

1. 本工具仅用于基础安全检测，不等同于完整漏洞扫描器。
2. 请只检测自己拥有或获得授权的网站。
3. 检测结果受网络环境、目标站点配置、防火墙策略影响。
4. 敏感路径检测只包含少量演示路径，可根据实际需求扩展。
5. 端口检测目前只检测 `80` 和 `443`。
6. TRACE 方法检测可能被部分 WAF 或代理拦截，结果仅供参考。
7. SSL 检测默认连接目标主机的 `443` 端口。

---

