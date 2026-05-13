# scanner/scanner.py
import datetime
import socket
import ssl
from urllib.parse import urlparse

import requests


def check_https(url: str) -> bool:
    return url.startswith("https://")


def check_ssl_details(hostname: str):
    """返回: (ssl_valid, days_left)"""
    if not hostname:
        return False, 0
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                expire_date = datetime.datetime.strptime(
                    cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
                )
                days_left = (expire_date - datetime.datetime.utcnow()).days
                return True, days_left
    except Exception:
        return False, 0


def check_security_headers(response: requests.Response):
    headers_to_check = [
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy",
    ]

    score = 0
    missing = []
    for header in headers_to_check:
        if header in response.headers:
            score += 5
        else:
            missing.append(header)

    return score, missing


def check_trace_method(url: str) -> bool:
    """True=TRACE可用(风险), False=TRACE不可用(更安全)"""
    try:
        r = requests.request("TRACE", url, timeout=5)
        return r.status_code < 400
    except Exception:
        return False


def check_sensitive_paths(base_url: str):
    paths = ["/admin", "/backup", "/test"]
    found = []
    base = base_url.rstrip("/")
    for path in paths:
        try:
            r = requests.get(base + path, timeout=3)
            if r.status_code == 200:
                found.append(path)
        except Exception:
            pass
    return found


def check_ports(host: str):
    open_ports = []
    if not host:
        return open_ports

    for port in [80, 443]:
        try:
            with socket.create_connection((host, port), timeout=3):
                open_ports.append(port)
        except Exception:
            pass
    return open_ports


def calc_level(score: int) -> str:
    if score >= 85:
        return "A级"
    elif score >= 70:
        return "B级"
    return "C级"

def normalize_url(url: str):
    """
    规范化URL。
    如果用户未输入协议：
    1. 先尝试 https
    2. 失败再尝试 http
    """
    url = url.strip()

    if url.startswith(("http://", "https://")):
        return url

    https_url = "https://" + url
    http_url = "http://" + url

    try:
        requests.get(https_url, timeout=3)
        return https_url
    except Exception:
        return http_url


def scan(url: str) -> dict:
    url = normalize_url(url)
    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        return {"ok": False, "error": "URL格式不正确"}

    result = {
        "ok": True,
        "url": url,
        "host": host,
        "score": 0,
        "level": "",
        "https": False,
        "ssl_valid": False,
        "ssl_days_left": 0,
        "security_header_score": 0,
        "missing_security_headers": [],
        "trace_enabled": False,
        "sensitive_paths": [],
        "open_ports": [],
        "info_leak": {
            "server_header_exists": None,
            "x_powered_by_exists": None,
        },
        "errors": [],
    }

    # HTTPS
    result["https"] = check_https(url)
    if result["https"]:
        result["score"] += 10

    # SSL
    ssl_valid, days_left = check_ssl_details(host)
    result["ssl_valid"] = ssl_valid
    result["ssl_days_left"] = days_left
    if ssl_valid:
        result["score"] += 10
        if days_left > 7:
            result["score"] += 10

    # 请求站点
    response = None
    try:
        response = requests.get(url, timeout=5)
    except Exception as e:
        result["errors"].append(f"请求失败: {e}")

    if response is not None:
        # 安全头
        header_score, missing = check_security_headers(response)
        result["security_header_score"] = header_score
        result["missing_security_headers"] = missing
        result["score"] += header_score

        # 信息泄露
        server_exists = "Server" in response.headers
        x_powered_by_exists = "X-Powered-By" in response.headers
        result["info_leak"]["server_header_exists"] = server_exists
        result["info_leak"]["x_powered_by_exists"] = x_powered_by_exists

        if not server_exists:
            result["score"] += 10
        if not x_powered_by_exists:
            result["score"] += 10

    # TRACE
    result["trace_enabled"] = check_trace_method(url)
    if not result["trace_enabled"]:
        result["score"] += 10

    # 敏感路径
    result["sensitive_paths"] = check_sensitive_paths(url)
    if not result["sensitive_paths"]:
        result["score"] += 10

    # 端口
    result["open_ports"] = check_ports(host)
    if 443 in result["open_ports"]:
        result["score"] += 5
    if 80 in result["open_ports"]:
        result["score"] += 5

    # 兜底
    if result["score"] > 100:
        result["score"] = 100

    result["level"] = calc_level(result["score"])
    return result
