# phpmcp — PHP-CGI 参数注入 MCP Server

将 **CVE-2024-4577 / CVE-2024-8926**（PHP-CGI 参数注入）利用能力封装成 MCP server，
AI 可直接传入 **目标 IP、bypass 模块、任意系统命令 / PHP 代码**。

> ⚠️ **仅供授权测试**（企业红队、CTF、安全研究）。请勿用于未授权系统，非法使用自行承担法律责任。

## 文件

- `server.py` — MCP server 主程序（7 个 tool）
- `phpcgi.py` — 自包含核心利用模块（探测 / 命令 / 上传 / 下载 / bypass）
- `old/` — 原交互式工具（banner、rich 菜单、tor 等），仅作参考，不再依赖
- `pyproject.toml` — 依赖（`requests`、`mcp`），由 uv 管理

## 安装 & 启动

```powershell
cd C:\Users\Administrator\Desktop\666\CVE列表2\123\phpmcp
uv sync        # 首次安装依赖
uv run server.py
```

## 工具一览

| Tool | 说明 |
|------|------|
| `phpcgi_scan` | 探测目标是否存在注入点（返回 cgipoint + url） |
| `phpcgi_exec` | 执行系统命令 |
| `phpcgi_php` | 执行任意 PHP 代码 |
| `phpcgi_upload` | 向目标写入文件 |
| `phpcgi_download` | 读取目标文件 |
| `phpcgi_docroot` | 获取网站根目录 |
| `phpcgi_list_modules` | 列出 bypass 模块 / payload 组合 / CGI 字典 |

## 参数约定

- **`target`**：IP、`IP:port`、域名、或完整 URL 均可，例如 `1.2.3.4`、`1.2.3.4:8080`、`http://example.com`。
- **`command`**：任意系统命令，内部自动 base64 包裹，避免引号/特殊字符问题。
- **`bypass`**：逗号分隔的模块名，例如 `xff_ip_bypass,random_useragent,phpfilter_wrap`。
- **`payload_group`**：`1`（全量）/ `2` / `3`（最小）。
- **`cve_id`**：`CVE-2024-4577`（`%ADd`）或 `CVE-2024-8926`（`%a8-d%a8`）。
- **`cgipoint`**：留空则自动扫描；指定则跳过扫描直接利用。

## 接入 MCP 客户端（Claude Desktop / Cursor 等）

```json
{
  "mcpServers": {
    "phpmcp": {
      "command": "uv",
      "args": ["run", "server.py"],
      "cwd": "C:\\Users\\Administrator\\Desktop\\666\\CVE列表2\\123\\phpmcp"
    }
  }
}
```

## 典型流程

1. `phpcgi_scan(target="1.2.3.4", bypass="xff_ip_bypass,random_useragent")` 找到注入点
2. `phpcgi_exec(target="1.2.3.4", command="whoami")` 验证 RCE
3. `phpcgi_docroot` 拿网站根目录 → `phpcgi_upload` 写 webshell
