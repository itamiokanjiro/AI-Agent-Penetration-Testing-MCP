# ZoomEye MCP Server（uv 啟動）

將 ZoomEye 網頁 API（cookie/token/headers 來自 `.env`）包裝成 MCP server。

## 檔案說明

- `server.py` — MCP server 主程式（含 4 個 tool）
- `pyproject.toml` — 依賴宣告（`mcp>=1,<2`、`requests`），由 `uv` 管理
- `.env` — ZoomEye 登入 session（PowerShell `Invoke-WebRequest` 片段，內含 cookie/token）
- `uv.lock` — 依賴鎖定檔（自動產生）

## 首次安裝依賴

```powershell
cd mcp
uv sync
```

（若尚未安裝 uv：`pip install uv`）

## 啟動（stdio）

```powershell
uv run server.py
```

## 工具（Tools）

| Tool | 說明 |
|------|------|
| `search_zoomeye` | 搜尋 ZoomEye，傳回簡化結果（ip/port/domain）。query **一律傳明文**，server 自動編碼 |
| `search_zoomeye_raw` | 搜尋 ZoomEye，傳回完整原始 JSON。query **一律傳明文**，server 自動編碼 |
| `encode_zoomeye_query` | 明文查詢 → Base64 |
| `decode_zoomeye_query` | Base64 → 明文查詢 |

> `query` 一律傳**明文**查詢字串即可，server 會自動 Base64 編碼，無需自行編碼。
> `page` 限定 `>=1`；`page_size` 限定 `1~200`，參數已由 pydantic schema 約束並於服務端二次校驗。

### query 明文範例

```text
http.body="Claude" && http.body="自助充值" && after="2026-08-01"
```

server 會自動編碼為：

```text
aHR0cC5ib2R5PSJDbGF1ZGUiICYmIGh0dHAuYm9keT0i6Ieq5Yqp5YWF5YC8IiAmJiBhZnRlcj0iMjAyNi0wOC0wMSI
```

## 接入 MCP 客戶端（如 Claude Desktop / Cursor）

在客戶端的 MCP 設定加入 stdio server：

```json
{
  "mcpServers": {
    "zoomeye": {
      "command": "uv",
      "args": ["run", "server.py"],
      "cwd": "C:\\Users\\Administrator\\Desktop\\666\\CVE列表2\\123\\mcp"
    }
  }
}
```

> 若 `uv` 不在 PATH，改用完整路徑或 `python -m uv run server.py`。

## 注意事項

- `.env` 內的 `token`（JWT）有過期時間；若 API 回傳 `401 login required`，表示登入 session 已過期，需重新登入 ZoomEye 並更新 `.env`。
- 自訂 `.env` 路徑可用環境變數 `ZOOMEYE_ENV` 指定。
