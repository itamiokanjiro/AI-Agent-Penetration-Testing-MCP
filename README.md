# 資產偵查與滲透測試 MCP 工具集

> 使用 DeepSeek 也可以完成美好的滲透，攻擊無數企業 cluster 打到Master

本資料夾整合三個 MCP server，供 AI 客戶端（Claude Desktop / Cursor / Claude Code 等）直接呼叫。

> ⚠️ 僅供授權測試（紅隊、CTF、安全研究），未經授權使用請自負法律責任。
> 淪陷的目標請自行回報各國家的資安機構。

| 目錄 | 功能 |
|------|------|
| `zoomeyesmcp/` | ZoomEye 資產搜尋 |
| `fofa-mcp/` | FOFA 資產搜尋 |
| `phpmcp/` | PHP-CGI 參數注入（CVE-2024-4577 / 8926）利用 |
| `非AI工具包/` | 非 AI 工具包（ZoomEye 搜尋 / `.git` 外洩 / 路徑掃描） |

---

## 憑證取得（重要）

### ZoomEye

1. 登入 zoomeye.ai → 執行一次搜尋
2. DevTools → Network → `api/search` → 右鍵 → **Copy as PowerShell**
3. 整段貼到 `zoomeyesmcp/.env`

- 憑證**每日失效**，需每天重新複製貼上
- 每帳號每月 **3000** 額度

### FOFA

1. 登入 fofa.info → DevTools → Cookies 取登入 token
2. 設環境變數 `FOFA_WEB_TOKEN`

- 憑證**每週失效**，需每週更新

---

## 搜尋範例（ZoomEye）

CVE-2024-4577 目標：

```text
http.body!="301" && http.header="Apache" && http.header="PHP/8" && after="2026-09-01" && before="2027-01-31" && port!="80" && port="443" && country="JP"
```

> 破甲（WAF bypass / 利用）請自行準備，或是自建 AGENT。

---

## 非 AI 工具包（`非AI工具包/`）

傳統腳本（不經 MCP），對應上方 MCP 功能：

- `zoomeye.py` — ZoomEye 搜尋，輸出 ip/port/domain JSON
- `git.py` / `網域git.py` — 批次檢查 `.git/HEAD` 外洩
- `多重掃描.py` — 常見漏洞路徑掃描（`.git` / `.env` / config / backup / admin）
- `7000自己收集的IP表.json` — 自收集目標 IP 清單

---

## 啟動

```powershell
# ZoomEye
cd zoomeyesmcp; uv sync; uv run server.py

# FOFA
cd fofa-mcp; npm install; npm run build
$env:FOFA_WEB_TOKEN = "從 cookies 取出的 token"
node dist/index.js

# phpmcp
cd phpmcp; uv sync; uv run server.py
```

## 接入 MCP 客戶端

```json
{
  "mcpServers": {
    "zoomeye": { "command": "uv", "args": ["run", "server.py"], "cwd": "<本機路徑>\\zoomeyesmcp" },
    "fofa": { "command": "node", "args": ["dist/index.js"], "cwd": "<本機路徑>\\fofa-mcp", "env": { "FOFA_WEB_TOKEN": "xxx" } },
    "phpmcp": { "command": "uv", "args": ["run", "server.py"], "cwd": "<本機路徑>\\phpmcp" }
  }
}
```

> `cwd` 依實際本機路徑調整。

---

## 來源 / 致謝

- `phpmcp/`（PHP-CGI 參數注入工具）改寫自 [Night-have-dreams/php-cgi-Injector](https://github.com/Night-have-dreams/php-cgi-Injector)，原作者 Night-have-dreams，MIT License。
- `fofa-mcp/` 源自 [lulaide/fofa-mcp](https://github.com/lulaide/fofa-mcp)，MIT License。



