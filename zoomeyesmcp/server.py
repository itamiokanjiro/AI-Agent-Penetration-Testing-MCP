"""ZoomEye MCP Server (uv runnable).

將 ZoomEye 網頁 API（cookie/token/headers 來自 .env）包裝成 MCP server。

規範化重點：
1. 每個 tool 參數都透過 pydantic Field 宣告類型、範圍（ge/le）與描述，
   讓 MCP 客戶端產生嚴格的 JSON Schema，從源頭避免 AI 亂傳參數。
2. 服務端仍會二次校驗參數，即使客戶端繞過 schema 也會被攔截並回傳明確錯誤。
3. 查詢編碼只依賴顯式的編碼/解碼路徑，不再用「解碼後是否相同」這種不可靠的
   啟發式去猜 query 是明文還是 Base64。

執行方式：
    uv run server.py
"""

import base64
import json
import os
import re
from typing import Annotated, Literal
from urllib.parse import unquote

import requests
from mcp.server.fastmcp import FastMCP
from pydantic import Field

# 解析路徑，使 server 可從任意 cwd 執行。
HERE = os.path.dirname(os.path.abspath(__file__))
ENV_FILE = os.environ.get("ZOOMEYE_ENV", os.path.join(HERE, ".env"))

BASE_URL = "https://www.zoomeye.ai/api/search"
DEFAULT_TYPES = "v4+v6+web"
# ZoomEye 網站 API 的 pageSize 只接受 10 或 50，其他值會被歸一化。
ALLOWED_PAGE_SIZES = (10, 50)

mcp = FastMCP("zoomeye")


class ZoomEyeAPI:
    """ZoomEye 網頁 API 客戶端，session 由 .env 檔案中的片段重建。"""

    def __init__(self, env_file=ENV_FILE):
        self.session = requests.Session()
        self._query = None
        self._load_from_env(env_file)

    def _load_from_env(self, env_file):
        if not os.path.exists(env_file):
            raise FileNotFoundError(f"找不到 .env 設定檔: {env_file}")
        with open(env_file, "r", encoding="utf-8") as f:
            content = f.read()

        # User-Agent
        ua = re.search(r'\$session\.UserAgent\s*=\s*"([^"]+)"', content)
        if ua:
            self.session.headers["User-Agent"] = ua.group(1)

        # Cookies
        cookie_pat = re.compile(
            r'\$session\.Cookies\.Add\(\(New-Object System\.Net\.Cookie\("([^"]+)",\s*"([^"]+)",\s*"/",\s*"([^"]+)"\)\)\)'
        )
        for name, value, domain in cookie_pat.findall(content):
            self.session.cookies.set(name, value, domain=domain, path="/")

        # Headers block
        headers_match = re.search(r'-Headers @\{([^}]+)\}', content, re.DOTALL)
        if headers_match:
            for name, value in re.findall(r'"([^"]+)"\s*=\s*"([^"]+)"', headers_match.group(1)):
                value = value.replace('`"', '"').replace("`$", "$")
                self.session.headers[name] = value

        # Default query（-Uri 行中的 q 參數）
        uri_match = re.search(r'-Uri "([^"]+)"', content)
        if uri_match:
            q = re.search(r"q=([^&]+)", uri_match.group(1))
            if q:
                self._query = unquote(q.group(1))

    def _headers(self, query, page, page_size):
        referer = f"https://www.zoomeye.ai/searchResult?q={query}&page={page}&pageSize={page_size}"
        headers = {
            "Accept": "application/json, text/plain, */*",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Referer": referer,
        }
        token = self.session.cookies.get("token")
        if token:
            headers["Cube-Authorization"] = token
        return headers

    # ---- 編碼 / 解碼（顯式、可逆，不猜測） ----

    @staticmethod
    def encode_query(plain_query: str) -> str:
        """將明文查詢字串編碼為標準 Base64（保留 padding）。

        ZoomEye 服務端解碼時需要標準長度的 Base64（含 padding）。
        若去除 padding，組合查詢（含 && 多條件）會解碼失敗而回傳 total=0。
        """
        if not plain_query:
            raise ValueError("plain_query 不可為空")
        return base64.b64encode(plain_query.encode("utf-8")).decode("ascii")

    @staticmethod
    def decode_query(encoded_query: str) -> str:
        """將 Base64 查詢字串解碼回明文；失敗時拋出明確錯誤，而非原樣回傳。"""
        if not encoded_query:
            raise ValueError("encoded_query 不可為空")
        raw = unquote(encoded_query)
        padding = 4 - (len(raw) % 4)
        if padding != 4:
            raw += "=" * padding
        try:
            return base64.b64decode(raw).decode("utf-8")
        except Exception as exc:  # noqa: BLE001
            raise ValueError(f"無法解碼為 Base64 查詢字串: {exc}") from exc

    # ---- 搜尋 ----

    def search(self, query: str, page: int = 1, page_size: int = 50, t=DEFAULT_TYPES):
        """以「已編碼 Base64 query」執行搜尋，回傳解析後的 dict。"""
        # 服務端二次校驗（即使客戶端繞過 schema 也攔截）
        if not isinstance(page, int) or isinstance(page, bool) or page < 1:
            raise ValueError(f"page 必須為 >=1 的整數，收到: {page!r}")
        if not isinstance(page_size, int) or isinstance(page_size, bool) or page_size not in ALLOWED_PAGE_SIZES:
            raise ValueError(
                f"page_size 必須為 {ALLOWED_PAGE_SIZES} 之一（ZoomEye 只接受 10 或 50），收到: {page_size!r}"
            )

        params = {"q": query, "page": page, "pageSize": page_size, "t": t}
        headers = self._headers(query, page, page_size)

        try:
            resp = self.session.get(BASE_URL, params=params, headers=headers, timeout=30)
        except requests.exceptions.Timeout as exc:
            raise RuntimeError("請求超時（30 秒），請稍後重試") from exc
        except requests.exceptions.ConnectionError as exc:
            raise RuntimeError("連接錯誤，請檢查網路") from exc
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(f"請求異常: {exc}") from exc

        if resp.status_code != 200:
            raise RuntimeError(f"HTTP {resp.status_code}: {resp.text[:500]}")

        result = resp.json()

        # ZoomEye 即使 HTTP 200 也可能在 body 回業務錯誤
        status = result.get("status")
        if isinstance(status, int) and status != 200:
            detail = result.get("msg")
            if not detail and isinstance(result.get("result"), dict):
                inner = result["result"]
                detail = inner.get("reason") or inner.get("msg") or inner.get("msg_type") or inner.get("error_code")
            if not detail:
                detail = "未知錯誤"

            if status == 401:
                raise RuntimeError(
                    f"ZoomEye 登入失效（401 login required）：token 已過期，"
                    f"請重新登入 ZoomEye 並更新 .env 的 token。原始訊息: {detail}"
                )
            if status == 500:
                raise RuntimeError(
                    f"ZoomEye 查詢錯誤（500）：查詢語法可能有誤或參數不合法。原始訊息: {detail}"
                )
            raise RuntimeError(f"ZoomEye 錯誤（status={status}）：{detail}")
        return result


_api = ZoomEyeAPI()


def _simplify(match):
    # ZoomEye 網頁 API 的欄位結構：
    #   - match["ip"] 是「字串」（單一 IP），不是列表。
    #   - 埠在 match["portinfo"]["port"]（頂層 match["port"] 也存在，但 portinfo 更完整）。
    #   - 域名優先取 portinfo["hostname"]，其次 rdns / hostname，最後才 site。
    raw_ip = match.get("ip")
    if isinstance(raw_ip, (list, tuple)):
        ip = raw_ip[0] if raw_ip else "N/A"
    else:
        ip = raw_ip or "N/A"

    portinfo = match.get("portinfo") or {}
    port = portinfo.get("port") or match.get("port") or "N/A"

    domain = (
        portinfo.get("hostname")
        or match.get("hostname")
        or match.get("rdns")
        or match.get("site")
        or "N/A"
    )
    return {
        "ip": ip,
        "port": port,
        "domain": domain,
    }


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------
# 設計原則：只用「明文 query」做輸入，server 統一負責 Base64 編碼，避免 AI
# 自行編碼出錯。編碼/解碼工具保留給確實需要手動處理 Base64 的情境。
# ---------------------------------------------------------------------------

@mcp.tool()
def search_zoomeye(
    query: Annotated[
        str,
        Field(
            description=(
                "ZoomEye 明文查詢字串，例如 http.body=\"Claude\" && after=\"2026-08-01\"。"
                "欄位與運算子請參考 ZoomEye 語法（http.header/http.title/ip/port/after/before 等）。"
            ),
        ),
    ],
    page: Annotated[int, Field(description="頁碼，從 1 開始。", ge=1, default=1)] = 1,
    page_size: Annotated[
        Literal[10, 50],
        Field(description="每頁數量，ZoomEye 只接受 10 或 50。", default=50),
    ] = 50,
) -> str:
    """搜尋 ZoomEye，回傳簡化結果（total/page/count/data[ip,port,domain]）。

    query 一律傳「明文查詢字串」，server 會自動 Base64 編碼後送出，無需自行編碼。
    """
    encoded = _api.encode_query(query)
    result = _api.search(encoded, page=page, page_size=page_size)
    total = result.get("total", 0)
    matches = result.get("matches", [])
    simplified = [_simplify(m) for m in matches]
    return json.dumps(
        {"total": total, "page": page, "count": len(simplified), "data": simplified},
        ensure_ascii=False,
    )


@mcp.tool()
def search_zoomeye_raw(
    query: Annotated[
        str,
        Field(
            description=(
                "ZoomEye 明文查詢字串，例如 http.body=\"Claude\" && after=\"2026-08-01\"。"
                "server 會自動 Base64 編碼，無需自行編碼。"
            ),
        ),
    ],
    page: Annotated[int, Field(description="頁碼，從 1 開始。", ge=1, default=1)] = 1,
    page_size: Annotated[
        Literal[10, 50],
        Field(description="每頁數量，ZoomEye 只接受 10 或 50。", default=50),
    ] = 50,
) -> str:
    """搜尋 ZoomEye，回傳完整原始 JSON 響應（含所有欄位）。

    query 一律傳「明文查詢字串」，server 會自動 Base64 編碼後送出。
    適合需要 portinfo/protocol/geoinfo/ssl 等完整欄位的情境。
    """
    encoded = _api.encode_query(query)
    result = _api.search(encoded, page=page, page_size=page_size)
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
def encode_zoomeye_query(
    plain_query: Annotated[str, Field(description="要編碼的 ZoomEye 明文查詢字串。")],
) -> str:
    """將明文 ZoomEye 查詢字串編碼為 URL-safe Base64。"""
    return _api.encode_query(plain_query)


@mcp.tool()
def decode_zoomeye_query(
    encoded_query: Annotated[str, Field(description="要解碼的 Base64 ZoomEye 查詢字串。")],
) -> str:
    """將 Base64 編碼的 ZoomEye 查詢字串解碼回明文。"""
    return _api.decode_query(encoded_query)


if __name__ == "__main__":
    mcp.run()
