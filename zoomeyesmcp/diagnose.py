# -*- coding: utf-8 -*-
"""診斷 ZoomEye API 編碼問題：對比不同編碼方式對組合查詢的影響。"""
import sys
sys.stdout.reconfigure(encoding="utf-8")
import base64
import json
import re
from urllib.parse import quote, urlencode

import requests

ENV = r"C:\Users\Administrator\Desktop\666\CVE列表2\123\mcp\.env"
BASE_URL = "https://www.zoomeye.ai/api/search"

# --- 從 .env 重建 session ---
s = requests.Session()
content = open(ENV, encoding="utf-8").read()
ua = re.search(r'\$session\.UserAgent\s*=\s*"([^"]+)"', content)
if ua:
    s.headers["User-Agent"] = ua.group(1)
cookie_pat = re.compile(
    r'\$session\.Cookies\.Add\(\(New-Object System\.Net\.Cookie\("([^"]+)",\s*"([^"]+)",\s*"/",\s*"([^"]+)"\)\)\)'
)
for name, value, domain in cookie_pat.findall(content):
    s.cookies.set(name, value, domain=domain, path="/")

token = s.cookies.get("token")
print("token 前 30 字元:", token[:30] if token else "(無)")

def do_request(q, label):
    """q 為已編碼的字串，直接作為 query param（requests 會再 urlencode）。"""
    params = {"q": q, "page": 1, "pageSize": 10, "t": "v4+v6+web"}
    referer = f"https://www.zoomeye.ai/searchResult?q={q}&page=1&pageSize=10"
    headers = {
        "Accept": "application/json, text/plain, */*",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Referer": referer,
    }
    if token:
        headers["Cube-Authorization"] = token
    try:
        r = s.get(BASE_URL, params=params, headers=headers, timeout=30)
        j = r.json()
        return j.get("total"), j.get("labels"), r.url
    except Exception as e:
        return None, str(e), None

plain = 'title="Gitblit" && country="CN" && after="2026-09-01" && before="2027-01-31"'

print("=" * 70)
print("明文查詢:", plain)
print("=" * 70)

# 變體 A：標準 base64 去 padding（MCP 目前 encode_query）
a = base64.b64encode(plain.encode()).decode().rstrip("=")
total, labels, url = do_request(a, "A 標準base64去padding")
print(f"[A] 標準base64去padding: total={total} labels={labels}")
print(f"    q={a}")

# 變體 B：標準 base64 保留 padding
b = base64.b64encode(plain.encode()).decode()
total, labels, url = do_request(b, "B 標準base64留padding")
print(f"[B] 標準base64留padding: total={total} labels={labels}")
print(f"    q={b}")

# 變體 C：URL-safe base64
c = base64.urlsafe_b64encode(plain.encode()).decode().rstrip("=")
total, labels, url = do_request(c, "C urlsafe去padding")
print(f"[C] urlsafe去padding: total={total} labels={labels}")

# 變體 D：URL-safe base64 留 padding
d = base64.urlsafe_b64encode(plain.encode()).decode()
total, labels, url = do_request(d, "D urlsafe留padding")
print(f"[D] urlsafe留padding: total={total} labels={labels}")

# 變體 E：直接明文（不編碼）
total, labels, url = do_request(plain, "E 明文不編碼")
print(f"[E] 明文不編碼: total={total} labels={labels}")

# 對比：單條件 title="Gitblit"
print()
print("=" * 70)
single = 'title="Gitblit"'
sa = base64.b64encode(single.encode()).decode().rstrip("=")
total, labels, url = do_request(sa, "單條件")
print(f"單條件 title=Gitblit (去padding): total={total} labels={labels}")
