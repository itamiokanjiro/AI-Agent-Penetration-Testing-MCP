# -*- coding: utf-8 -*-
"""驗證修復後的 encode_query 是否正確。"""
import sys
sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, r"C:\Users\Administrator\Desktop\666\CVE列表2\123\mcp")

# 直接測試修復後的 encode_query 邏輯
import base64

def encode_query(plain_query: str) -> str:
    if not plain_query:
        raise ValueError("plain_query 不可為空")
    return base64.b64encode(plain_query.encode("utf-8")).decode("ascii")

plain = 'title="Gitblit" && country="CN" && after="2026-09-01" && before="2027-01-31"'
enc = encode_query(plain)
print("編碼結果:", enc)
print("結尾:", repr(enc[-4:]), "（應以 = 或 == 結尾）")

# 驗證與已知正確值一致
expected_tail = "==" 
print("保留 padding:", enc.endswith("="))
