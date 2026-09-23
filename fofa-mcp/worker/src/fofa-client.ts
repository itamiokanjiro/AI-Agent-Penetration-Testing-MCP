export interface FOFAConfig {
  apiKey: string;
  email: string;
  baseURL: string;
  webToken?: string;
  webPrivateKey?: string;
  userId: string;
  plan: "free" | "paid";
  maxPageSize: number;
  allowFull: boolean;
}

export interface FOFASearchResult {
  error: boolean;
  errmsg: string;
  mode: string;
  page: number;
  query: string;
  results: string[][];
  size: number;
}

const DEFAULT_FIELDS = "ip,port,protocol,host,domain,title,server";
const DEFAULT_SIZE = 50;
const MAX_SIZE = 10000;
const WEB_APP_ID = "9e9fb94330d97833acfbc041ee1a76793f1bc691";

export function normalizeSearchOptions(config: FOFAConfig, size = DEFAULT_SIZE, full = false): { size: number; full: boolean } {
  const bounded = Math.min(Math.max(1, Math.floor(Number.isFinite(size) ? size : DEFAULT_SIZE)), config.maxPageSize || DEFAULT_SIZE);
  if (full && !config.allowFull) {
    throw new Error("当前免费用户配置不允许 full 搜索；请使用分页查询");
  }
  return { size: bounded, full };
}

export function isOfficialAPI(baseURL: string): boolean {
  return ["https://fofa.info", "https://fofapro.com"].includes(baseURL);
}

function utf8Base64(value: string): string {
  const bytes = new TextEncoder().encode(value);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function decodeBase64(value: string): Uint8Array {
  const binary = atob(value.replace(/\s+/g, ""));
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

function pemBytes(pem: string): Uint8Array {
  const body = pem.replace(/-----BEGIN [^-]+-----|-----END [^-]+-----|\s/g, "");
  return decodeBase64(body);
}

function derLength(length: number): Uint8Array {
  if (length < 128) return Uint8Array.of(length);
  const bytes: number[] = [];
  for (let n = length; n; n >>>= 8) bytes.unshift(n & 255);
  return Uint8Array.of(0x80 | bytes.length, ...bytes);
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const part of parts) { out.set(part, offset); offset += part.length; }
  return out;
}

function pkcs1ToPkcs8(pkcs1: Uint8Array): Uint8Array {
  const algorithm = Uint8Array.of(0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00);
  const version = Uint8Array.of(0x02, 0x01, 0x00);
  const octetLength = derLength(pkcs1.length);
  const octet = concatBytes(Uint8Array.of(0x04), octetLength, pkcs1);
  const body = concatBytes(version, algorithm, octet);
  return concatBytes(Uint8Array.of(0x30), derLength(body.length), body);
}

async function webSignature(params: URLSearchParams, pem: string): Promise<string> {
  const der = pem.includes("BEGIN PRIVATE KEY") && !pem.includes("BEGIN RSA PRIVATE KEY")
    ? pemBytes(pem)
    : pkcs1ToPkcs8(pemBytes(pem));
  const key = await crypto.subtle.importKey(
    "pkcs8",
    der,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const values = [...params.entries()]
    .filter(([, value]) => value.length > 0)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([name, value]) => `${name}${value}`)
    .join("");
  const signature = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, new TextEncoder().encode(values));
  let binary = "";
  for (const byte of new Uint8Array(signature)) binary += String.fromCharCode(byte);
  return btoa(binary);
}

async function webSearch(config: FOFAConfig, query: string, fields: string, page: number, size: number, full: boolean): Promise<FOFASearchResult> {
  if (!config.webToken) throw new Error("网页 access token 未设置");
  if (!config.webPrivateKey) throw new Error("Worker 未配置 FOFA_WEB_PRIVATE_KEY");
  const params = new URLSearchParams({
    qbase64: utf8Base64(query), fields, page: String(page), size: String(size),
    full: String(full), ts: String(Date.now()), lang: "zh-CN",
  });
  const signed = new URLSearchParams(params);
  signed.set("sign", await webSignature(params, config.webPrivateKey));
  signed.set("app_id", WEB_APP_ID);
  const response = await fetch(`${config.baseURL.replace(/\/+$/, "")}/search?${signed}`, {
    headers: { Authorization: config.webToken, Accept: "application/json", Origin: "https://fofa.info", Referer: "https://fofa.info/" },
  });
  const payload = await response.json() as { code?: number; message?: string; data?: Record<string, unknown> };
  if (!response.ok || payload.code !== 0 || !payload.data) throw new Error(`FOFA 网页搜索错误: ${payload.message || `HTTP ${response.status}`}`);
  const data = payload.data;
  const assets = Array.isArray(data.assets) ? data.assets as Record<string, unknown>[] : [];
  const names = fields.split(",").map((field) => field.trim()).filter(Boolean);
  const pageInfo = data.page && typeof data.page === "object" ? data.page as Record<string, unknown> : {};
  return {
    error: false, errmsg: "", mode: String(data.mode || "normal"),
    page: Number(pageInfo.num ?? page) || page, query: String(data.q || query),
    results: assets.map((asset) => names.map((name) => {
      const value = asset[name];
      return value === null || value === undefined ? "" : typeof value === "string" ? value : JSON.stringify(value);
    })),
    size: Number(pageInfo.total ?? assets.length) || assets.length,
  };
}

export async function fofaSearch(
  config: FOFAConfig,
  query: string,
  fields = DEFAULT_FIELDS,
  page = 1,
  size = DEFAULT_SIZE,
  full = false
): Promise<FOFASearchResult> {
  const normalized = normalizeSearchOptions(config, size, full);

  if (config.webToken) return webSearch(config, query, fields, page, normalized.size, normalized.full);
  if (!config.apiKey) throw new Error("API Key 未设置");

  const params = new URLSearchParams();
  params.set("email", config.email);
  params.set("key", config.apiKey);
  params.set("qbase64", btoa(query));
  params.set("fields", fields);
  params.set("page", String(page));
  params.set("size", String(Math.min(normalized.size, MAX_SIZE)));
  if (normalized.full) params.set("full", "true");

  const resp = await fetch(`${config.baseURL}/api/v1/search/all?${params}`);
  const text = await resp.text();

  let data: FOFASearchResult;
  try {
    data = JSON.parse(text) as FOFASearchResult;
  } catch {
    throw new Error(`FOFA API 返回异常 (HTTP ${resp.status}): ${text.substring(0, 200)}`);
  }

  if (data.error) throw new Error(`FOFA API 错误: ${data.errmsg}`);
  return data;
}

export function formatResults(result: FOFASearchResult, fields: string): string {
  const fieldNames = fields.split(",").map((f) => f.trim());
  let out = `查询: ${result.query}\n模式: ${result.mode} | 总数: ${result.size} | 页码: ${result.page} | 本页: ${result.results.length}\n\n`;

  for (let i = 0; i < result.results.length; i++) {
    const row = result.results[i];
    out += `--- 结果 #${i + 1} ---\n`;
    for (let j = 0; j < row.length && j < fieldNames.length; j++) {
      out += `  ${fieldNames[j]}: ${row[j]}\n`;
    }
  }
  return out;
}
