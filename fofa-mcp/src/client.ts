import { createDecipheriv, createHash, createPrivateKey, sign as rsaSign } from "node:crypto";
import { readFileSync } from "node:fs";

const DEFAULT_BASE_URL = "https://fofa.info";
const DEFAULT_WEB_API_URL = "https://api.fofa.info/v1";
const MAX_API_SIZE = 10000;
const DEFAULT_FREE_PAGE_SIZE = 50;
const WEB_APP_ID = "9e9fb94330d97833acfbc041ee1a76793f1bc691";
const WEB_AES_PASSPHRASE = "fofa-v5-secure-2025";

const webPrivateKeyPromises = new Map<string, Promise<ReturnType<typeof createPrivateKey>>>();

export type FOFAPlan = "free" | "paid";

export interface FOFAConfig {
  apiKey: string;
  email: string;
  baseURL: string;
  webToken?: string;
  webTokenFile?: string;
  webPrivateKey?: string;
  userId: string;
  plan: FOFAPlan;
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

export function loadConfig(): FOFAConfig {
  const plan: FOFAPlan = process.env.FOFA_PLAN === "paid" ? "paid" : "free";
  const tokenFile = process.env.FOFA_WEB_TOKEN_FILE || "";
  const webToken = process.env.FOFA_WEB_TOKEN || process.env.FOFA_TOKEN || (tokenFile ? loadWebTokenFile(tokenFile) : "");
  const webPrivateKey = process.env.FOFA_WEB_PRIVATE_KEY || "";
  const webMode = process.env.FOFA_MODE === "web" || Boolean(webToken);
  const configuredMax = Number.parseInt(process.env.FOFA_MAX_PAGE_SIZE || "", 10);
  const defaultMax = plan === "free" ? DEFAULT_FREE_PAGE_SIZE : MAX_API_SIZE;
  const maxPageSize = Math.min(MAX_API_SIZE, Math.max(1, Number.isFinite(configuredMax)
    ? configuredMax : defaultMax));
  return {
    apiKey: process.env.FOFA_API_KEY || "",
    email: process.env.FOFA_EMAIL || "",
    baseURL: (process.env.FOFA_BASE_URL || (webMode ? DEFAULT_WEB_API_URL : DEFAULT_BASE_URL)).replace(/\/+$/, ""),
    webToken,
    webTokenFile: tokenFile || undefined,
    webPrivateKey,
    userId: process.env.FOFA_USER_ID || "stdio",
    plan,
    maxPageSize,
    allowFull: process.env.FOFA_ALLOW_FULL === "true" || plan === "paid",
  };
}

export function isOfficialAPI(baseURL: string): boolean {
  return [DEFAULT_BASE_URL, "https://fofa.info", "https://fofapro.com"].includes(baseURL);
}

export function normalizeSearchOptions(config: FOFAConfig, size = DEFAULT_FREE_PAGE_SIZE, full = false): { size: number; full: boolean } {
  const requested = Number.isFinite(size) ? Math.floor(size) : DEFAULT_FREE_PAGE_SIZE;
  const bounded = Math.min(Math.max(1, requested), Math.min(MAX_API_SIZE, config.maxPageSize || DEFAULT_FREE_PAGE_SIZE));
  if (full && !config.allowFull) {
    throw new Error("当前免费用户配置不允许 full 搜索；请使用分页查询或由管理员调整 FOFA_ALLOW_FULL");
  }
  return { size: bounded, full };
}

function evpBytesToKey(password: string, salt: Buffer, length: number): Buffer {
  const chunks: Buffer[] = [];
  let previous = Buffer.alloc(0);
  let total = 0;
  while (total < length) {
    previous = createHash("md5").update(Buffer.concat([previous, Buffer.from(password), salt])).digest();
    chunks.push(previous);
    total += previous.length;
  }
  return Buffer.concat(chunks).subarray(0, length);
}

function decryptWebPrivateKey(encrypted: string): string {
  const raw = Buffer.from(encrypted, "base64");
  if (raw.subarray(0, 8).toString() !== "Salted__") throw new Error("FOFA 网页签名密钥格式异常");
  const keyIv = evpBytesToKey(WEB_AES_PASSPHRASE, raw.subarray(8, 16), 48);
  const decipher = createDecipheriv("aes-256-cbc", keyIv.subarray(0, 32), keyIv.subarray(32, 48));
  return Buffer.concat([decipher.update(raw.subarray(16)), decipher.final()]).toString("utf8");
}

function loadWebTokenFile(filePath: string): string {
  const raw = readFileSync(filePath, "utf8").trim();
  if (!raw) throw new Error(`FOFA 网页 token 文件为空: ${filePath}`);
  try {
    const parsed = JSON.parse(raw) as unknown;
    const records = Array.isArray(parsed)
      ? parsed
      : (parsed && typeof parsed === "object" && Array.isArray((parsed as { tokens?: unknown }).tokens)
        ? (parsed as { tokens: unknown[] }).tokens : []);
    for (const record of [...records].reverse()) {
      if (typeof record === "string" && record.trim()) return record.trim();
      if (record && typeof record === "object") {
        const token = (record as { authorization?: unknown; access_token?: unknown; token?: unknown }).authorization
          ?? (record as { access_token?: unknown }).access_token
          ?? (record as { token?: unknown }).token;
        if (typeof token === "string" && token.trim()) return token.trim();
      }
    }
  } catch {
    return raw;
  }
  throw new Error(`FOFA 网页 token 文件没有可用 token: ${filePath}`);
}

async function loadWebPrivateKey(config: FOFAConfig): Promise<ReturnType<typeof createPrivateKey>> {
  const cacheKey = config.webPrivateKey || "__fofa_homepage__";
  let webPrivateKeyPromise = webPrivateKeyPromises.get(cacheKey);
  if (!webPrivateKeyPromise) {
    webPrivateKeyPromise = (async () => {
      let pem = config.webPrivateKey;
      if (pem && !pem.includes("BEGIN")) {
        pem = readFileSync(pem, "utf8");
      }
      if (!pem) {
        const response = await fetch(DEFAULT_BASE_URL + "/");
        if (!response.ok) throw new Error(`FOFA 网页配置获取失败: HTTP ${response.status}`);
        const html = await response.text();
        const match = html.match(/apiKey:\"([^\"]+)\"/);
        if (!match) throw new Error("FOFA 网页配置中未找到签名密钥");
        pem = decryptWebPrivateKey(match[1]);
      }
      return createPrivateKey(pem);
    })();
    webPrivateKeyPromises.set(cacheKey, webPrivateKeyPromise);
  }
  return webPrivateKeyPromise;
}

function webSign(params: URLSearchParams, key: ReturnType<typeof createPrivateKey>): string {
  const values = [...params.entries()]
    .filter(([, value]) => String(value).length > 0)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([name, value]) => `${name}${value}`)
    .join("");
  return rsaSign("RSA-SHA256", Buffer.from(values), key).toString("base64");
}

function stringifyWebField(value: unknown): string {
  if (value === null || value === undefined) return "";
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") return String(value);
  return JSON.stringify(value);
}

async function webSearch(config: FOFAConfig, query: string, fields: string, page: number, size: number, full: boolean): Promise<FOFASearchResult> {
  const webToken = config.webTokenFile ? loadWebTokenFile(config.webTokenFile) : config.webToken;
  if (!webToken) throw new Error("FOFA_WEB_TOKEN/FOFA_WEB_TOKEN_FILE 未设置");
  const key = await loadWebPrivateKey(config);
  const params = new URLSearchParams();
  params.set("qbase64", Buffer.from(query).toString("base64"));
  params.set("fields", fields);
  params.set("page", String(page));
  params.set("size", String(size));
  params.set("full", String(full));
  params.set("ts", String(Date.now()));
  params.set("lang", "zh-CN");
  const signed = new URLSearchParams(params);
  signed.set("sign", webSign(params, key));
  signed.set("app_id", WEB_APP_ID);
  const response = await fetch(`${config.baseURL || DEFAULT_WEB_API_URL}/search?${signed.toString()}`, {
    headers: {
      Authorization: webToken,
      Accept: "application/json",
      Origin: DEFAULT_BASE_URL,
      Referer: `${DEFAULT_BASE_URL}/`,
      "User-Agent": "Mozilla/5.0",
    },
  });
  const payload = await response.json() as { code?: number; message?: string; data?: Record<string, unknown> };
  if (!response.ok || payload.code !== 0 || !payload.data) {
    throw new Error(`FOFA 网页搜索错误: ${payload.message || `HTTP ${response.status}`}`);
  }
  const data = payload.data;
  const assets = Array.isArray(data.assets) ? data.assets as Record<string, unknown>[] : [];
  const names = fields.split(",").map((field) => field.trim()).filter(Boolean);
  const pageInfo = (data.page && typeof data.page === "object") ? data.page as Record<string, unknown> : {};
  const resultPage = Number(pageInfo.num ?? page) || page;
  const total = Number(pageInfo.total ?? assets.length) || assets.length;
  return {
    error: false,
    errmsg: "",
    mode: String(data.mode || "normal"),
    page: resultPage,
    query: String(data.q || query),
    results: assets.map((asset) => names.map((name) => stringifyWebField(asset[name]))),
    size: total,
  };
}

async function request<T>(config: FOFAConfig, path: string, params: URLSearchParams): Promise<T> {
  if (!config.apiKey) throw new Error("FOFA_API_KEY 环境变量未设置");

  params.set("email", config.email);
  params.set("key", config.apiKey);

  const url = `${config.baseURL}${path}?${params.toString()}`;
  const resp = await fetch(url);
  const data = (await resp.json()) as { error: boolean; errmsg: string };

  if (data.error) throw new Error(`FOFA API 错误: ${data.errmsg}`);
  return data as T;
}

export async function search(
  config: FOFAConfig,
  query: string,
  fields: string,
  page: number,
  size: number,
  full: boolean
): Promise<FOFASearchResult> {
  const normalized = normalizeSearchOptions(config, size, full);
  if (config.webToken || config.webTokenFile) return webSearch(config, query, fields, page, normalized.size, normalized.full);
  const params = new URLSearchParams();
  params.set("qbase64", Buffer.from(query).toString("base64"));
  params.set("fields", fields);
  params.set("page", String(page));
  params.set("size", String(normalized.size));
  if (normalized.full) params.set("full", "true");

  return request<FOFASearchResult>(config, "/api/v1/search/all", params);
}

export async function userInfo(config: FOFAConfig): Promise<Record<string, unknown>> {
  return request(config, "/api/v1/info/my", new URLSearchParams());
}

export async function stats(config: FOFAConfig, query: string, fields?: string): Promise<Record<string, unknown>> {
  const params = new URLSearchParams();
  params.set("qbase64", Buffer.from(query).toString("base64"));
  if (fields) params.set("fields", fields);
  return request(config, "/api/v1/search/stats", params);
}

export async function hostDetail(config: FOFAConfig, host: string, detail: boolean): Promise<Record<string, unknown>> {
  const params = new URLSearchParams();
  if (detail) params.set("detail", "true");
  return request(config, `/api/v1/host/${encodeURIComponent(host)}`, params);
}
