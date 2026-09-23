import assert from "node:assert/strict";
import test from "node:test";
import { generateKeyPairSync, verify as rsaVerify } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { loadSecrets, signToken, verifyToken } from "../dist/server/crypto.js";
import { loadConfig, normalizeSearchOptions, search } from "../dist/client.js";
import { UserRateLimiter } from "../dist/server/rate-limit.js";

const freeConfig = {
  apiKey: "free-key-a",
  email: "a@example.com",
  baseURL: "https://fofa.info",
  userId: "user-a",
  plan: "free",
  maxPageSize: 50,
  allowFull: false,
};

test("free plan clamps pages and rejects full search", () => {
  assert.deepEqual(normalizeSearchOptions(freeConfig, 10000, false), { size: 50, full: false });
  assert.throws(() => normalizeSearchOptions(freeConfig, 10, true), /不允许 full/);
});

test("stdio defaults to an isolated free-user profile", () => {
  delete process.env.FOFA_PLAN;
  delete process.env.FOFA_MAX_PAGE_SIZE;
  delete process.env.FOFA_ALLOW_FULL;
  const config = loadConfig();
  assert.equal(config.plan, "free");
  assert.equal(config.maxPageSize, 50);
  assert.equal(config.allowFull, false);
  assert.equal(config.userId, "stdio");
});

test("stdio imports the newest Authorization from the registration token file", () => {
  const dir = mkdtempSync("/tmp/fofa-token-file-");
  const file = join(dir, "fofa_authorizations.json");
  writeFileSync(file, JSON.stringify({ tokens: [{ authorization: "token-old" }, { authorization: "token-new" }] }));
  delete process.env.FOFA_WEB_TOKEN;
  delete process.env.FOFA_TOKEN;
  process.env.FOFA_WEB_TOKEN_FILE = file;
  try {
    const config = loadConfig();
    assert.equal(config.webToken, "token-new");
    assert.equal(config.baseURL, "https://api.fofa.info/v1");
  } finally {
    delete process.env.FOFA_WEB_TOKEN_FILE;
  }
});

test("paid plan can opt into full search and larger pages", () => {
  const paid = { ...freeConfig, plan: "paid", maxPageSize: 10000, allowFull: true };
  assert.deepEqual(normalizeSearchOptions(paid, 10000, true), { size: 10000, full: true });
});

test("rate limits users independently", () => {
  const limiter = new UserRateLimiter(2, 60_000);
  assert.equal(limiter.check("a", 0).allowed, true);
  assert.equal(limiter.check("a", 1).allowed, true);
  assert.equal(limiter.check("a", 2).allowed, false);
  assert.equal(limiter.check("b", 2).allowed, true);
  assert.equal(limiter.check("a", 60_001).allowed, true);
});

test("access tokens encrypt per-user credentials", async () => {
  process.env.JWE_SECRET = Buffer.alloc(32, 7).toString("base64");
  process.env.JWS_SECRET = Buffer.alloc(32, 9).toString("base64");
  const secrets = loadSecrets();
  const tokenA = await signToken(secrets, { ...freeConfig, userId: "oauth-client-a" });
  const tokenB = await signToken(secrets, { ...freeConfig, apiKey: "free-key-b", userId: "oauth-client-b" });
  assert.notEqual(tokenA, tokenB);
  assert.equal(tokenA.includes("free-key-a"), false);
  assert.equal((await verifyToken(secrets, tokenA)).userId, "oauth-client-a");
  assert.equal((await verifyToken(secrets, tokenB)).apiKey, "free-key-b");
});

test("thirty synthetic user profiles stay isolated", async () => {
  process.env.JWE_SECRET = Buffer.alloc(32, 7).toString("base64");
  process.env.JWS_SECRET = Buffer.alloc(32, 9).toString("base64");
  const secrets = loadSecrets();
  const tokens = await Promise.all(Array.from({ length: 30 }, async (_, index) => signToken(secrets, {
    ...freeConfig,
    apiKey: `free-key-${index}`,
    userId: `oauth-client-${index}`,
  })));
  const payloads = await Promise.all(tokens.map((token) => verifyToken(secrets, token)));
  assert.equal(new Set(payloads.map((payload) => payload.userId)).size, 30);
  assert.deepEqual(payloads.map((payload) => payload.apiKey), Array.from({ length: 30 }, (_, i) => `free-key-${i}`));
});

test("web search uses the browser endpoint and clamps free pages to 50", async () => {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const privatePem = privateKey.export({ type: "pkcs1", format: "pem" }).toString();
  const previousFetch = globalThis.fetch;
  let requested;
  globalThis.fetch = async (input) => {
    requested = new URL(String(input));
    return new Response(JSON.stringify({
      code: 0,
      data: { q: 'domain="example.com"', mode: "normal", page: { num: 1, total: 51 }, assets: [{ domain: "example.com", ip: "1.2.3.4" }] },
    }), { status: 200, headers: { "content-type": "application/json" } });
  };
  try {
    const result = await search({
      apiKey: "", email: "", baseURL: "https://api.fofa.info/v1", webToken: "browser-token",
      webPrivateKey: privatePem, userId: "web-user", plan: "free", maxPageSize: 50, allowFull: false,
    }, 'domain="example.com"', "domain,ip", 1, 100, false);
    assert.equal(result.results.length, 1);
    assert.equal(result.size, 51);
    assert.equal(requested.searchParams.get("size"), "50");
    const signed = requested.searchParams.get("sign");
    assert.ok(signed);
    const signInput = [...requested.searchParams.entries()]
      .filter(([name, value]) => !["sign", "app_id"].includes(name) && value.length > 0)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([name, value]) => `${name}${value}`).join("");
    assert.equal(rsaVerify("RSA-SHA256", Buffer.from(signInput), publicKey, Buffer.from(signed, "base64")), true);
  } finally {
    globalThis.fetch = previousFetch;
  }
});
