import express from "express";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { mcpAuthRouter, getOAuthProtectedResourceMetadataUrl } from "@modelcontextprotocol/sdk/server/auth/router.js";
import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import { FOFAOAuthProvider } from "./oauth-provider.js";
import { loadSecrets } from "./crypto.js";
import { createMcpServer } from "./create-mcp-server.js";
import type { FOFAConfig } from "../client.js";
import { UserRateLimiter } from "./rate-limit.js";

export async function startServer(): Promise<void> {
  const serverUrl = process.env.SERVER_URL || "http://localhost:3000";
  const secrets = loadSecrets();
  const listenAddr = process.env.LISTEN_ADDR || ":3000";

  let host = "0.0.0.0";
  let port = 3000;
  if (listenAddr.startsWith(":")) {
    port = parseInt(listenAddr.slice(1), 10);
  } else if (listenAddr.includes(":")) {
    const idx = listenAddr.lastIndexOf(":");
    host = listenAddr.slice(0, idx);
    port = parseInt(listenAddr.slice(idx + 1), 10);
  }

  const provider = new FOFAOAuthProvider(secrets, serverUrl);
  const configuredLimit = Number.parseInt(process.env.FOFA_MAX_REQUESTS_PER_MINUTE || "60", 10);
  const limiter = new UserRateLimiter(Number.isFinite(configuredLimit) ? Math.max(1, configuredLimit) : 60);
  const issuerUrl = new URL(serverUrl);
  const mcpServerUrl = new URL("/mcp", serverUrl);

  const app = express();
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  // OAuth 路由
  app.use(
    mcpAuthRouter({
      provider,
      issuerUrl,
      baseUrl: issuerUrl,
      resourceServerUrl: mcpServerUrl,
      resourceName: "FOFA MCP Server",
      scopesSupported: [],
    })
  );

  // Bearer auth 中间件
  const authMiddleware = requireBearerAuth({
    verifier: provider,
    requiredScopes: [],
    resourceMetadataUrl: getOAuthProtectedResourceMetadataUrl(mcpServerUrl),
  });

  // POST /mcp — 无状态：每个请求独立创建 server + transport
  app.post("/mcp", authMiddleware, async (req, res) => {
    const authInfo = (req as unknown as { auth: AuthInfo }).auth;
    const userId = String(authInfo.extra?.userId || authInfo.clientId || "unknown");
    const limit = limiter.check(userId);
    if (!limit.allowed) {
      res.setHeader("Retry-After", String(limit.retryAfterSeconds));
      res.status(429).json({ error: "rate_limited", retry_after_seconds: limit.retryAfterSeconds });
      return;
    }
    const config: FOFAConfig = {
      apiKey: authInfo.extra!.apiKey as string,
      email: authInfo.extra!.email as string,
      baseURL: authInfo.extra!.baseURL as string,
      webToken: authInfo.extra!.webToken as string | undefined,
      webPrivateKey: authInfo.extra!.webPrivateKey as string | undefined,
      userId,
      plan: (authInfo.extra!.plan as FOFAConfig["plan"]) || "free",
      maxPageSize: Number(authInfo.extra!.maxPageSize) || 50,
      allowFull: authInfo.extra!.allowFull === true,
    };

    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
    });

    const server = createMcpServer(config);
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
    await transport.close();
    await server.close();
  });

  app.listen(port, host, () => {
    console.log(`FOFA MCP HTTP 服务器已启动`);
    console.log(`监听: ${host}:${port}`);
    console.log(`公开地址: ${serverUrl}`);
    console.log(`MCP 端点: ${serverUrl}/mcp`);
  });
}
