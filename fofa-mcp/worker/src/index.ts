import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import { loadSecrets, type ServerSecrets } from "./crypto.js";
import {
  handleOAuthMetadata,
  handleResourceMetadata,
  handleRegister,
  handleAuthorizeGet,
  handleAuthorizePost,
  handleToken,
  extractConfigFromToken,
} from "./oauth.js";
import { createMcpServer } from "./mcp-server.js";

interface Env {
  SERVER_URL?: string;
  JWE_SECRET?: string;
  JWS_SECRET?: string;
  FOFA_WEB_PRIVATE_KEY?: string;
}

let cachedSecrets: ServerSecrets | null = null;
const requestHits = new Map<string, number[]>();

function getSecrets(env: Env): ServerSecrets {
  if (!cachedSecrets) {
    cachedSecrets = loadSecrets(env as unknown as Record<string, string | undefined>);
  }
  return cachedSecrets;
}

function corsHeaders(): Record<string, string> {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, Mcp-Session-Id, Mcp-Protocol-Version",
    "Access-Control-Expose-Headers": "Mcp-Session-Id",
  };
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const serverUrl = (env.SERVER_URL || url.origin).replace(/\/+$/, "");
    const secrets = getSecrets(env);

    // CORS preflight
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders() });
    }

    // OAuth discovery
    if (url.pathname === "/.well-known/oauth-authorization-server") {
      return handleOAuthMetadata(serverUrl);
    }
    if (url.pathname === "/.well-known/oauth-protected-resource/mcp" ||
        url.pathname === "/.well-known/oauth-protected-resource") {
      return handleResourceMetadata(serverUrl);
    }

    // Dynamic client registration
    if (url.pathname === "/register" && request.method === "POST") {
      const body = await request.json() as Record<string, unknown>;
      return handleRegister(body);
    }

    // Authorization
    if (url.pathname === "/authorize") {
      if (request.method === "GET") {
        return handleAuthorizeGet(url, serverUrl);
      }
      if (request.method === "POST") {
        const text = await request.text();
        const body = new URLSearchParams(text);
        return handleAuthorizePost(body, secrets, env.FOFA_WEB_PRIVATE_KEY || "");
      }
    }

    // Token exchange
    if (url.pathname === "/token" && request.method === "POST") {
      const text = await request.text();
      const body = new URLSearchParams(text);
      return handleToken(body, secrets);
    }

    // MCP endpoint — 无状态模式：每个请求独立创建 server + transport
    if (url.pathname === "/mcp") {
      if (request.method !== "POST") {
        return new Response("Method Not Allowed", { status: 405, headers: corsHeaders() });
      }

      // Verify token
      const authResult = await extractConfigFromToken(request, secrets);
      if (authResult instanceof Response) return authResult;

      const { config } = authResult;
      const now = Date.now();
      const recent = (requestHits.get(config.userId) || []).filter((t) => now - t < 60_000);
      if (recent.length >= 60) {
        return new Response(JSON.stringify({ error: "rate_limited", retry_after_seconds: 60 }), { status: 429, headers: { "Content-Type": "application/json", ...corsHeaders() } });
      }
      recent.push(now);
      requestHits.set(config.userId, recent);
      const body = await request.json();

      // 无状态：每次请求创建新的 transport + server
      const transport = new WebStandardStreamableHTTPServerTransport({
        sessionIdGenerator: undefined, // 无状态模式
        enableJsonResponse: true,      // 返回 JSON 而非 SSE
      });

      const server = createMcpServer(config);
      await server.connect(transport);

      const response = await transport.handleRequest(request, { parsedBody: body });

      // 请求处理完关闭
      await transport.close();
      await server.close();

      return response;
    }

    // Health check
    if (url.pathname === "/" || url.pathname === "/health") {
      return Response.json({ status: "ok", service: "fofa-mcp" }, { headers: corsHeaders() });
    }

    return new Response("Not Found", { status: 404 });
  },
};
