import type { Response } from "express";
import type { OAuthServerProvider, AuthorizationParams } from "@modelcontextprotocol/sdk/server/auth/provider.js";
import type { OAuthRegisteredClientsStore } from "@modelcontextprotocol/sdk/server/auth/clients.js";
import type { OAuthClientInformationFull, OAuthTokens } from "@modelcontextprotocol/sdk/shared/auth.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import { type ServerSecrets, encryptCode, decryptCode, signToken, verifyToken } from "./crypto.js";
import { renderAuthorizePage } from "./authorize-page.js";
import type { FOFAPlan } from "../client.js";

export class FOFAClientsStore implements OAuthRegisteredClientsStore {
  private clients = new Map<string, OAuthClientInformationFull>();

  getClient(clientId: string): OAuthClientInformationFull | undefined {
    return this.clients.get(clientId);
  }

  registerClient(client: OAuthClientInformationFull): OAuthClientInformationFull {
    this.clients.set(client.client_id, client);
    return client;
  }
}

export class FOFAOAuthProvider implements OAuthServerProvider {
  readonly clientsStore: FOFAClientsStore;
  private secrets: ServerSecrets;
  private serverUrl: string;

  constructor(secrets: ServerSecrets, serverUrl: string) {
    this.clientsStore = new FOFAClientsStore();
    this.secrets = secrets;
    this.serverUrl = serverUrl;
  }

  async authorize(
    client: OAuthClientInformationFull,
    params: AuthorizationParams,
    res: Response
  ): Promise<void> {
    const req = res.req;
    const body = req.body || {};

    // POST 可提交官方 API Key，或网页端 access token（免费用户无 API 配额时使用）
    if (req.method === "POST" && (body.api_key || body.web_token)) {
      const webToken = String(body.web_token || "").trim();
      const defaultBase = webToken ? "https://api.fofa.info/v1" : "https://fofa.info";
      const submittedBase = String(body.base_url || "").trim();
      const baseURL = (webToken && (!submittedBase || submittedBase === "https://fofa.info")
        ? defaultBase
        : (submittedBase || defaultBase)).replace(/\/+$/, "");
      const apiKey = (body.api_key as string) || "";
      const email = (body.email as string) || "";
      const plan: FOFAPlan = process.env.FOFA_DEFAULT_PLAN === "paid" ? "paid" : "free";

      const code = await encryptCode(this.secrets, {
        baseURL,
        apiKey,
        email,
        webToken: webToken || undefined,
        codeChallenge: params.codeChallenge,
        codeChallengeMethod: "S256",
        clientId: client.client_id,
        redirectUri: params.redirectUri,
        scopes: params.scopes || [],
        plan,
      });

      const redirectUrl = new URL(params.redirectUri);
      redirectUrl.searchParams.set("code", code);
      if (params.state) {
        redirectUrl.searchParams.set("state", params.state);
      }

      res.redirect(302, redirectUrl.toString());
      return;
    }

    // GET 或未带 FOFA 字段的请求 → 渲染授权页面
    const html = renderAuthorizePage({
      clientId: client.client_id,
      redirectUri: params.redirectUri,
      state: params.state || "",
      codeChallenge: params.codeChallenge,
      codeChallengeMethod: "S256",
      scope: (params.scopes || []).join(" "),
      serverUrl: this.serverUrl,
    });

    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.send(html);
  }

  async challengeForAuthorizationCode(
    _client: OAuthClientInformationFull,
    authorizationCode: string
  ): Promise<string> {
    const payload = await decryptCode(this.secrets, authorizationCode);
    return payload.codeChallenge;
  }

  async exchangeAuthorizationCode(
    _client: OAuthClientInformationFull,
    authorizationCode: string,
    _codeVerifier?: string,
    redirectUri?: string,
    _resource?: URL
  ): Promise<OAuthTokens> {
    const payload = await decryptCode(this.secrets, authorizationCode);

    // 验证 redirect_uri 一致
    if (redirectUri && redirectUri !== payload.redirectUri) {
      throw new Error("redirect_uri 不匹配");
    }

    const accessToken = await signToken(this.secrets, {
      baseURL: payload.baseURL,
      apiKey: payload.apiKey,
      email: payload.email,
      webToken: payload.webToken,
      webPrivateKey: payload.webPrivateKey,
      clientId: payload.clientId,
      scopes: payload.scopes,
      userId: payload.clientId,
      plan: payload.plan,
      maxPageSize: payload.plan === "paid" ? 10000 : 50,
      allowFull: payload.plan === "paid",
    });

    return {
      access_token: accessToken,
      token_type: "bearer",
    };
  }

  async exchangeRefreshToken(): Promise<OAuthTokens> {
    throw new Error("不支持 refresh token");
  }

  async verifyAccessToken(token: string): Promise<AuthInfo> {
    const payload = await verifyToken(this.secrets, token);
    return {
      token,
      clientId: payload.clientId,
      scopes: payload.scopes,
      expiresAt: payload.exp,
      extra: {
        baseURL: payload.baseURL,
        apiKey: payload.apiKey,
        email: payload.email,
        webToken: payload.webToken,
        webPrivateKey: payload.webPrivateKey,
        userId: payload.userId,
        plan: payload.plan,
        maxPageSize: payload.maxPageSize,
        allowFull: payload.allowFull,
      },
    };
  }
}
