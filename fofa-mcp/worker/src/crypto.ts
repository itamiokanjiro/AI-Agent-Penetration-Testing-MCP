import { EncryptJWT, jwtDecrypt, SignJWT, jwtVerify } from "jose";

export interface ServerSecrets {
  jweKey: Uint8Array;
  jwsKey: Uint8Array;
}

export interface CodePayload {
  baseURL: string;
  apiKey: string;
  email: string;
  webToken?: string;
  webPrivateKey?: string;
  codeChallenge: string;
  codeChallengeMethod: string;
  clientId: string;
  redirectUri: string;
  plan: "free" | "paid";
}

export interface TokenPayload {
  baseURL: string;
  apiKey: string;
  email: string;
  webToken?: string;
  webPrivateKey?: string;
  clientId: string;
  userId: string;
  plan: "free" | "paid";
  maxPageSize: number;
  allowFull: boolean;
}

export function loadSecrets(env: Record<string, string | undefined>): ServerSecrets {
  const jweEnv = env.JWE_SECRET;
  const jwsEnv = env.JWS_SECRET;

  let jweKey: Uint8Array;
  let jwsKey: Uint8Array;

  if (jweEnv) {
    const buf = Uint8Array.from(atob(jweEnv), (c) => c.charCodeAt(0));
    if (buf.length !== 32) throw new Error("JWE_SECRET 必须是 32 字节 base64");
    jweKey = buf;
  } else {
    jweKey = crypto.getRandomValues(new Uint8Array(32));
  }

  if (jwsEnv) {
    const buf = Uint8Array.from(atob(jwsEnv), (c) => c.charCodeAt(0));
    if (buf.length < 32) throw new Error("JWS_SECRET 至少 32 字节");
    jwsKey = buf;
  } else {
    jwsKey = crypto.getRandomValues(new Uint8Array(32));
  }

  return { jweKey, jwsKey };
}

export async function encryptCode(secrets: ServerSecrets, payload: CodePayload): Promise<string> {
  return new EncryptJWT(payload as unknown as Record<string, unknown>)
    .setProtectedHeader({ alg: "dir", enc: "A256GCM" })
    .setIssuedAt()
    .setExpirationTime("5m")
    .encrypt(secrets.jweKey);
}

export async function decryptCode(secrets: ServerSecrets, jwe: string): Promise<CodePayload> {
  const { payload } = await jwtDecrypt(jwe, secrets.jweKey);
  return payload as unknown as CodePayload;
}

export async function signToken(secrets: ServerSecrets, payload: TokenPayload): Promise<string> {
  const signed = await new SignJWT(payload as unknown as Record<string, unknown>)
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setExpirationTime("365d")
    .sign(secrets.jwsKey);
  return new EncryptJWT({ token: signed })
    .setProtectedHeader({ alg: "dir", enc: "A256GCM" })
    .setIssuedAt()
    .setExpirationTime("365d")
    .encrypt(secrets.jweKey);
}

export async function verifyToken(secrets: ServerSecrets, jws: string): Promise<TokenPayload & { exp: number }> {
  const outer = await jwtDecrypt(jws, secrets.jweKey);
  const signed = String(outer.payload.token || "");
  const { payload } = await jwtVerify(signed, secrets.jwsKey);
  return payload as unknown as TokenPayload & { exp: number };
}
