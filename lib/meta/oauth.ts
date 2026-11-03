import {
  createCipheriv,
  createDecipheriv,
  createHmac,
  randomBytes,
  timingSafeEqual,
} from "crypto";
import {
  getEncryptionKeyHex,
  getMetaGraphApiVersion,
  requireEnv,
} from "@/lib/env";
import { isFacebookLoginMode } from "@/lib/meta/login-mode";

// Instagram API with Instagram Login authorizes on www.instagram.com. The old
// api.instagram.com/oauth/authorize host belonged to the retired Basic Display
// API and now 404s ("Sorry, this page isn't available"), which looks like a bad
// link rather than a wrong endpoint. The token exchange below still lives on
// api.instagram.com — only the authorize hop moved.
const INSTAGRAM_OAUTH_URL = "https://www.instagram.com/oauth/authorize";
const INSTAGRAM_TOKEN_URL = "https://api.instagram.com/oauth/access_token";
const ALGORITHM = "aes-256-gcm";
const IV_LENGTH = 16;
const AUTH_TAG_LENGTH = 16;
const STATE_MAX_AGE_MS = 10 * 60 * 1000;

interface OAuthStatePayload {
  workspaceId: string;
  ts: number;
}

function base64UrlEncode(value: string): string {
  return Buffer.from(value).toString("base64url");
}

function base64UrlDecode(value: string): string {
  return Buffer.from(value, "base64url").toString("utf8");
}

function signState(payload: string): string {
  return createHmac("sha256", requireEnv("NEXTAUTH_SECRET"))
    .update(payload)
    .digest("base64url");
}

export function createOAuthState(workspaceId: string): string {
  const payload = base64UrlEncode(
    JSON.stringify({ workspaceId, ts: Date.now() } satisfies OAuthStatePayload)
  );
  return `${payload}.${signState(payload)}`;
}

export function verifyOAuthState(state: string | null): OAuthStatePayload | null {
  if (!state) return null;

  const [payload, signature] = state.split(".");
  if (!payload || !signature) return null;

  const expected = signState(payload);
  const signatureBuffer = Buffer.from(signature);
  const expectedBuffer = Buffer.from(expected);

  if (
    signatureBuffer.length !== expectedBuffer.length ||
    !timingSafeEqual(signatureBuffer, expectedBuffer)
  ) {
    return null;
  }

  try {
    const parsed = JSON.parse(base64UrlDecode(payload)) as OAuthStatePayload;
    if (typeof parsed.workspaceId !== "string" || !parsed.workspaceId) {
      return null;
    }

    // Reject a missing or non-numeric timestamp. `Date.now() - "abc"` is NaN,
    // and every comparison against NaN is false, so a non-numeric ts would
    // otherwise pass the age check and never expire. A ts in the future is
    // rejected for the same reason: it has not aged at all.
    if (typeof parsed.ts !== "number" || !Number.isFinite(parsed.ts)) {
      return null;
    }

    const age = Date.now() - parsed.ts;
    if (age < 0 || age > STATE_MAX_AGE_MS) {
      return null;
    }

    return parsed;
  } catch {
    return null;
  }
}

// Facebook Login (Unified login) scopes for the Instagram API. Used only when
// no Facebook Login for Business configuration ID is set; a configuration
// carries its own permission list.
const FACEBOOK_LOGIN_SCOPES = [
  "instagram_basic",
  "instagram_manage_comments",
  "instagram_manage_messages",
  "instagram_manage_insights",
  "pages_show_list",
  "pages_read_engagement",
  "pages_manage_metadata",
  "business_management",
].join(",");

function facebookGraphBase(): string {
  return `https://graph.facebook.com/${getMetaGraphApiVersion()}`;
}

function getFacebookAuthorizationUrl(redirectUri: string, state: string): string {
  const params = new URLSearchParams({
    client_id: requireEnv("INSTAGRAM_APP_ID"),
    redirect_uri: redirectUri,
    response_type: "code",
    state,
  });
  const configId = process.env.FACEBOOK_LOGIN_CONFIG_ID?.trim();
  if (configId) {
    params.set("config_id", configId);
    params.set("override_default_response_type", "true");
  } else {
    params.set("scope", FACEBOOK_LOGIN_SCOPES);
  }
  return `https://www.facebook.com/${getMetaGraphApiVersion()}/dialog/oauth?${params.toString()}`;
}

async function readGraphJson<T>(response: Response, step: string): Promise<T> {
  const data = await response.json().catch(() => ({}));
  if (!response.ok || data?.error) {
    const message = data?.error?.message ?? JSON.stringify(data);
    throw new Error(`${step} failed: ${message}`);
  }
  return data as T;
}

interface FacebookPage {
  id: string;
  name?: string;
  access_token?: string;
  instagram_business_account?: { id: string; username?: string };
}

/**
 * Pick the Page whose linked Instagram account should be connected. With
 * META_INSTAGRAM_USERNAME set, only that account is accepted, so a person who
 * manages several Pages cannot connect the wrong one by accident.
 */
export function selectInstagramPage(
  pages: FacebookPage[],
  wantedUsername?: string
): FacebookPage & { access_token: string; instagram_business_account: { id: string } } {
  const candidates = pages.filter(
    (page) => page.access_token && page.instagram_business_account?.id
  ) as Array<
    FacebookPage & { access_token: string; instagram_business_account: { id: string; username?: string } }
  >;
  const wanted = wantedUsername?.trim().replace(/^@/, "").toLowerCase();
  if (wanted) {
    const match = candidates.find(
      (page) => page.instagram_business_account.username?.toLowerCase() === wanted
    );
    if (!match) {
      throw new Error(
        `No Facebook Page you granted is linked to the Instagram account @${wanted}`
      );
    }
    return match;
  }
  if (candidates.length === 0) {
    throw new Error(
      "None of the Facebook Pages you granted has a linked Instagram professional account"
    );
  }
  return candidates[0];
}

async function exchangeFacebookCode(
  code: string,
  redirectUri: string
): Promise<{ accessToken: string; userId: string }> {
  const clientId = requireEnv("INSTAGRAM_APP_ID");
  const clientSecret = requireEnv("INSTAGRAM_APP_SECRET");

  const codeUrl = new URL(`${facebookGraphBase()}/oauth/access_token`);
  codeUrl.searchParams.set("client_id", clientId);
  codeUrl.searchParams.set("client_secret", clientSecret);
  codeUrl.searchParams.set("redirect_uri", redirectUri);
  codeUrl.searchParams.set("code", code);
  const short = await readGraphJson<{ access_token: string }>(
    await fetch(codeUrl.toString()),
    "Token exchange"
  );

  // A Page token derived from a long-lived user token never expires. System
  // user tokens from a Business login configuration are already long-lived and
  // may refuse this exchange, so fall back to the token we have.
  let userToken = short.access_token;
  try {
    const longUrl = new URL(`${facebookGraphBase()}/oauth/access_token`);
    longUrl.searchParams.set("grant_type", "fb_exchange_token");
    longUrl.searchParams.set("client_id", clientId);
    longUrl.searchParams.set("client_secret", clientSecret);
    longUrl.searchParams.set("fb_exchange_token", short.access_token);
    const long = await readGraphJson<{ access_token: string }>(
      await fetch(longUrl.toString()),
      "Long-lived token exchange"
    );
    userToken = long.access_token;
  } catch (error) {
    console.warn("[OAuth] Long-lived exchange skipped:", error);
  }

  const pagesUrl = new URL(`${facebookGraphBase()}/me/accounts`);
  pagesUrl.searchParams.set(
    "fields",
    "id,name,access_token,instagram_business_account{id,username}"
  );
  pagesUrl.searchParams.set("limit", "100");
  pagesUrl.searchParams.set("access_token", userToken);
  const pages = await readGraphJson<{ data?: FacebookPage[] }>(
    await fetch(pagesUrl.toString()),
    "Listing Facebook Pages"
  );

  const page = selectInstagramPage(
    pages.data ?? [],
    process.env.META_INSTAGRAM_USERNAME
  );
  return {
    accessToken: page.access_token,
    userId: page.instagram_business_account.id,
  };
}

export function getAuthorizationUrl(redirectUri: string, state: string): string {
  if (isFacebookLoginMode()) return getFacebookAuthorizationUrl(redirectUri, state);
  const params = new URLSearchParams({
    client_id: requireEnv("INSTAGRAM_APP_ID"),
    redirect_uri: redirectUri,
    scope:
      "instagram_business_basic,instagram_business_manage_messages,instagram_business_manage_comments,instagram_business_manage_insights",
    response_type: "code",
    state,
  });

  return `${INSTAGRAM_OAUTH_URL}?${params.toString()}`;
}

export async function exchangeCodeForToken(
  code: string,
  redirectUri: string
): Promise<{ accessToken: string; userId: string }> {
  if (isFacebookLoginMode()) return exchangeFacebookCode(code, redirectUri);
  const body = new URLSearchParams({
    client_id: requireEnv("INSTAGRAM_APP_ID"),
    client_secret: requireEnv("INSTAGRAM_APP_SECRET"),
    grant_type: "authorization_code",
    redirect_uri: redirectUri,
    code,
  });

  const response = await fetch(INSTAGRAM_TOKEN_URL, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: body.toString(),
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(
      `Token exchange failed: ${error.error_message || JSON.stringify(error)}`
    );
  }

  const data = await response.json();
  return {
    accessToken: data.access_token,
    userId: String(data.user_id),
  };
}

function getEncryptionKey(): Buffer {
  return Buffer.from(getEncryptionKeyHex(), "hex");
}

export function encryptToken(plaintext: string): string {
  const key = getEncryptionKey();
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv(ALGORITHM, key, iv);

  const encrypted = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();
  const combined = Buffer.concat([iv, authTag, encrypted]);

  return combined.toString("base64");
}

export function decryptToken(encryptedBase64: string): string {
  const key = getEncryptionKey();
  const combined = Buffer.from(encryptedBase64, "base64");

  const iv = combined.subarray(0, IV_LENGTH);
  const authTag = combined.subarray(IV_LENGTH, IV_LENGTH + AUTH_TAG_LENGTH);
  const ciphertext = combined.subarray(IV_LENGTH + AUTH_TAG_LENGTH);

  const decipher = createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(authTag);

  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString(
    "utf8"
  );
}
