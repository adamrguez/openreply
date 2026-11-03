import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  exchangeCodeForToken,
  getAuthorizationUrl,
  selectInstagramPage,
} from "../lib/meta/oauth";
import {
  getLongLivedToken,
  getUserInfo,
  getUserMedia,
  sendPrivateReply,
  subscribeInstagramAccountToWebhooks,
} from "../lib/meta/client";

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

beforeEach(() => {
  vi.stubEnv("META_LOGIN_MODE", "facebook");
  vi.stubEnv("META_GRAPH_API_VERSION", "v25.0");
  vi.stubEnv("INSTAGRAM_APP_ID", "1058696797185649");
  vi.stubEnv("INSTAGRAM_APP_SECRET", "app-secret");
});

afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

describe("Facebook Login mode", () => {
  it("builds a Facebook dialog URL with Instagram scopes", () => {
    const url = new URL(getAuthorizationUrl("https://dm.example.com/cb", "st"));
    expect(url.origin + url.pathname).toBe(
      "https://www.facebook.com/v25.0/dialog/oauth"
    );
    expect(url.searchParams.get("client_id")).toBe("1058696797185649");
    expect(url.searchParams.get("scope")).toContain("instagram_manage_comments");
    expect(url.searchParams.get("scope")).toContain("pages_manage_metadata");
  });

  it("uses a Business login configuration when one is set", () => {
    vi.stubEnv("FACEBOOK_LOGIN_CONFIG_ID", "987");
    const url = new URL(getAuthorizationUrl("https://dm.example.com/cb", "st"));
    expect(url.searchParams.get("config_id")).toBe("987");
    expect(url.searchParams.get("scope")).toBeNull();
  });

  it("stays on Instagram Login when the mode is not set", () => {
    vi.stubEnv("META_LOGIN_MODE", "");
    expect(getAuthorizationUrl("https://x/cb", "st")).toMatch(
      /^https:\/\/www\.instagram\.com\/oauth\/authorize\?/
    );
  });

  it("exchanges the code for the Page token of the linked Instagram account", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = new URL(String(input));
      if (url.pathname.endsWith("/oauth/access_token")) {
        return url.searchParams.get("grant_type") === "fb_exchange_token"
          ? json({ access_token: "long-user" })
          : json({ access_token: "short-user" });
      }
      if (url.pathname.endsWith("/me/accounts")) {
        expect(url.searchParams.get("access_token")).toBe("long-user");
        return json({
          data: [
            { id: "p1", access_token: "page-no-ig" },
            {
              id: "p2",
              access_token: "page-token",
              instagram_business_account: { id: "1784", username: "refreshtaller" },
            },
          ],
        });
      }
      throw new Error(`unexpected ${url}`);
    });
    vi.stubGlobal("fetch", fetchMock);

    await expect(exchangeCodeForToken("code", "https://x/cb")).resolves.toEqual({
      accessToken: "page-token",
      userId: "1784",
    });
  });

  it("only accepts the configured Instagram username", () => {
    const pages = [
      {
        id: "a",
        access_token: "t1",
        instagram_business_account: { id: "1", username: "otra" },
      },
      {
        id: "b",
        access_token: "t2",
        instagram_business_account: { id: "2", username: "RefreshTaller" },
      },
    ];
    expect(selectInstagramPage(pages, "@refreshtaller").id).toBe("b");
    expect(() => selectInstagramPage(pages, "nadie")).toThrow(/@nadie/);
  });

  it("keeps the Page token as a non-expiring token", async () => {
    await expect(getLongLivedToken("page-token")).resolves.toEqual({
      accessToken: "page-token",
      expiresIn: 0,
    });
  });

  it("reads the account and media through the linked Instagram account", async () => {
    const calls: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = new URL(String(input));
        calls.push(url.pathname);
        if (url.pathname === "/v25.0/me") {
          return json({
            instagram_business_account: { id: "1784", username: "refreshtaller" },
          });
        }
        if (url.pathname === "/v25.0/1784/media") return json({ data: [{ id: "m1" }] });
        throw new Error(`unexpected ${url}`);
      })
    );

    const info = await getUserInfo("page-token-x");
    expect(info).toMatchObject({ id: "1784", user_id: "1784", username: "refreshtaller" });
    const media = await getUserMedia("page-token-x");
    expect(media).toEqual([{ id: "m1" }]);
    expect(calls.every((path) => path.startsWith("/v25.0/"))).toBe(true);
  });

  it("sends private replies and subscribes webhooks through the Page", async () => {
    const requests: Array<{ url: string; body: unknown }> = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        requests.push({ url: String(input), body: JSON.parse(String(init?.body)) });
        return json({ recipient_id: "u", message_id: "m", success: true });
      })
    );

    await sendPrivateReply("page-token", "1784", "c1", "Aquí tienes el enlace");
    await subscribeInstagramAccountToWebhooks("1784", "page-token");

    expect(requests[0].url).toBe("https://graph.facebook.com/v25.0/me/messages");
    expect(requests[0].body).toEqual({
      recipient: { comment_id: "c1" },
      message: { text: "Aquí tienes el enlace" },
    });
    expect(requests[1].url).toBe(
      "https://graph.facebook.com/v25.0/me/subscribed_apps"
    );
  });

  it("falls back to the feed field when messaging permissions are missing", async () => {
    const bodies: unknown[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
        const body = JSON.parse(String(init?.body));
        bodies.push(body);
        if (body.subscribed_fields.length > 1) {
          return json(
            { error: { message: "needs pages_messaging", type: "OAuthException", code: 200 } },
            403
          );
        }
        return json({ success: true });
      })
    );

    await expect(
      subscribeInstagramAccountToWebhooks("1784", "page-token")
    ).resolves.toEqual({ success: true });
    expect(bodies).toEqual([
      { subscribed_fields: ["feed", "messages", "messaging_postbacks"] },
      { subscribed_fields: ["feed"] },
    ]);
  });
});
