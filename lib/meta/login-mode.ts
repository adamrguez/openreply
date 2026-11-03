/**
 * Which Meta login the direct (non-Zernio) connection uses.
 *
 * "instagram" (default): Instagram API with Instagram Login. Tokens are
 * Instagram user tokens and every call goes to graph.instagram.com.
 *
 * "facebook": Instagram API with Facebook Login (Meta's "Unified login" /
 * Facebook Login for Business). Meta no longer offers Instagram Login on newly
 * created apps, so new apps have to use this path. The stored token is the
 * Page access token of the Facebook Page linked to the Instagram professional
 * account, and every call goes to graph.facebook.com. INSTAGRAM_APP_ID and
 * INSTAGRAM_APP_SECRET then hold the Facebook app's ID and secret.
 */
export function isFacebookLoginMode(): boolean {
  return (process.env.META_LOGIN_MODE ?? "").trim().toLowerCase() === "facebook";
}
