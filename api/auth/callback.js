
const crypto = require("crypto");

function makeSession(user) {
  const payload = Buffer.from(JSON.stringify({
    id: user.id,
    username: user.username,
    avatar: user.avatar,
    exp: Date.now() + 7 * 24 * 60 * 60 * 1000
  })).toString("base64url");

  const signature = crypto
    .createHmac("sha256", process.env.SESSION_SECRET)
    .update(payload)
    .digest("base64url");

  return `${payload}.${signature}`;
}

module.exports = async (req, res) => {
  try {
    const cookies = Object.fromEntries(
      (req.headers.cookie || "").split(";").filter(Boolean).map(c => {
        const i = c.indexOf("=");
        return [c.slice(0, i).trim(), decodeURIComponent(c.slice(i + 1).trim())];
      })
    );

    const state = new URL(req.url, "https://example.com").searchParams.get("state");
    const code = new URL(req.url, "https://example.com").searchParams.get("code");

    if (!state || !code || state !== cookies.discord_oauth_state) {
      return res.status(400).send("Invalid OAuth state.");
    }

    const tokenResponse = await fetch("https://discord.com/api/oauth2/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: process.env.DISCORD_CLIENT_ID,
        client_secret: process.env.DISCORD_CLIENT_SECRET,
        grant_type: "authorization_code",
        code,
        redirect_uri: process.env.DISCORD_REDIRECT_URI
      })
    });

    const token = await tokenResponse.json();
    if (!tokenResponse.ok || !token.access_token) {
      return res.status(400).send("Discord token exchange failed.");
    }

    const userResponse = await fetch("https://discord.com/api/users/@me", {
      headers: { Authorization: `Bearer ${token.access_token}` }
    });

    const user = await userResponse.json();
    if (!userResponse.ok || !user.id || !process.env.SESSION_SECRET) {
      return res.status(400).send("Could not retrieve Discord account.");
    }

    const session = makeSession(user);

    res.setHeader("Set-Cookie", [
      "discord_oauth_state=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0",
      `discord_session=${session}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=604800`
    ]);

    res.writeHead(302, { Location: "/" });
    res.end();
  } catch (error) {
    res.status(500).send("Discord login failed.");
  }
};
        
