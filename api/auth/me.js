
const crypto = require("crypto");

module.exports = (req, res) => {
  const cookies = Object.fromEntries(
    (req.headers.cookie || "").split(";").filter(Boolean).map(c => {
      const i = c.indexOf("=");
      return [c.slice(0, i).trim(), decodeURIComponent(c.slice(i + 1).trim())];
    })
  );

  const session = cookies.discord_session;

  if (!session || !process.env.SESSION_SECRET) {
    return res.status(401).json({ loggedIn: false });
  }

  const [payload, signature] = session.split(".");

  if (!payload || !signature) {
    return res.status(401).json({ loggedIn: false });
  }

  const expected = crypto
    .createHmac("sha256", process.env.SESSION_SECRET)
    .update(payload)
    .digest("base64url");

  const a = Buffer.from(signature);
  const b = Buffer.from(expected);

  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return res.status(401).json({ loggedIn: false });
  }

  try {
    const user = JSON.parse(Buffer.from(payload, "base64url").toString());

    if (!user.id || !user.exp || user.exp < Date.now()) {
      return res.status(401).json({ loggedIn: false });
    }

    return res.status(200).json({
      loggedIn: true,
      user: {
        id: user.id,
        username: user.username,
        avatar: user.avatar
      }
    });
  } catch {
    return res.status(401).json({ loggedIn: false });
  }
};
