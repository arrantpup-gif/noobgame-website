
module.exports = (req, res) => {
  res.setHeader("Set-Cookie", [
    "discord_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0"
  ]);

  res.writeHead(302, { Location: "/" });
  res.end();
};
