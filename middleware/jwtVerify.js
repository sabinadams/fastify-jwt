const JWT = require("jsonwebtoken");

module.exports = async (request, reply, _) => {
  const token = request.headers["x-auth"];
  if (!token) return reply.status(401).send("No authorization provided");

  await JWT.verify(
    token.split(" ")[1],
    process.env.ACCESS_TOKEN_SECRET,
    (err, decoded) => {
      if (err) return reply.status(403).send("Invalid access");
      request.userId = decoded.id;
    }
  );
};
