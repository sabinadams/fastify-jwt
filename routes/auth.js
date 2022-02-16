const bcrypt = require("bcrypt");
const JWT = require("jsonwebtoken");
const { PrismaClient } = require("@prisma/client");
const prisma = new PrismaClient();

module.exports = (fastify, _, done) => {
  fastify.post(
    "/signup",
    { schema: { body: fastify.getSchema("PostAuthenticationBody") } },
    async (request, reply) => {
      const { email, password } = request.body;

      // If a user already exists with the email, send error
      const usersWithEmail = await prisma.user.count({ where: { email } });
      if (usersWithEmail) {
        return reply.status(400).send("User with that email already exists.");
      }

      // Hash the password and create new user
      const hashedPassword = await bcrypt.hash(password, 10);
      await prisma.user.create({
        data: {
          email,
          password: hashedPassword,
        },
      });

      // Send success
      return reply.status(201).send();
    }
  );

  fastify.post(
    "/signin",
    {
      schema: {
        body: fastify.getSchema("PostAuthenticationBody"),
      },
    },
    async (request, reply) => {
      const { email, password } = request.body;

      // Fetch the user details by email
      const [{ password: userPassword, id }] = await prisma.user.findMany({
        select: {
          id: true,
          password: true,
        },
        where: { email },
      });

      // If no user found, must be invalid
      if (!id) {
        return reply.status(401).send("Invalid credentials");
      }

      // If password hashes don't match, must be invalid
      const validCredentials = await bcrypt.compare(password, userPassword);
      if (!validCredentials) {
        return reply.status(401).send("Invalid credentials");
      }

      // If user was found and passwords matched, create access & refresh tokens
      const [accessToken, refreshToken] = generateTokens(id, { id });

      // Store the refresh token so we can invalidate later on
      await storeRefreshToken(id, refreshToken);

      // Add refresh token to httpOnly cookie
      reply.setCookie("refresh", refreshToken, {
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000,
      });

      // Send back access token with refresh token in the httpOnly cookie
      return reply.status(200).send({ accessToken });
    }
  );

  fastify.post(
    "/refresh",
    { schema: { headers: fastify.getSchema("RefreshRouteHeaders") } },
    async (request, reply) => {
      // Check for refresh token in headers
      const token = request.headers["x-refresh-token"];

      // Get details from refresh token
      let id = null;
      try {
        id = JWT.verify(
          token,
          process.env.REFRESH_TOKEN_SECRET,
          (err, decoded) => {
            if (err) {
              throw err;
            }

            return decoded.id;
          }
        );
      } catch (e) {
        return reply.status(401).send("Invalid token");
      }

      // If no ID, token was invalid
      if (!id) {
        return reply.status(401).send("Invalid token");
      }

      // Check the token in the db
      const dbToken = await prisma.refreshTokens.findFirst({
        where: { subject: id.toString() },
      });

      // Token not in db! Maybe revoked? Tampered with?
      if (!dbToken || !(await bcrypt.compare(token, dbToken.hash))) {
        return reply.status(401).send("Token not found");
      }

      // Generate new tokens
      const [accessToken, refreshToken] = generateTokens(dbToken.id, {
        id: dbToken.id,
      });

      await storeRefreshToken(id, refreshToken);

      // Add refresh token to httpOnly cookie
      reply.setCookie("refresh", refreshToken, {
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000 * 7,
      });

      // Send back access token with refresh token in the httpOnly cookie
      return reply.status(200).send({ accessToken });
    }
  );

  done();
};

// This function allows us to rotate our tokens
const storeRefreshToken = async (subject, token) => {
  await prisma.refreshTokens.deleteMany({ where: { subject } });
  await prisma.refreshTokens.create({
    data: {
      hash: await bcrypt.hash(token, 10),
      subject,
    },
  });
};

// This function returns an accessToken and a refreshToken
const generateTokens = (subject, payload) => {
  return [
    JWT.sign(payload, process.env.ACCESS_TOKEN_SECRET, {
      expiresIn: "15min",
      subject: subject.toString(),
      issuer: "localhost",
    }),
    JWT.sign(payload, process.env.REFRESH_TOKEN_SECRET, {
      expiresIn: "7day",
      subject: subject.toString(),
      issuer: "localhost",
    }),
  ];
};
