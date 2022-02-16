const fastify = require("fastify")({ logger: true });
const jwt = require("./middleware/jwtVerify");

// Plugins
fastify.register(require("fastify-cookie"));
fastify.register(require("./schemas/auth"));

// Auth Routes
fastify.register(require("./routes/auth"), { prefix: "auth" });

// Protected routes
fastify.register((instance, opts, done) => {
  instance
    .decorate("verifyAccessToken", jwt)
    .register(require("fastify-auth"))
    .after(() => {
      instance.addHook(
        "preHandler",
        instance.auth([instance.verifyAccessToken])
      );

      instance.get(
        "/test",
        { schema: { headers: instance.getSchema("AccessTokenHeaders") } },
        async (request, reply, next) => {
          return {
            hello: "World",
          };
        }
      );
    });
  done();
});

// Run the server!
const start = async () => {
  try {
    await fastify.listen(3000);
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};

start();
