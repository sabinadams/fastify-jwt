const fp = require("fastify-plugin");

module.exports = fp((fastify, _, done) => {
  fastify.addSchema({
    $id: "PostAuthenticationBody",
    type: "object",
    required: ["email", "password"],
    properties: {
      email: { type: "string" },
      password: { type: "string" },
    },
  });

  fastify.addSchema({
    $id: "RefreshRouteHeaders",
    type: "object",
    properties: {
      "x-refresh-token": { type: "string" },
    },
    required: ["x-refresh-token"],
  });

  fastify.addSchema({
    $id: "AccessTokenHeaders",
    type: "object",
    properties: {
      "x-auth": { type: "string" },
    },
    required: ["x-auth"],
  });
  done();
});
