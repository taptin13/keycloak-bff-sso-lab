local typedefs = require "kong.db.schema.typedefs"

return {
  name = "keycloak-jwks",
  fields = {
    { consumer = typedefs.no_consumer },
    { protocols = typedefs.protocols_http },
    {
      config = {
        type = "record",
        fields = {
          { issuer = { type = "string", required = true } },
          { jwks_uri = { type = "string", required = true } },
          { audience = { type = "string", required = true } },
          { cache_ttl = { type = "integer", default = 300, between = { 30, 3600 } } },
          { clock_skew = { type = "integer", default = 30, between = { 0, 300 } } },
        },
      },
    },
  },
}
