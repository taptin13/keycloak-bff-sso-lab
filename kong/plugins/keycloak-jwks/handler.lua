local cjson = require "cjson.safe"
local http = require "resty.http"
local jwt = require "resty.jwt"

local KeycloakJwks = {
  PRIORITY = 1005,
  VERSION = "1.0.0",
}

local function unauthorized()
  return kong.response.exit(401, { message = "Unauthorized" }, {
    ["WWW-Authenticate"] = 'Bearer realm="api"',
  })
end

local function fetch_jwks(conf)
  local cache_key = "keycloak-jwks:" .. conf.jwks_uri
  local jwks, err = kong.cache:get(cache_key, { ttl = conf.cache_ttl, neg_ttl = 30 }, function()
    local client = http.new()
    client:set_timeout(3000)
    local response, request_err = client:request_uri(conf.jwks_uri, {
      method = "GET",
      headers = { Accept = "application/json" },
      ssl_verify = true,
    })
    if not response then
      return nil, "JWKS request failed: " .. (request_err or "unknown error")
    end
    if response.status ~= 200 then
      return nil, "JWKS endpoint returned status " .. response.status
    end
    if #response.body > 1048576 then
      return nil, "JWKS response exceeds the 1 MiB limit"
    end

    local decoded, decode_err = cjson.decode(response.body)
    if not decoded or type(decoded.keys) ~= "table" then
      return nil, "Invalid JWKS response: " .. (decode_err or "missing keys")
    end
    return decoded
  end)

  if not jwks then
    return nil, err
  end
  return jwks, cache_key
end

local function find_signing_key(jwks, kid)
  for _, key in ipairs(jwks.keys) do
    if key.kid == kid and key.kty == "RSA" and key.use == "sig"
        and (key.alg == nil or key.alg == "RS256")
        and type(key.x5c) == "table" and type(key.x5c[1]) == "string" then
      return "-----BEGIN CERTIFICATE-----\n"
          .. key.x5c[1]
          .. "\n-----END CERTIFICATE-----\n"
    end
  end
end

local function has_expected_audience(aud, expected)
  if type(aud) == "string" then
    return aud == expected
  end
  if type(aud) == "table" then
    for _, value in ipairs(aud) do
      if value == expected then
        return true
      end
    end
  end
  return false
end

local function get_bearer_token()
  local authorization = kong.request.get_header("authorization")
  if type(authorization) ~= "string" then
    return nil
  end
  local scheme, token = authorization:match("^(%S+)%s+(.+)$")
  if scheme and scheme:lower() == "bearer" then
    return token
  end
end

local function verify_access_token(conf, token)
  if type(token) ~= "string" or #token > 16384 then
    return false, "missing or oversized access token"
  end

  local parsed = jwt:load_jwt(token)
  if not parsed.valid or type(parsed.header) ~= "table" or type(parsed.payload) ~= "table" then
    return false, "malformed JWT"
  end
  if parsed.header.alg ~= "RS256" or type(parsed.header.kid) ~= "string" then
    return false, "unexpected signing algorithm or missing key id"
  end

  local jwks, cache_key_or_err = fetch_jwks(conf)
  if not jwks then
    kong.log.err(cache_key_or_err)
    return false, "unable to load signing keys"
  end

  local signing_key = find_signing_key(jwks, parsed.header.kid)
  if not signing_key then
    kong.cache:invalidate(cache_key_or_err)
    jwks = fetch_jwks(conf)
    if jwks then
      signing_key = find_signing_key(jwks, parsed.header.kid)
    end
  end
  if not signing_key then
    return false, "unknown signing key"
  end

  local verified = jwt:verify(signing_key, token)
  if not verified.verified then
    return false, "invalid JWT signature"
  end

  local claims = parsed.payload
  local now = ngx.time()
  if claims.iss ~= conf.issuer then
    return false, "issuer mismatch"
  end
  if not has_expected_audience(claims.aud, conf.audience) then
    return false, "audience mismatch"
  end
  if type(claims.exp) ~= "number" or claims.exp <= now - conf.clock_skew then
    return false, "expired or missing expiration"
  end
  if claims.nbf ~= nil and (type(claims.nbf) ~= "number" or claims.nbf > now + conf.clock_skew) then
    return false, "token is not active"
  end
  if claims.iat ~= nil and (type(claims.iat) ~= "number" or claims.iat > now + conf.clock_skew) then
    return false, "issued-at time is in the future"
  end

  return true
end

function KeycloakJwks:access(conf)
  local token = get_bearer_token()
  local valid, reason = verify_access_token(conf, token)
  if not valid then
    kong.log.debug("JWT authentication rejected: ", reason)
    return unauthorized()
  end

  kong.service.request.clear_header("Cookie")
  kong.service.request.set_header("Authorization", "Bearer " .. token)
end

return KeycloakJwks
