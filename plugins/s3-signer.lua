-- /opt/apisix/plugins/apisix/plugins/s3-signer.lua

local core = require("apisix.core")
local cjson = require('cjson')

local resty_sha256 = require('resty.sha256')
local str = require('resty.string')

local hmac_sha256 = ngx.hmac_sha256

local plugin_name = "s3-signer"

local schema = {
    type = "object",
    required = {"access_key", "secret_key", "region", "service"},
    properties = {
        access_key = {type = "string"},
        secret_key = {type = "string"},
        region = {type = "string"},
        service = {type = "string", default = "s3"}
    }
}

local _M = {
    version = 0.1,
    priority = 1,
    name = plugin_name,
    schema = schema,
}

-- AWS S3 signing functions taken from:
-- https://github.com/jobteaser/lua-resty-aws-signature

local function get_iso8601_basic(timestamp)
    return os.date('!%Y%m%dT%H%M%SZ', timestamp)
end
  
local function get_iso8601_basic_short(timestamp)
    return os.date('!%Y%m%d', timestamp)
end
  
local function get_derived_signing_key(keys, timestamp, region, service)
    -- local h_date = resty_hmac:new('AWS4' .. keys['secret_key'], resty_hmac.ALGOS.SHA256)
    -- h_date:update(get_iso8601_basic_short(timestamp))
    -- k_date = h_date:final()

    local k_date = ngx.hmac_sha256("AWS4" .. keys["secret_key"], get_iso8601_basic_short(timestamp))

    -- local h_region = resty_hmac:new(k_date, resty_hmac.ALGOS.SHA256)
    -- h_region:update(region)
    -- k_region = h_region:final()

    local k_region = ngx.hmac_sha256(k_date, region)
  
    -- local h_service = resty_hmac:new(k_region, resty_hmac.ALGOS.SHA256)
    -- h_service:update(service)
    -- k_service = h_service:final()

    local k_service = ngx.hmac_sha256(k_region, service)
  
    -- local h = resty_hmac:new(k_service, resty_hmac.ALGOS.SHA256)
    -- h:update('aws4_request')
    -- return h:final()

    return ngx.hmac_sha256(k_service, 'aws4_request')
end
  
local function get_cred_scope(timestamp, region, service)
    return get_iso8601_basic_short(timestamp)
      .. '/' .. region
      .. '/' .. service
      .. '/aws4_request'
end
  
local function get_signed_headers()
    return 'host;x-amz-content-sha256;x-amz-date'
end
  
local function get_sha256_digest(s)
    local h = resty_sha256:new()
    h:update(s or '')
    return str.to_hex(h:final())
end
  
local function get_hashed_canonical_request(timestamp, host, uri, body, method)
    local digest = get_sha256_digest(body)
    local canonical_request = method .. '\n'
      .. uri .. '\n'
      .. '\n'
      .. 'host:' .. host .. '\n'
      .. 'x-amz-content-sha256:' .. digest .. '\n'
      .. 'x-amz-date:' .. get_iso8601_basic(timestamp) .. '\n'
      .. '\n'
      .. get_signed_headers() .. '\n'
      .. digest
    return get_sha256_digest(canonical_request)
end
  
local function get_string_to_sign(timestamp, region, service, host, uri, body, method)
    return 'AWS4-HMAC-SHA256\n'
      .. get_iso8601_basic(timestamp) .. '\n'
      .. get_cred_scope(timestamp, region, service) .. '\n'
      .. get_hashed_canonical_request(timestamp, host, uri, body, method)
end

local function get_signature(derived_signing_key, string_to_sign)
    -- local h = resty_hmac:new(derived_signing_key, resty_hmac.ALGOS.SHA256)
    -- h:update(string_to_sign)
    -- return h:final(nil, true)

    local signature_bin = ngx.hmac_sha256(derived_signing_key, string_to_sign)
    local signature_hex = require("resty.string").to_hex(signature_bin)
    return signature_hex
end
  
local function get_authorization(keys, timestamp, region, service, host, uri, body, method)
    local derived_signing_key = get_derived_signing_key(keys, timestamp, region, service)
    local string_to_sign = get_string_to_sign(timestamp, region, service, host, uri, body, method)
    local auth = 'AWS4-HMAC-SHA256 '
      .. 'Credential=' .. keys['access_key'] .. '/' .. get_cred_scope(timestamp, region, service)
      .. ', SignedHeaders=' .. get_signed_headers()
      .. ', Signature=' .. get_signature(derived_signing_key, string_to_sign)
    return auth
end
------------------------------------- 

local function get_s3_headers(args)
    local access_key = args.access_key
    local secret_key = args.secret_key

    local method = args.method
    local body = args.body

    local timestamp = tonumber(ngx.time())
    local service = args.service
    local region = args.region
    local host = args.host
    local uri = args.uri
    local body = args.body

    local creds = {
        access_key = access_key,
        secret_key = secret_key
    }

    local auth = get_authorization(creds, timestamp, region, service, host, uri, body, method)

    local headers = {
        ['Authorization'] = auth,
        ['x-amz-date'] = get_iso8601_basic(timestamp),
        ['x-amz-content-sha256'] = get_sha256_digest(body),
    }

    return headers
end

------ plugin methods

function _M.check_schema(conf)
    return core.schema.check(schema, conf)
end
  
function _M.access(conf, ctx)
    local req_method = core.request.get_method()
    local req_uri = ngx.var.request_uri
    local req_query = ngx.var.args
    local req_headers = ngx.req.get_headers()
    local req_body = nil

    if req_method ~= "GET" and req_method ~= "HEAD" then
        ngx.req.read_body()
        req_body = ngx.req.get_body_data()
    end

    -- Create signer input
    local signing_input = {
        method = req_method,
        uri = core.request.get_full_path(),
        headers = req_headers,
        body = req_body,
        query = req_query,
        region = conf.region,
        service = conf.service,
        access_key = conf.access_key,
        secret_key = conf.secret_key,
        session_token = conf.session_token
    }

    -- Sign the request (replace with actual signing implementation)
    local signed_headers = get_s3_headers(signing_input)

    -- Apply signed headers to upstream
    for k, v in pairs(signed_headers) do
        core.request.set_header(ctx, k, v)
    end
end

return _M
