-- LDAP group authorization for nginx-auth-spnego.
--
-- Place this file at /etc/nginx/lua/ldap_authz.lua and reference it from
-- your nginx location block:
--
--   location /protected {
--       auth_gss on;
--       auth_gss_format_full on;
--       access_by_lua_file /etc/nginx/lua/ldap_authz.lua;
--   }
--
-- Requires lua-resty-ldap (https://github.com/api7/lua-resty-ldap).
--
-- SPNEGO authentication always runs first because access_by_lua_file is
-- postponed to the end of the access phase by default.  Cookie-based
-- requests (krb5_auth_type == "cookie") skip the LDAP lookup since the
-- group check was already performed on the initial SPNEGO login.

local ldap_client = require "resty.ldap.client"

-- Configuration: adjust these values to match your environment.
local LDAP_HOST    = "127.0.0.1"
local LDAP_PORT    = 389
local BIND_DN      = "uid=http,ou=Services,dc=example,dc=com"
local BIND_PW      = "httptest"
local PEOPLE_BASE  = "ou=People,dc=example,dc=com"
local GROUP_DN     = "cn=webusers,ou=Groups,dc=example,dc=com"

local user = ngx.var.remote_user

if not user or user == "" then
    return ngx.exit(ngx.HTTP_UNAUTHORIZED)
end

-- Cookie auth means the LDAP check was already done on the initial login;
-- skip redundant group lookup.
if ngx.var.krb5_auth_type == "cookie" then
    return
end

local client, err = ldap_client:new(LDAP_HOST, LDAP_PORT, {
    socket_timeout    = 5000,
    keepalive_timeout = 60000,
    keepalive_pool_size = 2,
})
if not client then
    ngx.log(ngx.ERR, "LDAP client init failed: ", err)
    return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
end

local ok, err = client:simple_bind(BIND_DN, BIND_PW)
if not ok then
    ngx.log(ngx.ERR, "LDAP bind failed: ", err)
    return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
end

local result, err = client:search(
    PEOPLE_BASE,
    2, 0, 1, 5, false,
    "(&(krbPrincipalName=" .. user .. ")(memberOf=" .. GROUP_DN .. "))",
    {"uid"}
)
if not result then
    ngx.log(ngx.ERR, "LDAP authz search failed: ", err)
    return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
end

if #result == 0 then
    ngx.log(ngx.ERR, "LDAP authz denied for '", user, "': not in ", GROUP_DN)
    return ngx.exit(ngx.HTTP_FORBIDDEN)
end
