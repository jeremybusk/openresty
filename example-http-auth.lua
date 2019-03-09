-- apt-get install -y lua-cjson lua-nginx lua-nginx-redis lua-nginx-string lua-scrypt nginx redis lua-rex-pcre
-- add this file in /etc/nginx/lua dir
-- add to nginx.conf under http
-- http {
--    lua_package_path "/etc/nginx/lua/?.lua;;";

-- add to server config
--    location /secureroute {
--        default_type 'text/plain';
--        access_by_lua_block {
--           local simpleauth = require "simpleauth"
--            simpleauth.proxyauth()
--        }
--        client_max_body_size 100m;
--        proxy_set_header Host $host;
--        proxy_pass http:/somehost.example.org:80/;
--    }



local simpleauth = {}

function simpleauth.proxyauth()
    if ngx.var.http_authorization == nil then
        ngx.status = 401
        ngx.say('Missing http authorization.')
        ngx.exit(401)
    end 

    s = string.match(ngx.var.http_authorization, '%S-$')
    local user_pass = ngx.decode_base64(s)
    username = string.match(user_pass, '(.*):')
    local nginx_sha256 = require "nginx.sha256"
    local str = require "nginx.string"
    local sha256 = nginx_sha256:new()
    sha256:update(ngx.var.http_authorization)
    local digest = sha256:final()
    local http_authorization_sha256 = str.to_hex(digest)
    -- local scrypt = require "scrypt"  -- more secure but more resource intensive  

    local redis = require "nginx.redis"
    local rdb = redis:new()
    rdb:set_timeout(1000) -- 1 sec
    local ok, err = rdb:connect("127.0.0.1", 6379)
    if not ok then
        ngx.say("failed to connect: ", err)
        return
    end 
    local db_http_authorization_sha256,err = rdb:hget(username, "http_authorization_sha256")

    if db_http_authorization_sha256 ~= http_authorization_sha256 then
        ngx.status = 401
        ngx.say("Failed http authorization.")
        ngx.exit(401)
    end 
end
return simpleauth
