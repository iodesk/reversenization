local ssl = require "ngx.ssl"
local cache = ngx.shared.cert_cache

local host, err = ssl.server_name()

if not host then
    return
end

local cert_der = cache:get(host .. ":cert")
local key_der  = cache:get(host .. ":key")

if not cert_der or not key_der then
    local cert_path = "/opt/certs/" .. host .. "/fullchain.pem"
    local key_path  = "/opt/certs/" .. host .. "/key.pem"

    local function read_file(path)
        local f = io.open(path, "r")
        if not f then return nil end
        local content = f:read("*a")
        f:close()
        return content
    end

    local cert_pem = read_file(cert_path)
    local key_pem  = read_file(key_path)

    if not cert_pem or not key_pem then
        cert_path = "/opt/certs/default/fullchain.pem"
        key_path  = "/opt/certs/default/key.pem"
        cert_pem = read_file(cert_path)
        key_pem  = read_file(key_path)
    end

    if cert_pem and key_pem then
        cert_der, err = ssl.parse_pem_cert(cert_pem)
        if not cert_der then
            ngx.log(ngx.ERR, "SSL: failed to parse cert for ", host, ": ", err)
            return
        end

        key_der, err = ssl.parse_pem_priv_key(key_pem)
        if not key_der then
            ngx.log(ngx.ERR, "SSL: failed to parse key for ", host, ": ", err)
            return
        end

        cache:set(host .. ":cert", cert_der, 3600)
        cache:set(host .. ":key", key_der, 3600)
    else
        ngx.log(ngx.ERR, "SSL: could not read cert/key files for ", host, " at ", cert_path)
        return
    end
end

if cert_der and key_der then
    ssl.clear_certs()
    ssl.set_cert(cert_der)
    ssl.set_priv_key(key_der)
end
