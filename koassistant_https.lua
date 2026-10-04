-- Plugin-scoped HTTPS transport. LuaSec 1.3.2 defaults to verify="none" and
-- does not check hostnames, even with verify="peer". Never use those defaults
-- for provider credentials, OAuth tokens, or executable update downloads.
local HTTPS = {}

local function ipv4(value)
    local parts = {}
    for part in value:gmatch("[^.]+") do
        if not part:match("^%d+$") or #part > 3 or tonumber(part) > 255
            or (#part > 1 and part:sub(1, 1) == "0") then return nil end
        parts[#parts + 1] = tonumber(part)
    end
    if #parts ~= 4 or table.concat(parts, ".") ~= value then return nil end
    return parts
end

local function ip(value)
    local v4 = ipv4(value)
    if v4 then return "v4:" .. value end
    if not value:find(":", 1, true) then return nil end
    -- Canonicalize IPv6 SANs without DNS or platform-specific inet_pton/FFI.
    local tail = value:match("([^:]+)$")
    if tail and tail:find(".", 1, true) then
        v4 = ipv4(tail)
        if not v4 then return nil end
        value = value:sub(1, #value - #tail) .. string.format("%x:%x", v4[1]*256+v4[2], v4[3]*256+v4[4])
    end
    if value:find("[^%x:]") then return nil end
    local first = value:find("::", 1, true)
    if first and value:find("::", first + 2, true) then return nil end
    local function groups(part)
        local out = {}
        if part == "" then return out end
        if part:sub(1, 1) == ":" or part:sub(-1) == ":" then return nil end
        for group in part:gmatch("[^:]+") do
            if #group > 4 then return nil end
            out[#out + 1] = string.format("%04x", tonumber(group, 16))
        end
        return out
    end
    local left = groups(first and value:sub(1, first - 1) or value)
    local right = groups(first and value:sub(first + 2) or "")
    if not left or not right then return nil end
    local count = #left + #right
    if (first and count >= 8) or (not first and count ~= 8) then return nil end
    return "v6:" .. table.concat(left) .. string.rep("0000", 8 - count) .. table.concat(right)
end

local function dns(value)
    if type(value) ~= "string" then return nil end
    value = value:lower():gsub("%.$", "")
    if #value == 0 or #value > 253 or value:find("[^a-z0-9.-]")
        or value:find("..", 1, true) or value:sub(1, 1) == "." then return nil end
    for label in value:gmatch("[^.]+") do
        if #label > 63 or label:sub(1, 1) == "-" or label:sub(-1) == "-" then return nil end
    end
    return value
end

function HTTPS.matchesHostname(cert, hostname)
    if type(hostname) ~= "string" or hostname:find("%z") then return false end
    hostname = hostname:gsub("^%[(.*)%]$", "%1")
    local address = ip(hostname)
    local extensions = cert:extensions()
    local san = extensions and extensions["2.5.29.17"]
    if type(san) ~= "table" then return false end
    if address then
        for _, candidate in ipairs(san.iPAddress or {}) do
            if type(candidate) == "string" and ip(candidate) == address then return true end
        end
        return false -- IP literals must match IP SANs, never DNS names or CNs.
    end
    if hostname:match("^[%d.]+$") then return false end
    hostname = dns(hostname)
    if not hostname then return false end
    for _, candidate in ipairs(san.dNSName or {}) do
        if type(candidate) == "string" then
            local suffix = candidate:match("^%*%.(.+)$")
            if suffix then
                suffix = dns(suffix)
                local label, rest = hostname:match("^([^.]+)%.(.+)$")
                if suffix and suffix:find(".", 1, true) and rest == suffix
                    and not label:match("^xn%-%-") then return true end
            elseif dns(candidate) == hostname then
                return true
            end
        end
    end
    -- No legacy common-name fallback: require subjectAltName (RFC 9525).
    return false
end

function HTTPS.caFile()
    local configured = os.getenv("SSL_CERT_FILE")
    local candidates = configured and {configured} or {
        "data/ca-bundle.crt", -- KOReader's shipped roots, independent of device OS.
        "/etc/ssl/cert.pem", "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
    }
    for _, path in ipairs(candidates) do
        local file = io.open(path, "rb")
        if file then file:close(); return path end
    end
    error("No readable TLS CA bundle; restore KOReader data/ca-bundle.crt or set SSL_CERT_FILE")
end

function HTTPS.wrap(raw, hostname, timeout)
    local conn = raw
    local ok, result = pcall(function()
        conn = assert(require("ssl").wrap(raw, {
            mode = "client", protocol = "any", verify = "peer", cafile = HTTPS.caFile(),
            options = {"all", "no_sslv2", "no_sslv3", "no_tlsv1", "no_tlsv1_1"},
        }))
        if not ip(hostname) then conn:sni(hostname) end -- LuaSec returns no values on success.
        assert(conn:settimeout(timeout or 180))
        assert(conn:dohandshake()) -- Peer chain, validity period and CA trust.
        local cert = assert(conn:getpeercertificate(), "TLS peer supplied no certificate")
        assert(HTTPS.matchesHostname(cert, hostname), "TLS certificate does not match requested hostname")
        return conn
    end)
    if not ok then
        pcall(function() (conn or raw):close() end)
        error(result, 0)
    end
    return result
end

function HTTPS.proxy(value)
    if value == nil then value = require("socket.http").PROXY end
    if not value then return nil end
    local parsed = require("socket.url").parse(value)
    if not parsed or parsed.scheme ~= "http" or not parsed.host
        or parsed.user or parsed.password or (parsed.path and parsed.path ~= "" and parsed.path ~= "/") then
        error("HTTPS requires an HTTP CONNECT proxy without URL credentials")
    end
    return parsed.host, tonumber(parsed.port) or 3128
end

-- connect_tcp is injectable for macOS's pre-resolved, post-fork FFI connection.
function HTTPS.connect(hostname, port, timeout, connect_tcp, proxy)
    local proxy_host, proxy_port = HTTPS.proxy(proxy)
    local raw
    local ok, result = pcall(function()
        if connect_tcp then
            raw = connect_tcp(proxy_host or hostname, proxy_port or port)
        else
            raw = assert(require("socket").tcp())
            assert(raw:settimeout(timeout or 180))
            assert(raw:connect(proxy_host or hostname, proxy_port or port))
        end
        if proxy_host then
            local authority = (hostname:find(":", 1, true) and "[" .. hostname .. "]" or hostname) .. ":" .. port
            assert(not authority:find("[\r\n]"), "Invalid CONNECT authority")
            assert(raw:send("CONNECT " .. authority .. " HTTP/1.1\r\nHost: " .. authority .. "\r\n\r\n"))
            local status = assert(raw:receive("*l"))
            assert(status:match("^HTTP/1%.[01] 200[ %s]"), "HTTP proxy refused CONNECT")
            local done = false
            for _ = 1, 100 do
                local line = assert(raw:receive("*l"))
                assert(#line <= 8192, "Oversized CONNECT header")
                if line == "" then done = true; break end
            end
            assert(done, "Too many CONNECT headers")
        end
        -- Credentials/body are not sent until BOTH peer and hostname checks pass.
        return HTTPS.wrap(raw, hostname, timeout)
    end)
    if not ok then
        if raw then pcall(function() raw:close() end) end
        error(result, 0)
    end
    return result
end

function HTTPS.request(request)
    local http = require("socket.http")
    if request.url:sub(1, 8) ~= "https://" then return http.request(request) end
    local parsed = assert(require("socket.url").parse(request.url))
    assert(parsed.host and not parsed.user and not parsed.password, "Invalid HTTPS URL")
    local req = {}
    for k, v in pairs(request) do req[k] = v end
    -- Never forward credentials to a redirected origin or bypass this factory
    -- through LuaSocket's redirect code. Return 3xx to the caller instead.
    req.redirect = false
    local proxy = request.proxy or http.PROXY or false
    req.create = function()
        local wrapper = { timeout = http.TIMEOUT or 180 }
        function wrapper:settimeout(timeout) self.timeout = timeout; return 1 end
        function wrapper:connect(host, port)
            self.sock = HTTPS.connect(host, port, self.timeout, nil, proxy)
            return 1
        end
        for _, name in ipairs({"send", "receive", "getfd", "dirty", "getstats", "setstats"}) do
            wrapper[name] = function(self, ...) return self.sock[name](self.sock, ...) end
        end
        function wrapper:close() if self.sock then return self.sock:close() end; return 1 end
        return wrapper
    end
    -- LuaSocket's built-in proxy mode sends absolute-form HTTPS over plain TCP;
    -- the socket factory above owns CONNECT instead. These calls are synchronous
    -- in a forked worker, and the global is restored even on transport errors.
    local saved_proxy = http.PROXY
    req.proxy = nil
    http.PROXY = nil
    local ok, a, b, c, d = pcall(http.request, req)
    http.PROXY = saved_proxy
    if not ok then error(a, 0) end
    return a, b, c, d
end

-- Release assets use cross-origin redirects (GitHub -> asset CDN). Only this
-- credential-free GET path follows them, validating TLS anew on every hop.
function HTTPS.publicGet(request)
    assert(not request.method or request.method == "GET", "Public downloads must use GET")
    assert(not request.source, "Public downloads cannot have a request body")
    for key in pairs(request.headers or {}) do
        assert(key:lower() == "user-agent" or key:lower() == "accept", "Unexpected public download header")
    end
    local url = request.url
    for _ = 1, 6 do
        assert(url:sub(1, 8) == "https://", "Refusing non-HTTPS download or redirect")
        local chunks, size = {}, 0
        local ok, code, headers, status = HTTPS.request{
            url=url, method="GET", headers=request.headers,
            sink=function(chunk)
                if chunk then
                    size = size + #chunk
                    assert(size <= 64 * 1024 * 1024, "Public download exceeds 64 MiB")
                    chunks[#chunks + 1] = chunk
                end
                return 1
            end,
        }
        if not ok then return ok, code, headers, status end
        if (code == 301 or code == 302 or code == 303 or code == 307 or code == 308)
            and headers and headers.location then
            url = require("socket.url").absolute(url, headers.location)
        else
            -- Do not write intermediate redirect pages into the destination zip.
            if request.sink then
                for _, chunk in ipairs(chunks) do assert(request.sink(chunk)) end
                assert(request.sink(nil))
            end
            return ok, code, headers, status
        end
    end
    error("Too many HTTPS download redirects")
end

return HTTPS
