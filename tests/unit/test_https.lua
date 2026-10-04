local script = debug.getinfo(1, "S").source:gsub("^@", "")
local root = (script:match("^(.*)/tests/unit/") or ".")
package.path = root .. "/?.lua;" .. root .. "/tests/lib/?.lua;" .. package.path
require("mock_koreader")
local T = require("test_runner"):new()
local HTTPS = require("koassistant_https")

local function cert(dns, ips)
    return {extensions = function() return { ["2.5.29.17"] = {dNSName=dns, iPAddress=ips} } end}
end

T:test("DNS SANs are case insensitive and exact", function()
    assert(HTTPS.matchesHostname(cert({"API.Example.org"}), "api.example.org"))
    assert(not HTTPS.matchesHostname(cert({"other.example.org"}), "api.example.org"))
    assert(not HTTPS.matchesHostname(cert({"api.example.org\0.attacker"}), "api.example.org"))
end)
T:test("wildcards match only a whole single label", function()
    local c = cert({"*.example.org"})
    assert(HTTPS.matchesHostname(c, "api.example.org"))
    for _, name in ipairs({"example.org", "a.b.example.org", "example.org.attacker", "xn--test.example.org"}) do
        assert(not HTTPS.matchesHostname(c, name), name)
    end
    assert(not HTTPS.matchesHostname(cert({"a*.example.org"}), "api.example.org"))
    assert(not HTTPS.matchesHostname(cert({"*.org"}), "example.org"))
end)
T:test("IP literals require exact IP SANs", function()
    assert(HTTPS.matchesHostname(cert(nil, {"127.0.0.1"}), "127.0.0.1"))
    assert(not HTTPS.matchesHostname(cert({"127.0.0.1"}), "127.0.0.1"))
    assert(not HTTPS.matchesHostname(cert(nil, {"127.0.0.1"}), "127.0.0.2"))
    assert(not HTTPS.matchesHostname(cert(nil, {"127.0.0.1"}), "127.000.0.1"))
    assert(HTTPS.matchesHostname(cert(nil, {"0:0:0:0:0:0:0:1"}), "::1"))
    assert(HTTPS.matchesHostname(cert(nil, {"0:0:0:0:0:ffff:7f00:1"}), "::ffff:127.0.0.1"))
    assert(not HTTPS.matchesHostname(cert(nil, {"::1"}), "::2"))
    assert(not HTTPS.matchesHostname(cert(nil, {"::1"}), ":::1"))
end)
T:test("missing SAN never falls back to common name", function()
    local c = {extensions=function() return {} end, subject=function() return {{name="commonName", value="api.example.org"}} end}
    assert(not HTTPS.matchesHostname(c, "api.example.org"))
end)
T:test("public downloads reject credentials and plaintext URLs", function()
    assert(not pcall(HTTPS.publicGet, {url="https://example.org", headers={Authorization="secret"}}))
    assert(not pcall(HTTPS.publicGet, {url="https://example.org", headers={Cookie="secret"}}))
    assert(not pcall(HTTPS.publicGet, {url="http://example.org"}))
end)
T:test("public download redirect loops are bounded", function()
    local original = HTTPS.request
    local calls = 0
    HTTPS.request = function()
        calls = calls + 1
        return 1, 302, {location="https://example.org/loop"}
    end
    local old_url = package.loaded["socket.url"]
    package.loaded["socket.url"] = {absolute=function(_, url) return url end}
    local ok = pcall(HTTPS.publicGet, {url="https://example.org"})
    HTTPS.request = original
    package.loaded["socket.url"] = old_url
    assert(not ok and calls == 6)
end)

local original_ssl = package.loaded.ssl
local original_ca = HTTPS.caFile
local closed, params, peer, handshake
local function reset()
    closed, params, peer, handshake = false, nil, cert({"api.example.org"}), true
    HTTPS.caFile = function() return "test-roots.pem" end
    package.loaded.ssl = {wrap=function(raw, options)
        params = options
        return {
            sni=function() return true end, settimeout=function() return 1 end,
            dohandshake=function() return handshake, "untrusted or expired certificate" end,
            getpeercertificate=function() return peer end,
            close=function() closed=true end,
        }
    end}
end
local raw = {close=function() closed=true end}
T:test("wrap requires a CA-validated peer before returning a socket", function()
    reset()
    assert(HTTPS.wrap(raw, "api.example.org", 3))
    assert(params.verify == "peer" and params.cafile == "test-roots.pem")
    assert(not closed)
end)
T:test("wrap closes and rejects an untrusted or expired peer", function()
    reset(); handshake = nil
    assert(not pcall(HTTPS.wrap, raw, "api.example.org", 3))
    assert(closed)
end)
T:test("wrap closes and rejects a trusted wrong-host peer", function()
    reset(); peer = cert({"attacker.invalid"})
    assert(not pcall(HTTPS.wrap, raw, "api.example.org", 3))
    assert(closed)
end)
T:test("missing CA bundle fails closed and closes raw socket", function()
    reset(); HTTPS.caFile=function() error("No CA bundle") end
    assert(not pcall(HTTPS.wrap, raw, "api.example.org", 3))
    assert(closed)
end)
package.loaded.ssl = original_ssl
HTTPS.caFile = original_ca

-- Load the same shared transport used by OAuth, image requests and providers.
T:test("base transport no longer accepts the wrong-host baseline", function()
    local socket = require("socket")
    local old_tcp = socket.tcp
    reset(); peer = cert({"attacker.invalid"})
    socket.tcp=function() return {settimeout=function() return 1 end, connect=function() return 1 end, close=raw.close} end
    local ok = pcall(require("koassistant_api.base").connectSSLInSubprocess, nil, "api.example.org", 443, 3)
    socket.tcp = old_tcp
    package.loaded.ssl = original_ssl
    HTTPS.caFile = original_ca
    assert(not ok and closed)
end)

T:test("macOS resolves the CONNECT proxy in the parent, not the API host", function()
    local socket, http, ffi = require("socket"), require("socket.http"), require("ffi")
    local old_dns, old_proxy, old_os = socket.dns, http.PROXY, ffi.os
    local old_url = package.loaded["socket.url"]
    package.loaded["socket.url"] = {parse=function() return {scheme="http", host="proxy.test", port="1056"} end}
    local queried
    socket.dns = {getaddrinfo=function(host) queried=host; return {{family="inet",addr="127.0.0.1"}} end}
    http.PROXY, ffi.os = "http://proxy.test:1056", "OSX"
    local ok, address, host, port = pcall(require("koassistant_api.base").resolveForSubprocess,
        "https://api.example.org/v1/responses")
    socket.dns, http.PROXY, ffi.os = old_dns, old_proxy, old_os
    package.loaded["socket.url"] = old_url
    assert(ok and queried == "proxy.test" and address == "127.0.0.1" and host == "proxy.test" and port == 1056)
end)

return T:summary()
