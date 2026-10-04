#!/usr/bin/env python3
"""Loopback-only TLS/CONNECT regression tests; no API keys or provider calls.

Requires luajit, openssl, LuaSocket, LuaSec 1.3.2+ and dkjson on LUA_PATH/C_PATH.
Generates disposable CAs, certificates and keys in a temporary directory.
"""

import http.server
import os
from pathlib import Path
import select
import shutil
import socket
import socketserver
import ssl
import subprocess
import tempfile
import threading
import unittest

ROOT = Path(__file__).resolve().parents[2]
LUA = r'''
package.path = "./?.lua;./tests/lib/?.lua;" .. package.path
local mode, url = arg[1], arg[2]
local real_ffi = require("ffi")
local http = require("socket.http")
http.PROXY = os.getenv("TEST_PROXY")
local proxy = http.PROXY
local ltn12 = require("ltn12")
local headers = { Authorization = "Bearer test-only-not-a-credential", ["Content-Length"] = "4" }
if mode == "public" then
    local chunks = {}
    local _, code = require("koassistant_https").publicGet{
        url=url, method="GET", sink=ltn12.sink.table(chunks),
    }
    assert(code == 200 and table.concat(chunks) == "OK", tostring(code))
elseif mode == "raw" or mode == "raw-resolved" then
    require("mock_koreader")
    if mode == "raw-resolved" then
        package.loaded.ffi = real_ffi
        -- Minimal host POSIX declarations to exercise the real pre-resolved FFI
        -- connection without needing a GUI installation's ffi/posix_h module.
        package.preload["ffi/posix_h"] = function()
            local family = real_ffi.os == "OSX" and "uint8_t sin_len; uint8_t sin_family;" or "uint16_t sin_family;"
            real_ffi.cdef("struct in_addr { uint32_t s_addr; }; struct sockaddr; struct sockaddr_in { " .. family ..
                " uint16_t sin_port; struct in_addr sin_addr; char sin_zero[8]; };")
            real_ffi.cdef[[
                enum { AF_INET = 2 };
                int socket(int, int, int);
                int close(int);
                uint16_t htons(uint16_t);
                int inet_aton(const char *, struct in_addr *);
                char *strerror(int);
            ]]
        end
    end
    local base = require("koassistant_api.base")
    local parsed = require("socket.url").parse(url)
    local conn = base.connectSSLInSubprocess(mode == "raw-resolved" and "127.0.0.1" or nil,
        parsed.host, tonumber(parsed.port), 3)
    assert(conn:send("POST / HTTP/1.1\r\nHost: localhost\r\nAuthorization: " .. headers.Authorization ..
        "\r\nConnection: close\r\nContent-Length: 4\r\n\r\nTEST"))
    assert(conn:receive("*l"):find("200", 1, true))
    conn:close()
elseif mode == "fetch" then
    require("mock_koreader")
    local base = require("koassistant_api.base")
    local code, body = base.fetchInSubprocess(url, {method="POST", headers=headers, body="TEST", timeout=3})
    assert(code == 200 and body == "OK", tostring(code) .. " " .. tostring(body))
elseif mode == "stream" then
    require("mock_koreader")
    local received = {}
    require("ffi/util").writeToFD = function(_, chunk) received[#received+1] = chunk end
    local base = require("koassistant_api.base")
    base:backgroundRequest(url, headers, "TEST")(123, 7)
    local body = table.concat(received)
    assert(body == "OK", body)
else
    local chunks = {}
    local _, code = require("koassistant_https").request{
        url=url, method="POST", headers=headers, source=ltn12.source.string("TEST"), sink=ltn12.sink.table(chunks),
    }
    assert(http.PROXY == proxy, "global proxy not restored")
    if mode == "redirect" then assert(code == 302, tostring(code))
    else assert(code == 200 and table.concat(chunks) == "OK", tostring(code)) end
end
'''


class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self.server.requests.append((self.path, self.headers.get("Authorization"), body))
        redirect = self.path.startswith("/redirect")
        self.send_response(302 if redirect else 200)
        if self.path == "/redirect-https":
            self.send_header("Location", f"https://localhost:{self.server.server_port}/")
        elif self.path == "/redirect-invalid":
            self.send_header("Location", f"https://localhost:{self.server.wronghost_port}/")
        elif self.path == "/redirect":
            self.send_header("Location", "http://127.0.0.1:1/never-follow-this")
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"OK")

    do_GET = do_POST

    def log_message(self, *args):
        pass


class Proxy(socketserver.StreamRequestHandler):
    def handle(self):
        self.connection.settimeout(5)
        line = self.rfile.readline().decode().strip()
        if not line:
            return
        self.server.requests.append(line)
        method, authority, _ = line.split()
        if method != "CONNECT":
            self.wfile.write(b"HTTP/1.1 400 CONNECT required\r\n\r\n")
            return
        host, port = authority.rsplit(":", 1)
        # The test proxy must never connect anywhere other than our loopback servers.
        assert host in ("localhost", "127.0.0.1") and int(port) in self.server.allowed_ports
        while self.rfile.readline() not in (b"\r\n", b"\n", b""):
            pass
        if self.server.reject:
            self.wfile.write(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
            return
        with socket.create_connection(("127.0.0.1", int(port)), timeout=5) as upstream:
            self.wfile.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            self.wfile.flush()
            while True:
                readable, _, _ = select.select([self.connection, upstream], [], [], 5)
                if not readable:
                    return
                for source in readable:
                    try:
                        data = source.recv(65536)
                        if not data:
                            return
                        (upstream if source is self.connection else self.connection).sendall(data)
                    except (ConnectionError, TimeoutError):
                        return


class TLSIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="koassistant-tls-")
        cls.addClassCleanup(cls.temp.cleanup)
        cls.directory = Path(cls.temp.name)
        cls.lua = os.environ.get("LUA", "luajit")
        cls.openssl = os.environ.get("OPENSSL", "openssl")
        for binary in (cls.lua, cls.openssl):
            if not shutil.which(binary):
                raise RuntimeError(f"Required executable missing: {binary}")
        cls.driver = cls.directory / "client.lua"
        cls.driver.write_text(LUA)

        def openssl(*args):
            result = subprocess.run([cls.openssl, *args], cwd=cls.directory, capture_output=True, text=True)
            if result.returncode:
                raise RuntimeError(result.stderr)

        openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key",
                "-out", "ca.pem", "-days", "2", "-subj", "/CN=KOAssistant test root",
                "-addext", "basicConstraints=critical,CA:TRUE")
        (cls.directory / "index").touch()
        (cls.directory / "serial").write_text("01\n")
        (cls.directory / "ca.cnf").write_text(
            "[ca]\ndefault_ca=test\n[test]\ndatabase=index\nserial=serial\n"
            "new_certs_dir=.\ncertificate=ca.pem\nprivate_key=ca.key\n"
            "default_md=sha256\npolicy=policy\n[policy]\ncommonName=supplied\n")
        cls.servers = {}
        for name, san in (("valid", "DNS:localhost,IP:127.0.0.1"),
                          ("wronghost", "DNS:attacker.invalid"),
                          ("expired", "DNS:localhost"), ("untrusted", "DNS:localhost")):
            openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", f"{name}.key",
                    "-out", f"{name}.csr", "-subj", "/CN=localhost")
            (cls.directory / "extensions").write_text(f"subjectAltName={san}\nextendedKeyUsage=serverAuth\n")
            signing = ["-signkey", f"{name}.key"] if name == "untrusted" else ["-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial"]
            if name == "expired":
                openssl("ca", "-batch", "-config", "ca.cnf", "-in", "expired.csr", "-out", "expired.pem",
                        "-startdate", "20000101000000Z", "-enddate", "20000102000000Z", "-extfile", "extensions")
            else:
                openssl("x509", "-req", "-in", f"{name}.csr", *signing, "-out", f"{name}.pem",
                        "-days", "1", "-extfile", "extensions")
            server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            server.requests = []
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cls.directory / f"{name}.pem", cls.directory / f"{name}.key")
            server.socket = context.wrap_socket(server.socket, server_side=True)
            cls.servers[name] = server
            cls.start(server)
        cls.servers["valid"].wronghost_port = cls.servers["wronghost"].server_port
        cls.proxy = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Proxy)
        cls.proxy.daemon_threads = True
        cls.proxy.requests = []
        cls.proxy.reject = False
        cls.proxy.allowed_ports = {s.server_port for s in cls.servers.values()}
        cls.start(cls.proxy)

    @classmethod
    def start(cls, server):
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        cls.addClassCleanup(server.server_close)
        cls.addClassCleanup(server.shutdown)

    def run_client(self, name, mode="request", proxy=False, path="/", host="localhost", missing_ca=False):
        env = dict(os.environ, SSL_CERT_FILE=str(self.directory / ("absent.pem" if missing_ca else "ca.pem")))
        env.pop("TEST_PROXY", None)
        if proxy:
            env["TEST_PROXY"] = f"http://127.0.0.1:{self.proxy.server_address[1]}"
        url = f"https://{host}:{self.servers[name].server_port}{path}"
        return subprocess.run([self.lua, str(self.driver), mode, url], cwd=ROOT, env=env,
                              capture_output=True, text=True, timeout=12)

    def test_valid_certificate_all_paths_direct_and_connect(self):
        for mode in ("request", "raw", "raw-resolved", "fetch", "stream"):
            for proxy in (False, True):
                with self.subTest(mode=mode, proxy=proxy):
                    result = self.run_client("valid", mode, proxy)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(self.proxy.requests)
        self.assertTrue(all(line.startswith("CONNECT ") for line in self.proxy.requests))

    def test_bad_certificates_never_receive_http_credentials(self):
        for name in ("wronghost", "expired", "untrusted"):
            for mode in ("request", "raw", "raw-resolved", "fetch", "stream"):
                for proxy in (False, True):
                    with self.subTest(name=name, mode=mode, proxy=proxy):
                        result = self.run_client(name, mode, proxy)
                        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(self.servers[name].requests, [])

    def test_ip_san(self):
        result = self.run_client("valid", host="127.0.0.1")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_missing_ca_fails_before_http(self):
        before = len(self.servers["valid"].requests)
        result = self.run_client("valid", missing_ca=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(self.servers["valid"].requests), before)

    def test_redirect_not_followed(self):
        for proxy in (False, True):
            result = self.run_client("valid", "redirect", proxy, path="/redirect")
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_public_download_redirects_require_https_and_a_valid_peer(self):
        for proxy in (False, True):
            result = self.run_client("valid", "public", proxy, path="/redirect-https")
            self.assertEqual(result.returncode, 0, result.stderr)
            for path in ("/redirect", "/redirect-invalid"):
                result = self.run_client("valid", "public", proxy, path=path)
                self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.servers["wronghost"].requests, [])

    def test_proxy_refusal_fails_before_http(self):
        before = len(self.servers["valid"].requests)
        self.proxy.reject = True
        try:
            result = self.run_client("valid", proxy=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(len(self.servers["valid"].requests), before)
        finally:
            self.proxy.reject = False


if __name__ == "__main__":
    unittest.main(verbosity=2)
