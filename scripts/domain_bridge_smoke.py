#!/usr/bin/env python3
"""Exercise real MosDNS/Mihomo processes without Internet DNS or root access.

Optionally add a real dnsmasq executable to test the complete ECS forwarding hop.
The SOCKS requests carry numeric destinations, so domain rules can only succeed
through the bridge while protocol sniffing and Mihomo DNS are disabled.
"""

import argparse
import concurrent.futures
import http.server
import ipaddress
import json
import os
from pathlib import Path
import socket
import socketserver
import struct
import subprocess
import tempfile
import threading
import time
import urllib.request
import urllib.error
import urllib.parse


HTTP = urllib.request.build_opener(urllib.request.ProxyHandler({}))
ALLOCATED_PORTS = set()


def free_port():
    # Windows may allow a TCP ephemeral port that is excluded for UDP.
    # Services here use both transports, so verify both before launching.
    for attempt in range(100):
        with socket.socket() as tcp, socket.socket(type=socket.SOCK_DGRAM) as udp:
            # TCP's automatic sequence may remain inside a long UDP exclusion
            # range on Windows. Fall back to independent explicit candidates.
            candidate = 0 if attempt < 10 else 1024 + int.from_bytes(os.urandom(2), "big") % (65536 - 1024)
            try:
                tcp.bind(("127.0.0.1", candidate))
            except OSError:
                continue
            port = tcp.getsockname()[1]
            if port in ALLOCATED_PORTS:
                continue
            try:
                udp.bind(("127.0.0.1", port))
            except OSError:
                continue
            ALLOCATED_PORTS.add(port)
            return port
    raise RuntimeError("could not find a free TCP/UDP port")


def dns_name(name):
    return b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.rstrip(".").split(".")) + b"\x00"


def read_name(data, pos):
    labels, end, visited = [], None, set()
    while True:
        if pos in visited:
            raise ValueError("DNS compression loop")
        visited.add(pos)
        length = data[pos]
        if length & 0xC0 == 0xC0:
            if end is None:
                end = pos + 2
            pos = ((length & 0x3F) << 8) | data[pos + 1]
            continue
        pos += 1
        if length == 0:
            return ".".join(labels), end if end is not None else pos
        labels.append(data[pos:pos + length].decode("ascii"))
        pos += length


def records(data):
    _, flags, qd, an, ns, ar = struct.unpack_from("!6H", data)
    pos = 12
    for _ in range(qd):
        _, pos = read_name(data, pos)
        pos += 4
    result = []
    for _ in range(an + ns + ar):
        name, pos = read_name(data, pos)
        kind, cls, ttl, size = struct.unpack_from("!HHIH", data, pos)
        pos += 10
        result.append((name, kind, cls, ttl, data[pos:pos + size]))
        pos += size
    if flags & 15:
        raise AssertionError(f"DNS RCODE {flags & 15}")
    return result


def dns_query(port, name, client="127.0.0.2", ecs=None, tcp=False, qtype=1, raw=False):
    request_id = int.from_bytes(os.urandom(2), "big")
    extra = b""
    if ecs is not None:
        address = ipaddress.ip_address(ecs)
        subnet = struct.pack("!HBB", 1 if address.version == 4 else 2, address.max_prefixlen, 0) + address.packed
        option = struct.pack("!HH", 8, len(subnet)) + subnet
        extra = b"\x00" + struct.pack("!HHIH", 41, 1232, 0, len(option)) + option
    request = struct.pack("!6H", request_id, 0x100, 1, 0, 0, bool(extra)) + dns_name(name) + struct.pack("!HH", qtype, 1) + extra
    with socket.socket(type=socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as sock:
        sock.settimeout(4)
        sock.bind((client, 0))
        if tcp:
            sock.connect(("127.0.0.1", port))
            sock.sendall(struct.pack("!H", len(request)) + request)
            response = recv_exact(sock, struct.unpack("!H", recv_exact(sock, 2))[0])
        else:
            sock.sendto(request, ("127.0.0.1", port))
            response, _ = sock.recvfrom(65535)
    assert response[:2] == request[:2]
    if raw:
        return response
    return [str(ipaddress.ip_address(rr[4])) for rr in records(response) if rr[1] == 1]


class Upstream(socketserver.ThreadingUDPServer):
    daemon_threads = True

    def __init__(self, policy_address):
        self.policy_address = policy_address
        self.calls = {}
        self.ecs_seen = 0
        self.lock = threading.Lock()
        super().__init__(("127.0.0.1", 0), DNSHandler)


class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        name, end = read_name(data, 12)
        qtype, _ = struct.unpack_from("!HH", data, end)
        with self.server.lock:
            self.server.calls[name] = self.server.calls.get(name, 0) + 1
            for _, kind, _, _, payload in records(data):
                if kind == 41:
                    pos = 0
                    while pos + 4 <= len(payload):
                        option, length = struct.unpack_from("!HH", payload, pos)
                        self.server.ecs_seen += option == 8
                        pos += 4 + length
        additional, additional_count, answer_count = b"", 0, 0
        if name == "https.bridge.test" and qtype == 65:
            target = "svc-endpoint.bridge.test"
            binding = struct.pack("!H", 1) + dns_name(target)
            answer = b"\xc0\x0c" + struct.pack("!HHIH", 65, 1, 600, len(binding)) + binding
            answer_count = 1
            for owner, address in ((target, "203.0.113.111"), ("unrelated.bridge.test", "203.0.113.112")):
                additional += dns_name(owner) + struct.pack("!HHIH", 1, 1, 600, 4) + socket.inet_aton(address)
                additional_count += 1
        elif name == "truncated.bridge.test" and qtype == 1:
            answer = b"".join(b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 600, 4) + socket.inet_aton(f"203.0.113.{i}") for i in range(1, 101))
            answer_count = 100
        elif qtype != 1:
            answer = b""
        else:
            address = self.server.policy_address if name == "policy.bridge.test" else "127.0.0.1"
            if name == "previous.bridge.test":
                address = "203.0.113.100"
            if name in ("expiry.bridge.test", "expiry-stable.bridge.test"):
                address = "203.0.113.113"
            if name == "expiry-only.bridge.test":
                address = "203.0.113.114"
            ttl = 2 if name in ("expiry.bridge.test", "expiry-only.bridge.test") else 600
            answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, ttl, 4) + socket.inet_aton(address)
            answer_count = 1
        response = data[:2] + struct.pack("!5H", 0x8180, 1, answer_count, 0, additional_count) + data[12:end + 4] + answer + additional
        sock.sendto(response, self.client_address)


class EchoHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(4)
        try:
            while data := self.request.recv(4096):
                self.request.sendall(data)
        except (OSError, TimeoutError):
            pass


class EchoServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


class UDPEchoHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        sock.sendto(data, self.client_address)


class UDPEchoServer(socketserver.ThreadingUDPServer):
    daemon_threads = True


def recv_exact(sock, length):
    value = b""
    while len(value) < length:
        part = sock.recv(length - len(value))
        if not part:
            raise ConnectionError("connection closed")
        value += part
    return value


def socks_echo(port, target_port, client="127.0.0.2", payload=b"bridge-probe", expect_success=True):
    try:
        with socket.socket() as sock:
            sock.settimeout(3)
            sock.bind((client, 0))
            sock.connect(("127.0.0.1", port))
            sock.sendall(b"\x05\x01\x00")
            assert recv_exact(sock, 2) == b"\x05\x00"
            sock.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", target_port))
            header = recv_exact(sock, 4)
            if header[1] != 0:
                raise ConnectionError(f"SOCKS status {header[1]}")
            length = {1: 4, 4: 16}.get(header[3])
            if length is None:
                length = recv_exact(sock, 1)[0]
            recv_exact(sock, length + 2)
            sock.sendall(payload)
            assert recv_exact(sock, len(payload)) == payload
    except (OSError, ConnectionError, AssertionError):
        if expect_success:
            raise
        return False
    if not expect_success:
        raise AssertionError("expected domain rule to reject this connection")
    return True


def socks_udp_echo(port, target_port, client="127.0.0.2", expect_success=True):
    # A new source socket is required for each session: Mihomo's UDP NAT key
    # is the inbound source address and port, not the packet's destination.
    with socket.socket() as control, socket.socket(type=socket.SOCK_DGRAM) as udp:
        control.settimeout(3)
        udp.settimeout(1 if not expect_success else 3)
        control.bind((client, 0))
        udp.bind((client, 0))
        control.connect(("127.0.0.1", port))
        control.sendall(b"\x05\x01\x00")
        assert recv_exact(control, 2) == b"\x05\x00"
        control.sendall(b"\x05\x03\x00\x01" + socket.inet_aton(client) + struct.pack("!H", udp.getsockname()[1]))
        header = recv_exact(control, 4)
        assert header[:3] == b"\x05\x00\x00"
        family, length = {1: (socket.AF_INET, 4), 4: (socket.AF_INET6, 16)}[header[3]]
        relay = socket.inet_ntop(family, recv_exact(control, length))
        relay_port = struct.unpack("!H", recv_exact(control, 2))[0]
        if relay in ("0.0.0.0", "::"):
            relay = "127.0.0.1"
        prefix = b"\x00\x00\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", target_port)
        payload = b"bridge-udp-probe"
        udp.sendto(prefix + payload, (relay, relay_port))
        try:
            response, _ = udp.recvfrom(65535)
        except TimeoutError:
            if expect_success:
                raise
            return False
        assert expect_success, "expected domain rule to reject this UDP session"
        assert response == prefix + payload, response
        # Check packet ordering/reuse too, after the initial mapping lookup.
        for sequence in range(3):
            payload = f"bridge-udp-{sequence}".encode()
            udp.sendto(prefix + payload, (relay, relay_port))
            assert udp.recvfrom(65535)[0] == prefix + payload
        return True


def get_json(url, method="GET", value=None):
    body = None if value is None else json.dumps(value).encode()
    request = urllib.request.Request(url, data=body, method=method, headers={"Content-Type": "application/json"})
    try:
        with HTTP.open(request, timeout=5) as response:
            data = response.read()
            return json.loads(data) if data else None
    except urllib.error.HTTPError as error:
        raise RuntimeError(f"HTTP {error.code}: {error.read().decode(errors='replace')}") from error


def lookup_views(api, ip, client=None):
    params = {"ip": ip}
    if client is not None:
        params["client"] = client
    url = api + "?" + urllib.parse.urlencode(params)
    full = get_json(url)
    route = get_json(url + "&view=route")
    assert "candidates" not in route, route
    assert route == {key: value for key, value in full.items() if key != "candidates"}, (full, route)
    return route


class LegacyAPI(http.server.ThreadingHTTPServer):
    """Simulate v1 before compact views: unknown query fields are ignored."""

    daemon_threads = True

    def __init__(self, api):
        self.api = api
        self.calls = 0
        self.route_requests = 0
        self.full_responses = 0
        self.lock = threading.Lock()
        super().__init__(("127.0.0.1", 0), LegacyAPIHandler)


class LegacyAPIHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        params = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        with self.server.lock:
            self.server.calls += 1
            self.server.route_requests += params.get("view") == ["route"]
        # Deliberately drop view and forward only fields supported by old MosDNS.
        legacy_params = {key: params[key][-1] for key in ("ip", "client") if key in params}
        try:
            value = get_json(self.server.api + "?" + urllib.parse.urlencode(legacy_params))
            with self.server.lock:
                self.server.full_responses += bool(value.get("candidates"))
            body = json.dumps(value).encode()
            self.send_response(200)
        except (OSError, RuntimeError, ValueError) as error:
            body = json.dumps({"error": str(error)}).encode()
            self.send_response(502)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mosdns", required=True, type=Path)
    parser.add_argument("--mihomo", required=True, type=Path)
    parser.add_argument("--dnsmasq", type=Path)
    parser.add_argument("--connections", type=int, default=1000)
    parser.add_argument("--work-dir", type=Path)
    args = parser.parse_args()
    work = (args.work_dir or Path(tempfile.mkdtemp(prefix="domain-bridge-"))).resolve()
    work.mkdir(parents=True, exist_ok=True)
    processes, logs, servers = [], [], []
    result = {"connections": args.connections, "dnsmasq": bool(args.dnsmasq), "work_dir": str(work)}

    def start(name, command):
        log = (work / f"{name}.log").open("wb")
        logs.append(log)
        process = subprocess.Popen([str(arg) for arg in command], stdout=log, stderr=subprocess.STDOUT, cwd=work)
        processes.append(process)
        return process

    def wait_http(url):
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            for process in processes:
                if process.poll() is not None:
                    raise RuntimeError(f"child exited with {process.returncode}; inspect {work}")
            try:
                return get_json(url)
            except (OSError, ValueError):
                time.sleep(0.05)
        raise TimeoutError(f"service did not start: {url}")

    def wait_socks(port):
        # The controller can become ready before the mixed listener is bound.
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=1) as sock:
                    sock.sendall(b"\x05\x01\x00")
                    if recv_exact(sock, 2) == b"\x05\x00":
                        return
            except OSError:
                pass
            time.sleep(0.05)
        raise TimeoutError(f"SOCKS listener did not start: {port}")

    try:
        upstreams = [Upstream("192.0.2.10"), Upstream("192.0.2.20")]
        echo = EchoServer(("127.0.0.1", 0), EchoHandler)
        udp_echo = UDPEchoServer(("127.0.0.1", 0), UDPEchoHandler)
        servers = upstreams + [echo, udp_echo]
        for server in servers:
            threading.Thread(target=server.serve_forever, daemon=True).start()
        mos_port, api_port, socks_port, controller_port, dnsmasq_port = [free_port() for _ in range(5)]
        plugins = [{"tag": "domain_index", "type": "domain_mapping", "args": {"size": 65536, "allocation": {"enable": False}}}]
        for i, server in enumerate(upstreams):
            plugins += [
                {"tag": f"cache_{i}", "type": "cache", "args": {"size": 256}},
                {"tag": f"forward_{i}", "type": "forward", "args": {"upstreams": [{"addr": f"udp://127.0.0.1:{server.server_address[1]}"}]}},
                {"tag": f"policy_{i}", "type": "sequence", "args": [
                    {"exec": f"$cache_{i}"}, {"matches": "has_resp", "exec": "accept"}, {"exec": f"$forward_{i}"}]}]
        plugins.append({"tag": "main", "type": "sequence", "args": [
            {"exec": "$domain_index"},
            {"matches": "client_ip 127.0.0.2", "exec": "goto policy_0"},
            {"exec": "goto policy_1"}]})
        for transport in ("udp", "tcp"):
            plugins.append({"tag": transport, "type": f"{transport}_server", "args": {
                "entry": "main", "listen": f"127.0.0.1:{mos_port}", "trusted_ecs": ["127.0.0.1/32"]}})
        mos_config = work / "mosdns.yaml"
        mos_config.write_text(json.dumps({"log": {"level": "warn"}, "api": {"http": f"127.0.0.1:{api_port}"}, "plugins": plugins}), encoding="utf-8")
        mos = start("mosdns", [args.mosdns.resolve(), "start", "-c", mos_config, "-d", work])
        api = f"http://127.0.0.1:{api_port}/plugins/domain_index/v1/lookup"
        wait_http(api + "?ip=127.0.0.1")

        if args.dnsmasq:
            start("dnsmasq", [args.dnsmasq.resolve(), "--no-daemon", "--conf-file=/dev/null", "--no-resolv", "--no-hosts", "--bind-interfaces", "--listen-address=127.0.0.1", f"--port={dnsmasq_port}", f"--server=127.0.0.1#{mos_port}", "--add-subnet=32,128", "--strip-subnet", "--cache-size=150", "--log-facility=-"])
            version = subprocess.check_output([str(args.dnsmasq.resolve()), "--version"], text=True)
            result["dnsmasq_version"] = version.splitlines()[0]
            time.sleep(0.15)

        def query(name, client="127.0.0.2", tcp=False, forge=None):
            if args.dnsmasq:
                return dns_query(dnsmasq_port, name, client, forge, tcp)
            return dns_query(mos_port, name, "127.0.0.1", client, tcp)

        # Same QNAME must not mix policies, including cache hits and TCP DNS.
        for tcp in (False, True):
            assert query("policy.bridge.test", "127.0.0.2", tcp) == ["192.0.2.10"]
            assert query("policy.bridge.test", "127.0.0.3", tcp) == ["192.0.2.20"]
        assert [server.calls.get("policy.bridge.test") for server in upstreams] == [1, 1]
        if args.dnsmasq:
            assert query("policy.bridge.test", forge="127.0.0.3") == ["192.0.2.10"]
        # Same policy cache, different client: outer observer must still record both.
        query("cached.bridge.test", "127.0.0.3")
        query("cached.bridge.test", "127.0.0.4")
        assert get_json(api + "?ip=127.0.0.1&client=127.0.0.4")["scope"] == "client"
        assert upstreams[1].calls.get("cached.bridge.test") == 1
        assert not any(server.ecs_seen for server in upstreams), "internal identity ECS leaked upstream"
        print("PASS ECS identity, upstream policy isolation, cache-hit observation, TCP DNS", flush=True)

        # Exercise the actual server's final packing and Additional processing.
        # Use MosDNS directly so dnsmasq's automatic TCP retry cannot hide TC.
        dns_query(mos_port, "previous.bridge.test", "127.0.0.1", "127.0.0.2")
        truncated = dns_query(mos_port, "truncated.bridge.test", "127.0.0.1", "127.0.0.2", raw=True)
        assert struct.unpack_from("!H", truncated, 2)[0] & 0x200
        assert socket.inet_aton("203.0.113.100") not in [rr[4] for rr in records(truncated) if rr[1] == 1]
        assert get_json(api + "?ip=203.0.113.100&client=127.0.0.2")["domain"] == "previous.bridge.test"
        dns_query(mos_port, "https.bridge.test", "127.0.0.1", "127.0.0.2", qtype=65)
        assert get_json(api + "?ip=203.0.113.111&client=127.0.0.2")["domain"] == "https.bridge.test"
        assert get_json(api + "?ip=203.0.113.112&client=127.0.0.2")["status"] == "miss"
        result["response_boundary_regressions"] = "pass"
        print("PASS UDP truncation preserves prior evidence and only related HTTPS Additional is indexed", flush=True)

        # Compact responses must preserve routing evidence and expiry semantics.
        # Dedicated IPs keep this check independent of echo-server observations.
        query("expiry-stable.bridge.test", "127.0.0.4")
        query("expiry.bridge.test", "127.0.0.2")
        query("expiry-only.bridge.test", "127.0.0.6")
        scoped_expiry = get_json(api + "?ip=203.0.113.113&client=127.0.0.2&view=route")
        assert scoped_expiry["domain"] == "expiry.bridge.test" and scoped_expiry["scope"] == "client"
        global_expiry = get_json(api + "?ip=203.0.113.113&client=127.0.0.5&view=route")
        assert global_expiry["domain"] == "expiry.bridge.test" and global_expiry["scope"] == "global" and global_expiry["conflict"]
        deadline = time.monotonic() + 6
        while True:
            after = get_json(api + "?ip=203.0.113.113&client=127.0.0.2&view=route")
            expired = get_json(api + "?ip=203.0.113.114&client=127.0.0.6&view=route")
            if after.get("domain") == "expiry-stable.bridge.test" and expired["status"] == "miss":
                break
            if time.monotonic() >= deadline:
                raise AssertionError(f"expired route evidence retained: {after}, {expired}")
            time.sleep(0.05)
        assert after["scope"] == "global" and not after["conflict"]
        assert lookup_views(api, "203.0.113.113", "127.0.0.2") == after
        assert lookup_views(api, "203.0.113.114", "127.0.0.6")["status"] == "miss"

        query("alpha.bridge.test", "127.0.0.2")
        query("beta.bridge.test", "127.0.0.3")
        assert lookup_views(api, "127.0.0.1", "127.0.0.2")["domain"] == "alpha.bridge.test"
        scoped_conflict = lookup_views(api, "127.0.0.1", "127.0.0.3")
        assert scoped_conflict["domain"] == "beta.bridge.test" and scoped_conflict["scope"] == "client" and scoped_conflict["conflict"]
        fallback = lookup_views(api, "127.0.0.1", "2001:db8::2")
        assert fallback["scope"] == "global" and fallback["conflict"]
        assert lookup_views(api, "127.0.0.1")["scope"] == "global"
        result["route_view_regressions"] = "pass"
        print("PASS compact/full lookup equivalence, client/global conflicts, expiry and fallback", flush=True)

        config = {
            "mixed-port": socks_port, "bind-address": "127.0.0.1", "allow-lan": True,
            "mode": "rule", "log-level": "warning", "find-process-mode": "off",
            "external-controller": f"127.0.0.1:{controller_port}", "dns": {"enable": False},
            "sniffer": {"enable": False}, "profile": {"store-selected": False},
            "domain-mapping": {"enable": True, "timeout": 50, "providers": [{
                "name": "mosdns", "type": "mosdns-http-v1", "endpoint": api}]},
            "rules": ["DOMAIN,alpha.bridge.test,DIRECT", "DOMAIN,beta.bridge.test,REJECT", "DOMAIN,fallback.bridge.test,DIRECT", "MATCH,REJECT"],
        }
        mihomo_config = work / "mihomo.yaml"
        mihomo_config.write_text(json.dumps(config), encoding="utf-8")
        start("mihomo", [args.mihomo.resolve(), "-d", work / "mihomo-home", "-f", mihomo_config])
        controller = f"http://127.0.0.1:{controller_port}"
        wait_http(controller + "/version")
        wait_socks(socks_port)
        target_port = echo.server_address[1]
        socks_echo(socks_port, target_port)
        socks_echo(socks_port, target_port, client="127.0.0.3", expect_success=False)
        begin = time.monotonic()
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
            successes = sum(pool.map(lambda _: socks_echo(socks_port, target_port), range(args.connections)))
        assert successes == args.connections
        result.update(successful_connections=successes, connection_seconds=round(time.monotonic() - begin, 3))
        print(f"PASS {successes}/{args.connections} independent numeric-destination TCP connections, DNS/sniffer disabled", flush=True)

        udp_target = udp_echo.server_address[1]
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            udp_successes = sum(pool.map(lambda _: socks_udp_echo(socks_port, udp_target), range(100)))
        socks_udp_echo(socks_port, udp_target, client="127.0.0.3", expect_success=False)
        result["successful_udp_sessions"] = udp_successes
        print(f"PASS {udp_successes}/100 numeric-destination UDP sessions and subsequent packets", flush=True)

        # Reload off/on must not leave a stale mapping on new connections.
        def reload_config():
            mihomo_config.write_text(json.dumps(config), encoding="utf-8")
            get_json(controller + "/configs?force=true", "PUT", {"payload": json.dumps(config)})

        config["domain-mapping"]["enable"] = False
        reload_config()
        socks_echo(socks_port, target_port, expect_success=False)
        config["domain-mapping"]["enable"] = True
        reload_config()
        socks_echo(socks_port, target_port)
        print("PASS provider disable/enable reload", flush=True)

        legacy = LegacyAPI(api)
        servers.append(legacy)
        threading.Thread(target=legacy.serve_forever, daemon=True).start()
        config["domain-mapping"]["providers"][0]["endpoint"] = f"http://127.0.0.1:{legacy.server_address[1]}/plugins/domain_index/v1/lookup"
        reload_config()
        socks_echo(socks_port, target_port)
        socks_echo(socks_port, target_port, client="127.0.0.3", expect_success=False)
        with legacy.lock:
            assert legacy.calls >= 2 and legacy.route_requests == legacy.calls and legacy.full_responses == legacy.calls
        config["domain-mapping"]["providers"][0]["endpoint"] = api
        reload_config()
        result["legacy_api_compatibility"] = "pass"
        print("PASS Mihomo requests compact views and accepts a legacy endpoint returning full JSON", flush=True)

        # Stop the DNS process: lookup failure must reach existing protocol sniffing.
        config["sniffer"] = {"enable": True, "parse-pure-ip": True, "override-destination": False, "sniff": {"HTTP": {"ports": [target_port], "override-destination": False}}}
        reload_config()
        mos.terminate()
        mos.wait(timeout=5)
        socks_echo(socks_port, target_port, payload=b"GET / HTTP/1.1\r\nHost: fallback.bridge.test\r\n\r\n")
        print("PASS unavailable provider falls back to HTTP sniffing and existing rules", flush=True)
        result["status"] = "pass"
        (work / "result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(json.dumps(result, indent=2))
    except Exception as error:
        result.update(status="fail", error=str(error))
        (work / "result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(f"FAIL: inspect process logs in {work}", flush=True)
        raise
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
        for server in servers:
            server.shutdown()
            server.server_close()
        for log in logs:
            log.close()


if __name__ == "__main__":
    main()
