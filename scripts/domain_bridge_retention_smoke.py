#!/usr/bin/env python3
"""Test retention using real local MosDNS/Mihomo processes and numeric SOCKS.

The synthetic DNS upstream and TCP/UDP destinations are local. Mihomo DNS and
protocol sniffing are disabled, and unmatched destinations are rejected. No
production service, Internet DNS server, or privileged listener is used.
"""

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import json
from pathlib import Path
import socket
import socketserver
import struct
import subprocess
import threading
import time
import urllib.parse

from domain_bridge_smoke import (
    EchoHandler, EchoServer, UDPEchoHandler, UDPEchoServer, dns_query,
    free_port, get_json, read_name, records, recv_exact, socks_echo,
    socks_udp_echo,
)


ANSWERS = {
    "short.retention.test": ("127.0.0.1", 5),
    "long.retention.test": ("203.0.113.10", 300),
    "zero.retention.test": ("203.0.113.11", 0),
    "cold.retention.test": ("203.0.113.12", 1),
    "replacement.retention.test": ("127.0.0.1", 5),
}


class RetentionDNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        name, end = read_name(data, 12)
        qtype, qclass = struct.unpack_from("!HH", data, end)
        answer, count = b"", 0
        if name in ANSWERS and qtype == 1 and qclass == 1:
            address, ttl = ANSWERS[name]
            answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, ttl, 4) + socket.inet_aton(address)
            count = 1
        response = data[:2] + struct.pack("!5H", 0x8180, 1, count, 0, 0) + data[12:end + 4] + answer
        sock.sendto(response, self.client_address)


class RetentionUpstream(socketserver.ThreadingUDPServer):
    daemon_threads = True


def timestamp(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


@contextmanager
def held_socks_connection(port, target_port, client="127.0.0.2"):
    """Keep an echo connection alive while inspecting controller metadata."""
    with socket.socket() as sock:
        sock.settimeout(3)
        sock.bind((client, 0))
        source_port = sock.getsockname()[1]
        sock.connect(("127.0.0.1", port))
        sock.sendall(b"\x05\x01\x00")
        assert recv_exact(sock, 2) == b"\x05\x00"
        sock.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", target_port))
        header = recv_exact(sock, 4)
        assert header[:3] == b"\x05\x00\x00", header
        length = {1: 4, 4: 16}.get(header[3])
        if length is None:
            length = recv_exact(sock, 1)[0]
        recv_exact(sock, length + 2)
        sock.sendall(b"retention-held")
        assert recv_exact(sock, 14) == b"retention-held"
        yield source_port


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mosdns", type=Path, required=True)
    parser.add_argument("--mihomo", type=Path, required=True)
    parser.add_argument("--legacy-mihomo", type=Path, help="Optional older bridge-enabled kernel without retention fields")
    parser.add_argument("--work-dir", type=Path, required=True)
    args = parser.parse_args()
    work = args.work_dir.resolve()
    work.mkdir(parents=True, exist_ok=True)
    processes, logs, servers = [], [], []
    result = {"status": "running", "work_dir": str(work), "checks": {}}

    def check(name, detail="pass"):
        result["checks"][name] = detail
        print(f"PASS {name}", flush=True)

    def start(name, command):
        log = (work / f"{name}.log").open("wb")
        logs.append(log)
        process = subprocess.Popen([str(arg) for arg in command], cwd=work, stdout=log, stderr=subprocess.STDOUT)
        processes.append(process)
        return process

    def check_processes():
        for process in processes:
            if process.poll() is not None:
                raise RuntimeError(f"child exited with {process.returncode}; inspect {work}")

    def wait_http(url):
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            check_processes()
            try:
                return get_json(url)
            except (OSError, RuntimeError, ValueError):
                time.sleep(0.05)
        raise TimeoutError(f"service did not start: {url}")

    def wait_socks(port):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            check_processes()
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
        upstream = RetentionUpstream(("127.0.0.1", 0), RetentionDNSHandler)
        echo = EchoServer(("127.0.0.1", 0), EchoHandler)
        udp_echo = UDPEchoServer(("127.0.0.1", 0), UDPEchoHandler)
        servers = [upstream, echo, udp_echo]
        for server in servers:
            threading.Thread(target=server.serve_forever, daemon=True).start()
        dns_port, api_port = free_port(), free_port()
        plugins = [
            {"tag": "domain_index", "type": "domain_mapping", "args": {
                "size": 262144, "allocation": {"enable": False}, "retention": {"mode": "lru"}}},
            {"tag": "cold_index", "type": "domain_mapping", "args": {
                "retention": {"mode": "lru", "ttl_multiplier": 1, "min_window": 1, "max_window": 1}}},
            {"tag": "local_forward", "type": "forward", "args": {
                "upstreams": [{"addr": f"udp://127.0.0.1:{upstream.server_address[1]}"}]}},
            {"tag": "main", "type": "sequence", "args": [
                {"exec": "$domain_index"}, {"exec": "$cold_index"}, {"exec": "$local_forward"}]},
        ]
        for transport in ("udp", "tcp"):
            plugins.append({"tag": transport, "type": f"{transport}_server", "args": {
                "entry": "main", "listen": f"127.0.0.1:{dns_port}", "trusted_ecs": ["127.0.0.1/32"]}})
        mos_config = work / "mosdns.yaml"
        mos_config.write_text(json.dumps({"log": {"level": "warn"}, "api": {"http": f"127.0.0.1:{api_port}"}, "plugins": plugins}), encoding="utf-8")
        start("mosdns", [args.mosdns.resolve(), "start", "-c", mos_config, "-d", work])
        api_root = f"http://127.0.0.1:{api_port}/plugins"

        def lookup(index="domain_index", address="127.0.0.1", client="127.0.0.2", route=False):
            parameters = {"ip": address, "client": client, "view": "route" if route else "full"}
            return get_json(f"{api_root}/{index}/v1/lookup?" + urllib.parse.urlencode(parameters))

        def stats(index="domain_index"):
            return get_json(f"{api_root}/{index}/v1/stats")

        def query(name, client="127.0.0.2", tcp=False):
            response = dns_query(dns_port, name, "127.0.0.1", ecs=client, tcp=tcp, raw=True)
            address, ttl = ANSWERS[name]
            answers = [(rr[3], str(socket.inet_ntoa(rr[4]))) for rr in records(response) if rr[1] == 1]
            assert answers == [(ttl, address)], answers
            return response

        wait_http(f"{api_root}/domain_index/v1/stats")
        for index in ("domain_index", "cold_index"):
            observed = stats(index)
            assert observed["retention_mode"] == "lru" and observed["observation_capacity"] == 262144, observed

        def launch_mihomo(binary, name):
            socks_port, controller_port = free_port(), free_port()
            config = {
                "mixed-port": socks_port, "bind-address": "127.0.0.1", "allow-lan": True,
                "mode": "rule", "log-level": "warning", "find-process-mode": "off",
                "external-controller": f"127.0.0.1:{controller_port}", "dns": {"enable": False},
                "sniffer": {"enable": False}, "profile": {"store-selected": False},
                "domain-mapping": {"enable": True, "timeout": 200, "providers": [{
                    "name": "mosdns", "type": "mosdns-http-v1", "endpoint": f"{api_root}/domain_index/v1/lookup"}]},
                "rules": ["DOMAIN,short.retention.test,DIRECT", "DOMAIN,replacement.retention.test,REJECT", "MATCH,REJECT"],
            }
            config_path = work / f"{name}.yaml"
            config_path.write_text(json.dumps(config), encoding="utf-8")
            start(name, [binary.resolve(), "-d", work / f"{name}-home", "-f", config_path])
            controller = f"http://127.0.0.1:{controller_port}"
            version = wait_http(controller + "/version")
            wait_socks(socks_port)
            return socks_port, controller, version

        socks_port, controller, version = launch_mihomo(args.mihomo, "mihomo")
        result["mihomo_version"] = version
        target_port, udp_target = echo.server_address[1], udp_echo.server_address[1]
        # With no observations there can be no numeric-destination DOMAIN hit.
        socks_echo(socks_port, target_port, expect_success=False)
        socks_udp_echo(socks_port, udp_target, expect_success=False)
        check("missing evidence reaches MATCH REJECT for TCP and UDP")

        query("short.retention.test")
        query("short.retention.test", client="127.0.0.3", tcp=True)
        query("long.retention.test")
        query("zero.retention.test")
        query("cold.retention.test")
        short_initial = lookup()
        assert short_initial["domain"] == "short.retention.test" and short_initial["scope"] == "client", short_initial
        assert timestamp(short_initial["expires_at"]) - time.time() > 299, short_initial
        zero = lookup(address="203.0.113.11", route=True)
        assert zero["status"] == "hit" and zero["dns_stale"] and zero["retention_mode"] == "lru", zero
        check("TTL zero is retained without changing the DNS answer")

        before_long = time.time()
        long = lookup(address="203.0.113.10", route=True)
        assert timestamp(long["expires_at"]) >= before_long + 2999, long
        assert 299 <= timestamp(long["dns_expires_at"]) - time.time() <= 301, long
        check("TTL 300 grants a 3000 second routing lease")

        # No polling or route lookup may keep the cold index alive during wait.
        time.sleep(6.2)
        check_processes()
        stale = lookup()
        assert stale["dns_stale"] and stale["domain"] == "short.retention.test", stale
        assert timestamp(stale["dns_expires_at"]) < time.time() and timestamp(stale["expires_at"]) > time.time(), stale
        cold = lookup(index="cold_index", address="203.0.113.12", route=True)
        assert cold["status"] == "hit" and cold["dns_stale"], cold
        assert timestamp(cold["expires_at"]) > time.time(), cold
        check("cold LRU evidence survives beyond its one second lease")

        counters_before = {index: stats(index) for index in ("domain_index", "cold_index")}
        for _ in range(8):
            for index in counters_before:
                lookup(index=index)
                lookup(index=index, client="127.0.0.9")
                stats(index)
        counters_after = {index: stats(index) for index in counters_before}
        for index, before in counters_before.items():
            after = counters_after[index]
            for field in ("retention_touches", "retention_renewals", "observations", "observation_evictions"):
                assert before.get(field, 0) == after.get(field, 0), (index, field, before, after)
        check("full diagnostics and stats do not touch or renew retained observations")

        for _ in range(5):
            socks_echo(socks_port, target_port)
            socks_udp_echo(socks_port, udp_target)
        check("TTL 5 stale evidence routes numeric TCP and UDP after 6 seconds")

        with held_socks_connection(socks_port, target_port) as source_port:
            connections = get_json(controller + "/connections")["connections"]
            matching = [item for item in connections if str(item["metadata"].get("sourcePort")) == str(source_port) and item["metadata"].get("sourceIP") == "127.0.0.2"]
            assert len(matching) == 1, matching
            metadata = matching[0]["metadata"]
            diagnostic = metadata["domainResolution"]
            assert metadata["domainMappingHost"] == "short.retention.test", metadata
            assert diagnostic["dnsStale"] and diagnostic["retentionMode"] == "lru", diagnostic
            assert timestamp(diagnostic["dnsExpiresAt"]) < time.time() < timestamp(diagnostic["expiresAt"]), diagnostic
            result["stale_connection_diagnostics"] = diagnostic
        check("Mihomo controller exposes DNS expiry, stale status, and retention mode")

        query("replacement.retention.test")
        replaced = lookup(route=True)
        unaffected = lookup(client="127.0.0.3", route=True)
        assert replaced["domain"] == "replacement.retention.test" and replaced["conflict"], replaced
        assert unaffected["domain"] == "short.retention.test" and unaffected["scope"] == "client", unaffected
        socks_echo(socks_port, target_port, expect_success=False)
        socks_udp_echo(socks_port, udp_target, expect_success=False)
        socks_echo(socks_port, target_port, client="127.0.0.3")
        socks_udp_echo(socks_port, udp_target, client="127.0.0.3")
        check("latest real DNS observation changes routing without replacing another client's evidence")

        if args.legacy_mihomo:
            old_socks, old_controller, old_version = launch_mihomo(args.legacy_mihomo, "legacy-mihomo")
            socks_echo(old_socks, target_port, client="127.0.0.3")
            socks_udp_echo(old_socks, udp_target, client="127.0.0.3")
            socks_echo(old_socks, target_port, expect_success=False)
            with held_socks_connection(old_socks, target_port, client="127.0.0.3") as source_port:
                connections = get_json(old_controller + "/connections")["connections"]
                matching = [item for item in connections if str(item["metadata"].get("sourcePort")) == str(source_port) and item["metadata"].get("sourceIP") == "127.0.0.3"]
                assert len(matching) == 1, matching
                metadata = matching[0]["metadata"]
                assert metadata["domainMappingHost"] == "short.retention.test", metadata
                old_diagnostic = metadata["domainResolution"]
                assert not any(field in old_diagnostic for field in ("dnsExpiresAt", "dnsStale", "retentionMode")), "--legacy-mihomo is not an older kernel without retention support"
            result["legacy_mihomo_version"] = old_version
            check("older bridge kernel accepts additive retention API fields")

        result["final_stats"] = {index: stats(index) for index in ("domain_index", "cold_index")}
        result["status"] = "pass"
        result["completed_at"] = datetime.now(timezone.utc).isoformat()
        print(json.dumps(result, indent=2), flush=True)
    except Exception as error:
        result.update(status="fail", error=f"{type(error).__name__}: {error}")
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
                    process.wait(timeout=5)
        for server in servers:
            server.shutdown()
            server.server_close()
        for log in logs:
            log.close()
        (work / "result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
