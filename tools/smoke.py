#!/usr/bin/env python3
"""Exercise the installed CLI, wrapper, authorization boundary and audit chain."""
import argparse
from contextlib import ExitStack
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import selectors
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


class Upstream(BaseHTTPRequestHandler):
    calls = []

    def log_message(self, *_):
        pass

    def do_POST(self):
        request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        method = request["method"]
        if "id" not in request:
            self.send_response(202)
            self.end_headers()
            return
        if method == "initialize":
            result = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                      "serverInfo": {"name": "test-upstream", "version": "1"}}
        elif method == "tools/list":
            result = {"tools": [{"name": "read_file", "inputSchema": {
                "type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}}]}
        elif method == "tools/call":
            self.calls.append(request["params"])
            result = {"content": [{"type": "text", "text": "synthetic file content"}]}
        else:
            result = {}
        body = json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/tokencrumb")
    parser.add_argument("--tls", action="store_true", help="also exercise native TLS with a temporary certificate")
    args = parser.parse_args()
    binary = str(Path(args.binary).resolve())
    with tempfile.TemporaryDirectory(prefix="tokencrumb-test-") as directory, ExitStack() as stack:
        state = Path(directory)

        def cli(*argv):
            return subprocess.run([binary, *map(str, argv)], cwd=state, check=True,
                                  capture_output=True, text=True, timeout=30).stdout

        scheme = "https" if args.tls else "http"
        tls_flags = []
        ca_flags = []
        context = None
        if args.tls:
            (state / "tls.cnf").write_text(
                "[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=extensions\n"
                "[dn]\nCN=localhost\n[extensions]\nsubjectAltName=IP:127.0.0.1\n"
                "basicConstraints=critical,CA:FALSE\nextendedKeyUsage=serverAuth\n"
            )
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                            "-days", "1", "-keyout", "tls.key", "-out", "tls.crt",
                            "-config", "tls.cnf"],
                           cwd=state, check=True, capture_output=True, timeout=30)
            tls_flags = ["--tls-cert", "tls.crt", "--tls-key", "tls.key"]
            ca_flags = ["--ca", str(state / "tls.crt")]
            context = ssl.create_default_context(cafile=str(state / "tls.crt"))
        for kind in ("authority", "agent", "audit"):
            cli("keygen", "--type", kind, "--out", kind)
        cli("forge", "--key", "authority.key", "--tool", "read_file", "--operation", "read",
            "--agent-id", "reader", "--agent-pubkey", (state / "agent.pub").read_text().strip(),
            "--required-profile", "hardened_biscuit_anchored", "--audience", "local-gateway",
            "--resource-prefix", "/workspace/", "--ttl", "15m", "--budget", "20",
            "--out", "capability.b64")
        cli("attenuate", "--token", "capability.b64", "--authority-pub", "authority.pub",
            "--resource", "/workspace/reports/", "--budget", "5", "--ttl", "5m",
            "--tool", "read_file", "--out", "restricted.b64")
        cli("inspect", "restricted.b64")
        upstream = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
        upstream.daemon_threads = True
        stack.callback(upstream.server_close)
        threading.Thread(target=upstream.serve_forever, daemon=True).start()
        stack.callback(upstream.shutdown)
        with socket.socket() as port:
            port.bind(("127.0.0.1", 0))
            listen = port.getsockname()[1]
        log = stack.enter_context((state / "process.log").open("w+"))
        proxy = subprocess.Popen([
            binary, "serve", "--upstream", f"http://127.0.0.1:{upstream.server_port}/mcp",
            "--authority-pub", "authority.pub", "--policy", str(ROOT / "policy.yaml"),
            "--audience", "local-gateway", "--audit-key", "audit.key", "--audit", "audit.log",
            "--budget-state", "budget.json", "--listen", f"127.0.0.1:{listen}", *tls_flags],
            cwd=state, stdout=log, stderr=log)
        stack.callback(stop, proxy)
        deadline = time.monotonic() + 15
        while True:
            if proxy.poll() is not None:
                log.seek(0)
                raise RuntimeError(log.read())
            try:
                with socket.create_connection(("127.0.0.1", listen), timeout=0.2):
                    break
            except OSError:
                if time.monotonic() > deadline:
                    raise TimeoutError("proxy did not listen")
                time.sleep(0.05)
        wrapper = subprocess.Popen([
            binary, "client-wrap", "--proxy", f"{scheme}://127.0.0.1:{listen}/mcp",
            "--token", "restricted.b64", "--agent-key", "agent.key", *ca_flags],
            cwd=state, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log, text=True)
        stack.callback(stop, wrapper)
        sequence = 0

        def rpc(method, params):
            nonlocal sequence
            sequence += 1
            wrapper.stdin.write(json.dumps({"jsonrpc": "2.0", "id": sequence,
                                            "method": method, "params": params}) + "\n")
            wrapper.stdin.flush()
            with selectors.DefaultSelector() as selector:
                selector.register(wrapper.stdout, selectors.EVENT_READ)
                if not selector.select(15):
                    raise TimeoutError(f"wrapper did not answer {method}")
            response = json.loads(wrapper.stdout.readline())
            assert response["id"] == sequence, response
            return response

        initialized = rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                         "clientInfo": {"name": "smoke", "version": "1"}})
        assert "result" in initialized, initialized
        assert rpc("tools/list", {})["result"]["tools"][0]["name"] == "read_file"
        allowed = rpc("tools/call", {"name": "read_file", "arguments": {"path": "/workspace/reports/a.txt"}})
        assert not allowed["result"].get("isError"), allowed
        assert len(Upstream.calls) == 1
        for path in ("/workspace/other.txt", "/private/notes.txt"):
            denied = rpc("tools/call", {"name": "read_file", "arguments": {"path": path}})
            assert denied.get("error") or denied.get("result", {}).get("isError"), denied
        assert len(Upstream.calls) == 1, "an out-of-scope request reached the upstream"
        # A bearer copy of the capability cannot impersonate the agent.
        body = json.dumps({"jsonrpc": "2.0", "id": 99, "method": "tools/call", "params": {
            "name": "read_file", "arguments": {"path": "/workspace/reports/a.txt"}}}).encode()
        request = urllib.request.Request(f"{scheme}://127.0.0.1:{listen}/mcp", data=body, headers={
            "Content-Type": "application/json", "Accept": "application/json, text/event-stream",
            "Authorization": "Biscuit " + (state / "restricted.b64").read_text().strip()})
        try:
            with urllib.request.urlopen(request, timeout=10, context=context) as response:
                denied = json.load(response)
                assert denied.get("error") or denied.get("result", {}).get("isError"), denied
        except urllib.error.HTTPError as error:
            assert error.code in (400, 401, 403), error
        assert len(Upstream.calls) == 1
        stop(wrapper)
        stop(proxy)
        cli("audit-verify", "--log", "audit.log", "--pub", "audit.pub")
        cli("audit-head", "--log", "audit.log", "--key", "audit.key", "--out", "audit-head.json")
        assert (state / "budget.json.nonces.db").exists()
        print(f"PASS ({scheme}): CLI, signed call, attenuation, scope denials, unsigned denial, persistent state and audit")


if __name__ == "__main__":
    main()
