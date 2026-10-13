#!/usr/bin/env python3
"""Temporary synthetic native demo. No credentials, trust or state survive exit."""
import argparse
import base64
import contextlib
import http.cookiejar
import json
import os
from pathlib import Path
import queue
import shutil
import signal
import socket
import socketserver
import string
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request


class DemoError(Exception):
    pass


def write_json(path, value):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as file:
        json.dump(value, file)
        file.write("\n")


def render_template(name, root, address=""):
    template = Path(__file__).with_name(name).read_text(encoding="utf-8")
    return json.loads(string.Template(template).substitute(
        DEMO_ROOT=str(root), CONTROL_ADDRESS=address))


class OwnedProcess:
    def __init__(self, arguments, env):
        self.events = queue.Queue(maxsize=64)
        self.diagnostic = False
        self.process = subprocess.Popen(arguments, env=env, stdin=subprocess.DEVNULL,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        text=True, start_new_session=True)
        self.readers = [threading.Thread(target=self.read_output),
                        threading.Thread(target=self.read_diagnostics)]
        for reader in self.readers:
            reader.start()

    def read_output(self):
        with self.process.stdout as stream:
            for line in stream:
                if len(line) > 1 << 20:
                    self.diagnostic = True
                    continue
                try:
                    event = json.loads(line)
                except ValueError:
                    event = {"launch": line.strip()} if line.startswith("http://127.0.0.1:") else {}
                try:
                    self.events.put_nowait(event)
                except queue.Full:
                    pass

    def read_diagnostics(self):
        with self.process.stderr as stream:
            while stream.read(4096):
                self.diagnostic = True  # Never print child diagnostics or bearer material.

    def wait_event(self, key, value=None):
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise DemoError("owned process exited before readiness")
            try:
                event = self.events.get(timeout=0.1)
            except queue.Empty:
                continue
            if key in event and (value is None or event[key] == value):
                return event
        raise DemoError("owned process readiness timed out")

    def close(self):
        forced = False
        if self.process.poll() is None:
            os.killpg(self.process.pid, signal.SIGINT)
            try:
                self.process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                forced = True
                os.killpg(self.process.pid, signal.SIGKILL)
                self.process.wait(timeout=3)
        for reader in self.readers:
            reader.join(timeout=2)
        if forced or self.process.returncode != 0 or self.diagnostic or any(
                reader.is_alive() for reader in self.readers):
            raise DemoError("owned process did not exit cleanly")


class EchoHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        try:
            data = self.request.recv(65536)
            if data:
                self.request.sendall(self.server.prefix + data)
            while data:
                data = self.request.recv(65536)
                if data:
                    self.request.sendall(data)
        except (OSError, TimeoutError):
            pass


class EchoServer(socketserver.ThreadingTCPServer):
    daemon_threads = False
    block_on_close = True

    def __init__(self, prefix):
        self.prefix = prefix
        self.slots = threading.BoundedSemaphore(16)
        super().__init__(("127.0.0.1", 0), EchoHandler)
        self.thread = threading.Thread(target=self.serve_forever,
                                       kwargs={"poll_interval": 0.1})
        self.thread.start()

    @property
    def address(self):
        return "%s:%d" % self.server_address

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()

    def handle_error(self, request, client_address):
        pass  # Fixture payload/diagnostics are never logs.

    def close(self):
        self.shutdown()
        self.server_close()
        self.thread.join(timeout=2)
        if self.thread.is_alive():
            raise DemoError("echo target did not join")


def probe(address, prefix):
    host, port = address.rsplit(":", 1)
    payload = b"kavern-local-demo"
    with socket.create_connection((host, int(port)), timeout=3) as stream:
        stream.settimeout(3)
        stream.sendall(payload)
        stream.shutdown(socket.SHUT_WR)
        data = bytearray()
        while True:
            part = stream.recv(4096)
            if not part:
                break
            data.extend(part)
            if len(data) > 4096:
                raise DemoError("TCP receipt exceeded fixture bound")
    if bytes(data) != prefix + payload:
        raise DemoError("TCP target receipt mismatch")


def bridge_smoke(launch, revision):
    parsed = urllib.parse.urlsplit(launch)
    if parsed.scheme != "http" or parsed.hostname != "127.0.0.1":
        raise DemoError("unexpected bridge endpoint")
    code = urllib.parse.parse_qs(parsed.fragment).get("launch", [])
    if len(code) != 1:
        raise DemoError("invalid one-use bridge launch")
    origin = "http://" + parsed.netloc
    base = origin + parsed.path
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    bootstrap = urllib.request.Request(base + "session/bootstrap",
                                       json.dumps({"code": code[0]}).encode(),
                                       {"Origin": origin, "Content-Type": "application/json"})
    with opener.open(bootstrap, timeout=5) as response:
        token = json.load(response)["request_token"]
    request = urllib.request.Request(base + "api/devices/demo-device/status",
                                     headers={"X-Kavern-UI-Token": token})
    with opener.open(request, timeout=5) as response:
        status = json.load(response)
    if not status["ready"] or status["desired_revision"] != revision:
        raise DemoError("bridge sampled readiness/revision mismatch")
    logout = urllib.request.Request(base + "session/logout", b"{}",
                                    {"Origin": origin, "Content-Type": "application/json",
                                     "X-Kavern-UI-Token": token})
    with opener.open(logout, timeout=5) as response:
        if not json.load(response)["ok"]:
            raise DemoError("bridge logout failed")


def run_demo(bin_dir, interactive):
    if sys.platform != "linux":
        raise DemoError("native local administration example requires Linux")
    if not shutil.which("openssl"):
        raise DemoError("example requires installed OpenSSL; nothing is downloaded")
    bins = {name: bin_dir / name for name in ("kavernd", "kavern-agent", "kavernctl")}
    if any(not path.is_file() or not os.access(path, os.X_OK) for path in bins.values()):
        raise DemoError("build the three Kavern binaries first")
    with tempfile.TemporaryDirectory(prefix="kavern-demo-", dir="/tmp") as directory:
        root = Path(directory)
        private = root / "r"
        tls = root / "tls"
        private.mkdir(mode=0o700)
        tls.mkdir(mode=0o700)
        admin = private / "admin.sock"
        if len(str(admin).encode()) > 100:
            raise DemoError("temporary admin socket exceeds supported path bound")
        env = os.environ.copy()
        env["KAVERN_DEMO_MASTER"] = base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("=")
        result = subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                                 "-keyout", str(tls / "server.key"), "-out", str(tls / "server.crt"),
                                 "-days", "1", "-subj", "/CN=Kavern synthetic local demo",
                                 "-addext", "subjectAltName=IP:127.0.0.1",
                                 "-addext", "extendedKeyUsage=serverAuth"],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)
        if result.returncode:
            raise DemoError("temporary TLS fixture generation failed")
        (tls / "server.key").chmod(0o600)
        server_path = root / "server.json"
        server_config = render_template("server.template.json", root)
        write_json(server_path, server_config)
        sequence = 0

        def cli(*args, rejected=None):
            result = subprocess.run([str(bins["kavernctl"]), *args], env=env,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
            if rejected is not None:
                if result.returncode == 0 or rejected.encode() not in result.stderr:
                    raise DemoError("expected actor rejection not observed")
                return None
            if result.returncode or result.stderr:
                raise DemoError("documented CLI step failed")
            return result.stdout

        def online(action, *args, rejected=None):
            raw = cli("online", "--socket", str(admin), action, *args, rejected=rejected)
            return json.loads(raw) if raw is not None else None

        def mutation(kind, action, credential=None, **values):
            nonlocal sequence
            sequence += 1
            request = {"window": online("window"), "operation_id": "demo-operation-%d" % sequence,
                       "kind": kind, **values}
            path = root / ("request-%d.json" % sequence)
            write_json(path, request)
            args = ["--file", str(path)]
            if credential is not None:
                args += ["--credential-output", str(credential)]
            result = online(action, *args)
            if not result["saved"] or "issuance" in result:
                raise DemoError("saved result missing or credential reached stdout")
            return result, path

        cli("validate", "-kind", "server", "-config", str(server_path))
        cli("init-state", "-state", server_config["state_file"], "-master-key-env",
            "KAVERN_DEMO_MASTER", "-user", "demo-owner", "-project", "demo-project")
        with contextlib.ExitStack() as cleanup:
            first = EchoServer(b"first:")
            cleanup.callback(first.close)
            second = EchoServer(b"second:")
            cleanup.callback(second.close)

            def own(arguments, child_env=env):
                process = OwnedProcess(arguments, child_env)
                cleanup.callback(process.close)
                return process

            daemon = own([str(bins["kavernd"]), "-config", str(server_path)])
            control = daemon.wait_event("event", "server_ready")["control"]
            server_config["control_listen"] = control  # Restart binds the original synthetic endpoint.
            write_json(server_path, server_config)
            credential_path = private / "device.json"
            _, creation_request = mutation("create_device", "create-device", credential_path,
                                           device={"ID": "demo-device", "ProjectID": "demo-project",
                                                   "Name": "Synthetic demo device", "Enabled": True},
                                           credential_kind="kapv1_device_secret")
            with credential_path.open(encoding="utf-8") as file:
                credential = json.load(file)["issuance"]["credential"]
            if credential_path.stat().st_mode & 0o777 != 0o600:
                raise DemoError("protected issuance file mode mismatch")
            replay = online("retry", "--file", str(creation_request))
            if not replay["saved"] or "issuance" in replay:
                raise DemoError("original creation receipt/retry contract failed")
            configuration = online("get-device", "--id", "demo-device")
            configuration["Tunnels"] = [{"ID": "demo-tcp", "DeviceID": "demo-device",
                                          "Protocol": "tcp", "Listener": "127.0.0.1:0",
                                          "TargetAddr": first.address, "Enabled": True}]

            def put(value):
                return mutation("put_device", "put-device", device_id="demo-device",
                                expected_revision=value["Revision"], configuration=value)[0]

            saved = put(configuration)
            # Reuse the old device revision with a fresh operation/window: explicit CAS rejection.
            sequence += 1
            stale_path = root / "stale.json"
            write_json(stale_path, {"window": online("window"), "operation_id": "demo-stale",
                                    "kind": "put_device", "device_id": "demo-device",
                                    "expected_revision": configuration["Revision"],
                                    "configuration": configuration})
            online("put-device", "--file", str(stale_path), rejected="revision_conflict")
            agent_path = root / "agent.json"
            write_json(agent_path, render_template("agent.template.json", root, control))
            cli("validate", "-kind", "agent", "-config", str(agent_path))
            agent_env = {**env, "KAVERN_DEMO_DEVICE": credential}
            agent = own([str(bins["kavern-agent"]), "-config", str(agent_path)], agent_env)
            agent.wait_event("event", "agent_ready")

            def wait_status(predicate):
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    status = online("device-status", "--id", "demo-device")
                    if predicate(status):
                        return status
                    time.sleep(0.05)
                raise DemoError("sampled device status did not converge")

            def ready(revision):
                return wait_status(lambda s: s["ready"] and s["desired_revision"] == revision
                                   and s["session"]["applied_revision"] == revision)

            status = ready(saved["revision"])
            probe(status["listeners"][0]["bound_address"], b"first:")
            configuration = online("get-device", "--id", "demo-device")
            configuration["Tunnels"][0]["TargetAddr"] = second.address
            saved = put(configuration)
            status = ready(saved["revision"])
            probe(status["listeners"][0]["bound_address"], b"second:")
            configuration = online("get-device", "--id", "demo-device")
            configuration["Device"]["Enabled"] = False
            put(configuration)
            wait_status(lambda s: not s["device"]["Enabled"] and not s["ready"] and not s["session"]["present"])
            configuration = online("get-device", "--id", "demo-device")
            configuration["Device"]["Enabled"] = True
            saved = put(configuration)
            ready(saved["revision"])
            daemon.close()
            daemon = own([str(bins["kavernd"]), "-config", str(server_path)])
            daemon.wait_event("event", "server_ready")
            status = ready(saved["revision"])
            probe(status["listeners"][0]["bound_address"], b"second:")
            ui = own([str(bins["kavernctl"]), "ui", "--socket", str(admin),
                      "--credential-dir", str(private)])
            launch = ui.wait_event("launch")["launch"]
            if interactive:
                print("Synthetic local fixture only; all state/trust/credentials are deleted on exit.")
                print("Public TCP: " + status["listeners"][0]["bound_address"])
                print("Targets on this demo device: " + first.address + " and " + second.address)
                print("Bootstrap files (secret-free): " + str(server_path) + " and " + str(agent_path))
                print("Native credential stays in the private fixture file; never in the browser.")
                print("Open within two minutes; one-use local WebUI launch: " + launch, flush=True)
                try:
                    input("Press Enter or Ctrl-C to stop and delete this synthetic fixture.\n")
                except EOFError:
                    pass
            else:
                bridge_smoke(launch, saved["revision"])
        # ExitStack joins processes/echo workers before TemporaryDirectory removes material.
    print("PASS: native create/sync/TCP, target edit, stale CAS, disable/enable, restart/reconnect, WebUI bridge auth/status/logout and joined temporary cleanup")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", type=Path, default=Path("build/bin"))
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--smoke", action="store_true", help="bounded noninteractive synthetic acceptance")
    mode.add_argument("--interactive", action="store_true", help="explicitly open a temporary local demo")
    args = parser.parse_args()
    try:
        run_demo(args.bin_dir.resolve(), args.interactive)
    except KeyboardInterrupt:
        return 0  # Context managers still join and delete their owned fixture.
    except DemoError as error:
        print("FAIL: " + str(error), file=sys.stderr)
        return 1
    except Exception:
        print("FAIL: unexpected local fixture failure (sensitive details suppressed)", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
