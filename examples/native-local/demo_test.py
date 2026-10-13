"""Example acceptance: own built binaries, temporary material, terminal cleanup."""
import contextlib
import io
import json
import os
from pathlib import Path
import queue
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

import demo


class DemoAcceptance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        value = os.environ.get("KAVERN_EXAMPLE_BIN_DIR")
        if not value:
            raise RuntimeError("example-tests requires KAVERN_EXAMPLE_BIN_DIR; use make example-tests")
        cls.bin_dir = Path(value)

    @contextlib.contextmanager
    def tracked_directories(self):
        original = tempfile.TemporaryDirectory
        created = []

        def create(*args, **kwargs):
            directory = original(*args, **kwargs)
            created.append(Path(directory.name))
            return directory

        with mock.patch.object(demo.tempfile, "TemporaryDirectory", side_effect=create):
            yield created
        self.assertTrue(created)
        self.assertTrue(all(not path.exists() for path in created), "temporary material remained")

    def test_templates_keep_business_configuration_on_server(self):
        root = Path("/tmp/synthetic-template")
        agent = demo.render_template("agent.template.json", root, "127.0.0.1:8024")
        self.assertEqual(set(agent), {"server", "device_id", "secret_env", "ca_file"})
        server = demo.render_template("server.template.json", root)
        self.assertNotIn("limits", server)
        self.assertNotIn("targets", agent)
        self.assertEqual(server["master_key_env"], "KAVERN_DEMO_MASTER")

    def test_actual_smoke_joins_and_removes_material(self):
        with self.tracked_directories(), contextlib.redirect_stdout(io.StringIO()) as output:
            demo.run_demo(self.bin_dir, False)
        text = output.getvalue()
        self.assertIn("PASS:", text)
        self.assertNotIn("#launch=", text)
        self.assertNotIn('"credential"', text)

    def test_failure_after_daemon_ready_joins_and_removes_material(self):
        original = demo.OwnedProcess.wait_event

        def fail_after_ready(process, key, value=None):
            original(process, key, value)
            raise demo.DemoError("synthetic acceptance interruption")

        with self.tracked_directories(), mock.patch.object(
                demo.OwnedProcess, "wait_event", fail_after_ready):
            with self.assertRaises(demo.DemoError):
                demo.run_demo(self.bin_dir, False)

    def test_interactive_launch_and_enter_cleanup(self):
        process = subprocess.Popen([sys.executable, str(Path(demo.__file__)),
                                    "--bin-dir", str(self.bin_dir), "--interactive"],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True, start_new_session=True)
        events = queue.Queue(maxsize=32)

        def read():
            with process.stdout as stream:
                for line in stream:
                    events.put(line)

        reader = threading.Thread(target=read)
        reader.start()
        root = None
        try:
            deadline = time.monotonic() + 25
            launch = None
            while time.monotonic() < deadline:
                try:
                    line = events.get(timeout=0.1)
                except queue.Empty:
                    if process.poll() is not None:
                        break
                    continue
                if line.startswith("Bootstrap files (secret-free): "):
                    root = Path(line.split(": ", 1)[1].split(" and ", 1)[0]).parent
                if "one-use local WebUI launch: " in line:
                    launch = line.split("one-use local WebUI launch: ", 1)[1].strip()
                    break
            self.assertIsNotNone(launch, "interactive launch not delivered")
            # Do not print/capture the launch credential in test output/artifacts.
            demo.bridge_smoke(launch, "5")  # Script's five definite device revisions.
            process.stdin.write("\n")
            process.stdin.flush()
            process.wait(timeout=12)
            reader.join(timeout=2)
            self.assertEqual(process.returncode, 0)
            self.assertFalse(reader.is_alive())
            self.assertFalse(process.stderr.read(), "interactive child diagnostics present")
            self.assertIsNotNone(root)
            self.assertFalse(root.exists(), "interactive fixture material remained")
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGINT)
                try:
                    process.wait(timeout=12)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=3)
            process.stdin.close()
            process.stderr.close()
            reader.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
