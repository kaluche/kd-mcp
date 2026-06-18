import importlib
import sys
import types
import unittest


class _FakeFastMCP:
    def __init__(self, *_args, **_kwargs):
        self.settings = types.SimpleNamespace(
            host=None,
            port=None,
            streamable_http_path="/mcp",
            transport_security=None,
        )

    def tool(self, *_args, **_kwargs):
        def decorate(fn):
            return fn

        return decorate

    def run(self, *_args, **_kwargs):
        return None


def _install_fake_mcp():
    mcp_mod = types.ModuleType("mcp")
    server_mod = types.ModuleType("mcp.server")
    fastmcp_mod = types.ModuleType("mcp.server.fastmcp")
    fastmcp_mod.FastMCP = _FakeFastMCP
    sys.modules.setdefault("mcp", mcp_mod)
    sys.modules.setdefault("mcp.server", server_mod)
    sys.modules.setdefault("mcp.server.fastmcp", fastmcp_mod)


_install_fake_mcp()
server = importlib.import_module("kd_mcp.server")


class _FakeProc:
    pid = 4242
    returncode = None

    def poll(self):
        return None

    def wait(self, timeout=None):
        return 0

    def kill(self):
        return None

    def terminate(self):
        return None


class _PromptTimeoutKd:
    instances = []

    def __init__(self, args):
        self.args = args
        self.proc = _FakeProc()
        self.alive = True
        self.expect_calls = 0
        self.breaks = 0
        self.killed = False
        _PromptTimeoutKd.instances.append(self)

    def expect(self, _pattern, timeout=30.0):
        self.expect_calls += 1
        if self.expect_calls == 1:
            return "Kernel Debugger connection established\nWindows 10 Kernel Version test\n"
        raise TimeoutError("prompt timeout")

    def send_break(self):
        self.breaks += 1

    def read_available(self):
        return "symbol validation still running"

    def kill(self, wait=5.0):
        self.killed = True
        self.alive = False

    def is_alive(self):
        return self.alive


class _ResyncKd:
    def __init__(self, *, expect_result=None, read_result=""):
        self.expect_result = expect_result
        self.read_result = read_result
        self.breaks = 0
        self.drained = False

    def send_break(self):
        self.breaks += 1

    def expect(self, _pattern, timeout=30.0):
        if isinstance(self.expect_result, BaseException):
            raise self.expect_result
        return self.expect_result

    def read_available(self):
        return self.read_result

    def drain(self):
        self.drained = True


class _CommandKd:
    proc = _FakeProc()

    def __init__(self, output):
        self.output = output
        self.sent = []
        self.drained = False

    def drain(self):
        self.drained = True

    def sendline(self, cmd):
        self.sent.append(cmd)

    def expect(self, _pattern, timeout=30.0):
        return self.output

    def is_alive(self):
        return True

    def kill(self, wait=5.0):
        return None


class ServerFailureHandlingTests(unittest.TestCase):
    def setUp(self):
        server.STATE.kd = None
        server.STATE.last_connect_string = ""
        server.STATE.state = "disconnected"
        server.STATE.last_error = ""
        server.STATE.last_output_tail = ""
        server.STATE.last_pid = None

    def tearDown(self):
        server.STATE.kd = None
        server.STATE.last_connect_string = ""
        server.STATE.state = "disconnected"
        server.STATE.last_error = ""
        server.STATE.last_output_tail = ""
        server.STATE.last_pid = None

    def test_risky_raw_command_is_rejected_before_touching_kd(self):
        with self.assertRaisesRegex(ValueError, "Refusing risky kd command"):
            server._cmd("uf http!UlpInsertBuffer")

    def test_resync_success_marks_session_connected(self):
        kd = _ResyncKd(expect_result="interrupted\nkd> ")

        with self.assertRaisesRegex(TimeoutError, "resynced the session"):
            server._resync_locked(kd, "x http!Foo", 1.0)

        self.assertEqual(server.STATE.state, "connected")
        self.assertTrue(kd.drained)
        self.assertEqual(kd.breaks, 1)

    def test_resync_timeout_marks_session_desynced(self):
        kd = _ResyncKd(expect_result=TimeoutError("no prompt"), read_result="still busy")

        with self.assertRaises(server.KdDesyncError):
            server._resync_locked(kd, "uf http!Foo", 1.0)

        self.assertEqual(server.STATE.state, "desynced")
        self.assertIn("still busy", server.STATE.last_output_tail)

    def test_resync_transport_loss_is_distinct(self):
        kd = _ResyncKd(
            expect_result=TimeoutError("no prompt"),
            read_result="Retry sending the same data packet for 64 times",
        )

        with self.assertRaises(server.KdTransportLost):
            server._resync_locked(kd, "s -d ffff L100 41414141", 1.0)

        self.assertEqual(server.STATE.state, "transport_lost")

    def test_kernel_attach_keeps_process_after_prompt_validation_timeout(self):
        original = server.KdProcess
        _PromptTimeoutKd.instances = []
        server.KdProcess = _PromptTimeoutKd
        try:
            result = server.kernel_attach.__wrapped__("net:port=1,key=2", timeout=1)
        finally:
            server.KdProcess = original

        self.assertEqual(result["status"], "connected")
        self.assertEqual(result["validation"], "prompt_timeout")
        self.assertEqual(server.STATE.state, "connected")
        self.assertIs(server.STATE.kd, _PromptTimeoutKd.instances[0])
        self.assertFalse(_PromptTimeoutKd.instances[0].killed)

    def test_status_reports_state_without_kd_command(self):
        kd = _PromptTimeoutKd(["kd.exe"])
        server.STATE.kd = kd
        server.STATE.state = "connected"
        server.STATE.last_connect_string = "net:port=1,key=2"

        result = server.status()

        self.assertTrue(result["connected"])
        self.assertEqual(result["state"], "connected")
        self.assertEqual(result["pid"], 4242)

    def test_successful_command_clears_stale_failure_state(self):
        server.STATE.kd = _CommandKd("vertarget\nWindows test\nkd> ")
        server.STATE.state = "desynced"
        server.STATE.last_error = "old failure"

        output = server._cmd("vertarget")

        self.assertEqual(output, "Windows test")
        self.assertEqual(server.STATE.state, "connected")
        self.assertEqual(server.STATE.last_error, "")


if __name__ == "__main__":
    unittest.main()
