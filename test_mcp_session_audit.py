"""Tests for mcp-session-audit."""

import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import mcp_session_audit as msa


def jline(obj):
    return json.dumps(obj)


class TestAudit(unittest.TestCase):
    def test_clean_session(self):
        lines = [
            jline({"direction": "response", "id": 0, "result": {"tools": [{"name": "search"}]}}),
            jline({"direction": "request", "id": 1, "method": "tools/call",
                   "params": {"name": "search", "arguments": {"q": "x"}}}),
            jline({"direction": "response", "id": 1,
                   "result": {"content": [{"type": "text", "text": "found it"}]}}),
        ]
        findings = msa.audit(lines)
        self.assertEqual(findings, [])

    def test_dangling_tool_call(self):
        lines = [
            jline({"direction": "request", "id": 1, "method": "tools/call",
                   "params": {"name": "boom"}}),
            jline({"direction": "request", "id": 2, "method": "tools/call",
                   "params": {"name": "ok"}}),
            jline({"direction": "response", "id": 2,
                   "result": {"content": [{"type": "text", "text": "fine"}]}}),
        ]
        f = msa.audit(lines)
        crit = [x for x in f if x[0] == msa.CRITICAL and x[1] == "dangling-call"]
        self.assertEqual(len(crit), 1)
        self.assertIn("opencode #44852", crit[0][2])

    def test_orphan_response(self):
        lines = [jline({"direction": "response", "id": 9,
                        "result": {"content": []}})]
        f = msa.audit(lines)
        self.assertTrue(any(x[1] == "orphan-response" for x in f))

    def test_duplicate_response(self):
        lines = [
            jline({"direction": "request", "id": 1, "method": "tools/call", "params": {}}),
            jline({"direction": "response", "id": 1, "result": {"content": []}}),
            jline({"direction": "response", "id": 1, "result": {"content": []}}),
        ]
        f = msa.audit(lines)
        self.assertTrue(any(x[1] == "duplicate-response" and x[0] == msa.CRITICAL
                            for x in f))

    def test_both_result_and_error(self):
        lines = [
            jline({"direction": "request", "id": 1, "method": "tools/call", "params": {}}),
            jline({"direction": "response", "id": 1, "result": {}, "error": {"code": -32000, "message": "x"}}),
        ]
        f = msa.audit(lines)
        self.assertTrue(any(x[1] == "both-result-and-error" for x in f))

    def test_iserror_empty(self):
        lines = [
            jline({"direction": "request", "id": 1, "method": "tools/call", "params": {}}),
            jline({"direction": "response", "id": 1, "result": {"isError": True, "content": []}}),
        ]
        f = msa.audit(lines)
        self.assertTrue(any(x[1] == "iserror-empty" for x in f))

    def test_error_as_text(self):
        lines = [
            jline({"direction": "request", "id": 1, "method": "tools/call",
                   "params": {"name": "search"}}),
            jline({"direction": "response", "id": 1,
                   "result": {"content": [{"type": "text", "text": "Unknown tool: searh"}]}}),
        ]
        f = msa.audit(lines)
        self.assertTrue(any(x[1] == "error-as-text" for x in f))

    def test_unknown_tool(self):
        lines = [
            jline({"direction": "response", "id": 0, "result": {"tools": [{"name": "a"}]}}),
            jline({"direction": "request", "id": 1, "method": "tools/call",
                   "params": {"name": "zzz"}}),
            jline({"direction": "response", "id": 1, "result": {"content": []}}),
        ]
        f = msa.audit(lines)
        self.assertTrue(any(x[1] == "unknown-tool" and x[0] == msa.CRITICAL for x in f))

    def test_exec_failures_as_rpc(self):
        lines = [
            jline({"direction": "request", "id": 1, "method": "tools/call", "params": {}}),
            jline({"direction": "response", "id": 1, "error": {"code": -32000, "message": "db down"}}),
            jline({"direction": "request", "id": 2, "method": "tools/call", "params": {}}),
            jline({"direction": "response", "id": 2, "error": {"code": -32000, "message": "db down 2"}}),
        ]
        f = msa.audit(lines)
        self.assertTrue(any(x[1] == "exec-failure-as-rpc-error" for x in f))

    def test_malformed_error_object(self):
        lines = [
            jline({"direction": "request", "id": 1, "method": "tools/call", "params": {}}),
            jline({"direction": "response", "id": 1, "error": "boom"}),
        ]
        f = msa.audit(lines)
        self.assertTrue(any(x[1] == "malformed-error" for x in f))

    def test_notification_no_id(self):
        lines = [jline({"direction": "request", "method": "tools/call", "params": {}})]
        f = msa.audit(lines)
        self.assertTrue(any(x[1] == "notification-no-id" for x in f))

    def test_junk_lines_skipped(self):
        f = msa.audit(["not json", "[1,2,3]", jline({"direction": "response", "id": 1, "result": {}})])
        self.assertTrue(any(x[1] == "unparseable-line" for x in f))

    def test_exit_codes(self):
        d = tempfile.mkdtemp()
        clean = os.path.join(d, "clean.jsonl")
        with open(clean, "w") as fh:
            fh.write(jline({"direction": "request", "id": 1, "method": "tools/call",
                            "params": {"name": "t"}}) + "\n")
            fh.write(jline({"direction": "response", "id": 1,
                            "result": {"content": [{"type": "text", "text": "ok"}]}}) + "\n")
        dirty = os.path.join(d, "dirty.jsonl")
        with open(dirty, "w") as fh:
            fh.write(jline({"direction": "request", "id": 1, "method": "tools/call",
                            "params": {"name": "t"}}) + "\n")
        script = os.path.join(os.path.dirname(msa.__file__), "mcp_session_audit.py")
        self.assertEqual(subprocess.run([sys.executable, script, clean],
                                        capture_output=True).returncode, 0)
        self.assertEqual(subprocess.run([sys.executable, script, dirty],
                                        capture_output=True).returncode, 2)


if __name__ == "__main__":
    unittest.main()
