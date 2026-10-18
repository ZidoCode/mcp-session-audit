#!/usr/bin/env python3
"""mcp-session-audit — audit a recorded MCP session for protocol hygiene failures.

MCP sessions fail in ways that never surface as crashes: a tool call whose
result was lost mid-batch poisons every later request with dangling
tool_call_ids (opencode #44852); an isError:true envelope gets swallowed and
the model reads the error text as output (zeroclaw #7122, claude-agent-sdk
#717/#564); an execution failure is delivered as a JSON-RPC error so the
model never learns why its call failed (memoria #258); a validator clobbers
isError back to success and inflates the success rate (IBM mcp-context-forge
#4202). All of these are visible in a recorded transcript — if something
actually looks.

This tool looks. Input: JSONL where each line is one recorded message:
  {"direction":"request","id":1,"method":"tools/call","params":{...}}
  {"direction":"response","id":1,"result":{...}}          # or "error":{...}
(direction defaults to "response" when a line has a result/error and no
method; bare JSON-RPC batches and raw client/server logs are tolerated.)

Checks:
  1. dangling tool call  — a request with an id that never got a response
  2. orphan response     — a response whose id was never requested
  3. duplicate response  — two responses for the same id
  4. isError swallowed   — isError:true with no is_error flag upstream and
                           content that reads as ordinary output
  5. error-channel confusion — execution failures delivered as JSON-RPC
                           errors (model never sees the text), or error text
                           inside a successful result with no isError flag
  6. unknown tool        — tools/call for a name absent from a recorded
                           tools/list result

Exit codes: 0 = clean, 1 = warnings only, 2 = any CRITICAL finding.
"""

import json
import sys

CRITICAL = "CRITICAL"
WARNING = "WARNING"
INFO = "INFO"

ERROR_CODES = {
    -32700: "parse error",
    -32600: "invalid request",
    -32601: "method not found",
    -32602: "invalid params",
    -32603: "internal error",
}


def _err_text(result):
    """Extract text content from a CallToolResult-shaped result."""
    parts = []
    content = result.get("content")
    if isinstance(content, list):
        for block in content:
            if isinstance(block, dict) and isinstance(block.get("text"), str):
                parts.append(block["text"])
    return "\n".join(parts)


def audit(lines):
    """Audit a list of parsed JSONL lines. Returns list of (severity, code, msg)."""
    findings = []
    requests = {}       # id -> method
    responded = set()   # ids that have any response
    error_responded = set()
    known_tools = None
    exec_failures_as_rpc = 0

    for n, line in enumerate(lines, 1):
        if isinstance(line, str):
            try:
                line = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                findings.append((WARNING, "unparseable-line",
                                 f"line {n}: not valid JSON, skipped"))
                continue
        if not isinstance(line, dict):
            findings.append((WARNING, "unparseable-line",
                             f"line {n}: not an object, skipped"))
            continue

        direction = line.get("direction")
        rid = line.get("id")
        method = line.get("method")

        # sniff tools/list response for the known-tool set
        if direction == "response" or (method is None and "result" in line):
            result = line.get("result")
            if isinstance(result, dict) and isinstance(result.get("tools"), list):
                # tools/list is paginated: each page carries its own slice, so
                # merge instead of overwriting (a second page used to erase the
                # first one and turn every real tool call into "unknown tool").
                page = {t.get("name") for t in result["tools"] if isinstance(t, dict)}
                known_tools = page if known_tools is None else (known_tools | page)
                if rid is not None and rid not in requests:
                    requests[rid] = "tools/list"

        if direction == "request" or method is not None:
            if method == "tools/list" and rid is not None:
                requests[rid] = method
            elif method == "tools/call":
                if rid is None:
                    findings.append((WARNING, "notification-no-id",
                                     f"line {n}: tools/call without an id — "
                                     "fire-and-forget calls cannot be paired with results"))
                else:
                    requests[rid] = method
                    params = line.get("params")
                    name = params.get("name") if isinstance(params, dict) else None
                    if known_tools is not None and name not in known_tools:
                        findings.append((CRITICAL, "unknown-tool",
                                         f"line {n}: tools/call for '{name}' — not in the "
                                         "session's tools/list result (client will hang or "
                                         "get an unhandled error)"))
            elif method is not None and rid is not None:
                requests[rid] = method

        # response shape: has result XOR error
        has_result = "result" in line
        has_error = "error" in line
        if has_result and has_error:
            findings.append((CRITICAL, "both-result-and-error",
                             f"line {n}: response carries both 'result' and 'error' — "
                             "receivers must pick one; behavior undefined"))
        if not has_result and not has_error and method is None:
            continue
        if not has_result and not has_error:
            continue

        if rid is None:
            findings.append((WARNING, "response-no-id",
                             f"line {n}: response without an id — cannot be paired "
                             "with a request"))
            continue

        if rid in responded:
            findings.append((CRITICAL, "duplicate-response",
                             f"line {n}: second response for id {rid} — clients "
                             "deserialize one; the other is lost or corrupts state"))
        responded.add(rid)

        if has_error:
            error_responded.add(rid)
            err = line["error"]
            if not isinstance(err, dict) or "code" not in err or "message" not in err:
                findings.append((CRITICAL, "malformed-error",
                                 f"line {n}: 'error' is not a JSON-RPC error object "
                                 "(needs code + message)"))
            elif requests.get(rid) == "tools/call":
                exec_failures_as_rpc += 1

        if has_result and isinstance(line.get("result"), dict):
            result = line["result"]
            is_err = result.get("isError")
            text = _err_text(result)
            if is_err is True:
                if not text.strip():
                    findings.append((WARNING, "iserror-empty",
                                     f"line {n}: isError:true but content carries no "
                                     "text — the model gets the failure with no detail "
                                     "and cannot self-correct"))
            else:
                # success-shaped result whose text *reads* like an error
                low = text.lower()
                if text and (low.startswith("error") or "unknown tool" in low
                             or low.startswith("auth failed") or low.startswith("failed")
                             or " 403 " in low):
                    findings.append((WARNING, "error-as-text",
                                     f"line {n}: result looks successful (no isError) "
                                     f"but text reads as a failure: {text[:60]!r} — "
                                     "clients that trust isError will read this as "
                                     "output (mcp-era-probe channel-3 behavior)"))

    # dangling / orphan pairing
    for rid, method in sorted(requests.items()):
        if rid not in responded:
            sev = CRITICAL if method == "tools/call" else WARNING
            findings.append((sev, "dangling-call",
                             f"request id {rid} ({method}) never got a response — "
                             "dangling tool_call_id poisons all later requests "
                             "(opencode #44852)"))
    for rid in sorted(responded - set(requests)):
        if rid not in error_responded or requests:
            findings.append((WARNING, "orphan-response",
                             f"response for id {rid} but no matching request — "
                             "recorder dropped the request or ids desynced"))

    if exec_failures_as_rpc >= 2:
        findings.append((WARNING, "exec-failure-as-rpc-error",
                         f"{exec_failures_as_rpc} tools/call failures delivered as "
                         "JSON-RPC errors — execution failures belong in an isError "
                         "result so the model can self-correct (memoria #258)"))

    return findings


SEV_ORDER = {CRITICAL: 0, WARNING: 1, INFO: 2}
SEV_SYM = {CRITICAL: "[CRITICAL]", WARNING: "[WARNING ]", INFO: "[INFO    ]"}


def report(path, findings):
    lines = []
    counts = {s: 0 for s in SEV_ORDER}
    for sev, code, msg in findings:
        counts[sev] += 1
        lines.append(f"  {SEV_SYM[sev]} {msg}")
    print(f"mcp-session-audit: {path}")
    if not lines:
        print("  ALL CLEAR — no dangling calls, no swallowed errors, no channel confusion.")
        return 0
    for ln in lines:
        print(ln)
    parts = [f"{counts[s]} {s.lower()}" for s in (CRITICAL, WARNING, INFO) if counts[s]]
    print(f"\n  verdict: {', '.join(parts)}.")
    if counts[CRITICAL]:
        print("  the session will hang, poison later requests, or feed errors to the model as output.")
        return 2
    return 1


def load_lines(path):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return [ln for ln in (l.strip() for l in f) if ln]


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    path = argv[0]
    try:
        lines = load_lines(path)
    except OSError as exc:
        print(f"mcp-session-audit: cannot read {path}: {exc}", file=sys.stderr)
        return 2
    return report(path, audit(lines))


if __name__ == "__main__":
    sys.exit(main())
