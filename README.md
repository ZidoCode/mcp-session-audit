# mcp-session-audit

**Audit a recorded MCP session for protocol hygiene failures. Offline, deterministic, zero dependencies.**

MCP sessions fail in ways that never surface as crashes — they surface as the model
quietly doing the wrong thing:

- a failed parallel tool call leaves a **dangling tool_call_id** that poisons every
  later request ([opencode #44852](https://github.com/anomalyco/opencode/issues/44852))
- `isError:true` gets **swallowed** and the error text is read as ordinary output
  ([zeroclaw #7122](https://github.com/zeroclaw-labs/zeroclaw/pull/7122),
  [claude-agent-sdk #717](https://github.com/anthropics/claude-agent-sdk-python/pull/717))
- an execution failure is delivered as a **JSON-RPC error**, so the model never
  learns why its call failed ([memoria #258](https://github.com/matrixorigin/memoria/issues/258))
- a validator **clobbers isError back to success**, inflating success rates
  ([IBM mcp-context-forge #4202](https://github.com/IBM/mcp-context-forge/issues/4202))

All of these are visible in a recorded transcript. This tool looks.

## What it detects

| Severity | Finding |
|---|---|
| CRITICAL | dangling tool call (request never answered) |
| CRITICAL | duplicate response for the same id |
| CRITICAL | response with both `result` and `error` |
| CRITICAL | tools/call for a name absent from the session's tools/list |
| CRITICAL | malformed JSON-RPC error object |
| WARNING  | orphan response (no matching request) |
| WARNING  | `isError:true` with no error text (model can't self-correct) |
| WARNING  | success-shaped result whose text reads as a failure |
| WARNING  | execution failures delivered as JSON-RPC errors |
| WARNING  | unparseable / shapeless lines |

## Input format

JSONL, one recorded message per line:

```jsonl
{"direction":"request","id":1,"method":"tools/call","params":{"name":"search","arguments":{"q":"x"}}}
{"direction":"response","id":1,"result":{"content":[{"type":"text","text":"found it"}]}}
```

`direction` defaults to `response` when a line has a `result`/`error` and no
`method` — raw JSON-RPC client/server logs are tolerated.

## Usage

```
python3 mcp_session_audit.py session.jsonl
```

Exit codes (CI-friendly): **0** clean · **1** warnings · **2** any CRITICAL.

## Why offline replay?

Live probes (mcp-replay, MCP Inspector) need the server running. Most MCP session
failures are already sitting in a recorded transcript — a CI log, a debug dump, a
user-reported session file. Audit them where they are, with zero dependencies.

MIT License.
