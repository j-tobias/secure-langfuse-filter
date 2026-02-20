# Langfuse Integration

This document describes how the filter maps OpenWebUI's request/response cycle to Langfuse's tracing model, including the SDK methods used, trace structure, and data flow.

---

## Langfuse Concepts

| Langfuse Concept | What it represents in this filter |
|-----------------|----------------------------------|
| **Trace** | One chat conversation (identified by `chat_id`). All messages in the same chat share a trace. |
| **Session** | Same as trace — `session_id` is set to `chat_id` so Langfuse groups them. |
| **User** | SHA-256 hash of user email. Stable across sessions, not reversible. |
| **Generation** | An LLM call. Contains model, usage, and metadata stats (message counts, response time). One per request/response cycle. |
| **Tags** | Flat string labels on the trace. Always includes `"open-webui"`, plus the task name if non-default, plus chat tags from enrichments. |
| **Metadata** | Arbitrary JSON dict on each observation. Contains operational stats — no message content. |

---

## Trace Lifecycle

### 1. First message in a chat (inlet)

```
inlet() called
  │
  ├── Extract chat_id from metadata
  ├── Store model info for outlet
  │
  ├── Create trace: langfuse.trace(name, user_id, session_id, tags, metadata)
  ├── Store trace in self.chat_traces[chat_id]
  │
  └── Record inlet timestamp for response time calculation
```

### 2. LLM responds (outlet)

```
outlet() called
  │
  ├── Look up trace from self.chat_traces[chat_id]
  ├── Extract token usage from assistant message metadata
  ├── If task is title_generation/tags_generation → store enrichment
  ├── Calculate response_time_ms
  │
  ├── Update trace: trace.update(name, user_id, tags, metadata with enrichments)
  │
  ├── Create generation: trace.generation(name, model, metadata, usage)
  │   ├── metadata = {task, model_id, model_name, message_count, roles,
  │   │            input_chars, estimated_input_tokens, output_chars,
  │   │            estimated_output_tokens, response_time_ms}
  │   └── .end()
  │
  └── langfuse.flush()
```

### 3. Subsequent messages (same chat)

The trace is **reused** — `self.chat_traces[chat_id]` finds the existing trace object. New generations are added as children.

### 4. Title/tags generation (automatic OpenWebUI tasks)

These follow the same inlet → outlet flow but with `metadata.task` set to `"title_generation"` or `"tags_generation"`. In the outlet:

1. The raw LLM response (the generated title or tags) is captured in `self.chat_enrichments[chat_id]`
2. On all subsequent trace updates, this enrichment data is merged into the trace metadata as `chat_title` and `chat_tags`
3. Chat tags are also merged into the Langfuse `tags` array via `_build_tags(task_name, enrichments)`
4. Title/tags are the only LLM-generated text stored — all other content is excluded entirely

---

## Trace Structure in Langfuse

What you see in the Langfuse UI for a typical chat with 2 messages:

```
Trace: chat:abc-123-def
├── session_id: abc-123-def
├── user_id: a1b2c3d4... (SHA-256 hash)
├── tags: ["open-webui", "math", "arithmetic"]
├── metadata:
│   ├── interface: "open-webui"
│   ├── chat_title: "Math Questions"
│   └── chat_tags: "math, arithmetic"
│
├── Generation: user_response
│   ├── model: "llama3.1:latest"
│   ├── metadata: {task, model_id, model_name, message_count: 1,
│   │            roles: ["user"], input_chars: 24, estimated_input_tokens: 6,
│   │            output_chars: 156, estimated_output_tokens: 39,
│   │            response_time_ms: 1234.5}
│   └── usage: {input: 45, output: 28, unit: "TOKENS"}
│
├── Generation: title_generation
│   ├── model: "llama3.1:latest"
│   └── metadata: {task, message_count: 2, output_chars: 15, ...}
│
└── Generation: user_response  (second message)
    ├── model: "llama3.1:latest"
    ├── metadata: {task, message_count: 3, roles: ["user","assistant","user"],
    │            input_chars: 680, estimated_input_tokens: 170,
    │            output_chars: 423, estimated_output_tokens: 106,
    │            response_time_ms: 2150.3}
    └── usage: {input: 120, output: 85, unit: "TOKENS"}
```

---

## SDK Methods Used

| Method | Where Used | Purpose |
|--------|-----------|---------|
| `Langfuse(secret_key, public_key, host)` | `set_langfuse()` | Initialise the Langfuse client |
| `langfuse.auth_check()` | `set_langfuse()` | Verify credentials. Raises on failure. |
| `langfuse.trace(name, user_id, session_id, tags, metadata)` | `inlet()` | Create a trace for the chat. One trace per conversation. |
| `trace.update(name, user_id, tags, metadata)` | `outlet()` | Update trace-level attributes with enrichments (title, tags). |
| `trace.generation(name, model, metadata, usage)` | `outlet()` | Create an LLM generation observation. Contains model, stats metadata, and token usage. |
| `generation.end()` | `outlet()` | Close the generation observation. |
| `langfuse.flush()` | `outlet()`, `on_shutdown()`, `_cleanup_stale_chats()` | Send all pending observations to the Langfuse API. |

---

## Token Usage Extraction

Token usage comes from the assistant message object in the outlet body. Different LLM backends use different field names:

| Backend | Input tokens field | Output tokens field |
|---------|-------------------|-------------------|
| OpenAI-compatible | `prompt_tokens` | `completion_tokens` |
| Ollama | `prompt_eval_count` | `eval_count` |

The filter checks both field names with fallback:
```python
input_tokens = info.get("prompt_eval_count") or info.get("prompt_tokens")
output_tokens = info.get("eval_count") or info.get("completion_tokens")
```

Usage is only reported when **both** values are available. If the model doesn't provide usage data, the generation is created without it.

---

## Memory Management

The filter maintains per-chat state in several dicts:

| Dict | Contents | Cleaned up? |
|------|----------|-------------|
| `chat_traces` | Root Langfuse trace per chat | TTL cleanup + shutdown |
| `model_names` | Model ID/name per chat | TTL cleanup + shutdown |
| `inlet_timestamps` | Inlet entry time per chat | Popped in outlet + TTL cleanup |
| `chat_enrichments` | Title/tags per chat | TTL cleanup + shutdown |
| `chat_last_seen` | Last activity timestamp per chat | TTL cleanup + shutdown |

### TTL-Based Cleanup

To prevent unbounded memory growth in long-running servers:

- `_cleanup_stale_chats()` runs every **5 minutes** (`_CLEANUP_INTERVAL_SECONDS = 300`)
- Removes all state for chats inactive for **24 hours** (`_CHAT_TTL_SECONDS = 86400`)
- Ends stale Langfuse traces by removing them from state
- Flushes pending data after cleanup
- Triggered at the start of every `inlet()` call

### Shutdown

`on_shutdown()` clears all state dicts and flushes all pending data to Langfuse.

---

## Error Handling

| Scenario | Behaviour |
|----------|-----------|
| Langfuse credentials wrong (401/unauthorized) | `self.langfuse` set to `None`. All inlet/outlet calls skip tracing silently. |
| Langfuse host unreachable | `self.langfuse` set to `None`. |
| Trace creation fails | `body` returned unchanged. Chat continues without tracing. |
| Generation creation fails | Silently caught. Trace still exists, just missing this generation. |
| Flush fails | Silently caught. Data will be retried by Langfuse SDK on next flush. |
| Outlet called without matching trace | Inlet is re-run to create a trace. If it still fails, outlet returns body unchanged. |
| `user` is `None` | `user_id` becomes `None`. Trace is still created without a user association. |
