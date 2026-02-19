# Langfuse Integration

This document describes how the filter maps OpenWebUI's request/response cycle to Langfuse's tracing model, including the SDK methods used, trace structure, and data flow.

---

## Langfuse Concepts

| Langfuse Concept | What it represents in this filter |
|-----------------|----------------------------------|
| **Trace** | One chat conversation (identified by `chat_id`). All messages in the same chat share a trace. |
| **Session** | Same as trace — `session_id` is set to `chat_id` so Langfuse groups them. |
| **User** | SHA-256 hash of user email. Stable across sessions, not reversible. |
| **Span** | A unit of work. Used for the root trace span and for user input events. |
| **Generation** | An LLM call. Contains model, input messages, output, and token usage. |
| **Tags** | Flat string labels on the trace. Always includes `"open-webui"`, plus the task name if non-default. |
| **Metadata** | Arbitrary JSON dict on each observation. Contains sanitised operational data + enrichments. |

---

## Trace Lifecycle

### 1. First message in a chat (inlet)

```
inlet() called
  │
  ├── Extract chat_id from metadata
  ├── Hash user email → user_id
  ├── Sanitise metadata + body
  ├── Redact message content
  │
  ├── Create root span: langfuse.start_span(name="chat:{chat_id}")
  ├── Set trace attributes: span.update_trace(user_id, session_id, tags)
  ├── Store span in self.chat_traces[chat_id]
  │
  ├── Create child span: trace.start_span(name="user_input:{uuid}")
  │   └── input = [redacted messages]
  │   └── .end()
  │
  └── Record inlet timestamp for response time calculation
```

### 2. LLM responds (outlet)

```
outlet() called
  │
  ├── Look up trace from self.chat_traces[chat_id]
  ├── Extract assistant message + token usage
  ├── If task is title_generation/tags_generation → store enrichment
  ├── Redact assistant message
  ├── Calculate response_time_ms
  │
  ├── Update trace: trace.update_trace(output, metadata with enrichments)
  │
  ├── Create generation: trace.start_generation(name="llm_response:{uuid}")
  │   ├── model = model_id or model_name
  │   ├── input = [redacted messages]
  │   ├── output = [redacted response]
  │   ├── usage = {input: N, output: M}
  │   └── .end()
  │
  └── langfuse.flush()
```

### 3. Subsequent messages (same chat)

The trace is **reused** — `self.chat_traces[chat_id]` finds the existing root span. New user_input spans and llm_response generations are added as children.

### 4. Title/tags generation (automatic OpenWebUI tasks)

These follow the same inlet → outlet flow but with `metadata.task` set to `"title_generation"` or `"tags_generation"`. In the outlet:

1. The raw LLM response (the generated title or tags) is captured in `self.chat_enrichments[chat_id]`
2. On all subsequent trace updates, this enrichment data is merged into the trace metadata as `chat_title` and `chat_tags`
3. The actual content is still redacted for the generation's input/output (if `redact_content=True`)

---

## Trace Structure in Langfuse

What you see in the Langfuse UI for a typical chat with 2 messages:

```
Trace: chat:abc-123-def
├── session_id: abc-123-def
├── user_id: a1b2c3d4... (SHA-256 hash)
├── tags: ["open-webui"]
├── metadata:
│   ├── chat_title: "Math Questions"           ← enrichment
│   ├── chat_tags: "math, arithmetic"          ← enrichment
│   ├── response_time_ms: 1234.5
│   ├── model_id: "llama3.1:latest"
│   ├── model_name: "Llama 3.1 (8B)"
│   └── interface: "open-webui"
│
├── Span: user_input:uuid-1
│   └── input: [{"role": "user", "content": "[REDACTED | 24 chars | 5 words | ~6 tokens]"}]
│
├── Generation: llm_response:uuid-1
│   ├── model: "llama3.1:latest"
│   ├── input: [{"role": "user", "content": "[REDACTED | 24 chars | ..."}]
│   ├── output: "[REDACTED | 156 chars | 28 words | ~39 tokens]"
│   └── usage: {input: 45, output: 28, unit: "TOKENS"}
│
├── Generation: llm_response:uuid-title  (title_generation task)
│   └── output: "[REDACTED | 15 chars | 2 words | ~4 tokens]"
│
├── Span: user_input:uuid-2  (second message)
│   └── input: [{"role": "user", "content": "[REDACTED | ...]"}, ...]
│
└── Generation: llm_response:uuid-2
    ├── input: [...full conversation, all redacted...]
    ├── output: "[REDACTED | 423 chars | ...]"
    └── usage: {input: 120, output: 85, unit: "TOKENS"}
```

---

## SDK Methods Used

| Method | Where Used | Purpose |
|--------|-----------|---------|
| `Langfuse(secret_key, public_key, host, debug)` | `set_langfuse()` | Initialise the Langfuse client |
| `langfuse.auth_check()` | `set_langfuse()` | Verify credentials. Raises on failure. |
| `langfuse.start_span(name, input, metadata)` | `inlet()` | Create root span (implicitly creates the trace). The root span represents the entire chat session. |
| `span.update_trace(user_id, session_id, tags, input, output, metadata)` | `inlet()`, `outlet()` | Set/update trace-level attributes. Called on the root span to set user, session, enrichments, etc. |
| `span.start_span(name, metadata, input)` | `inlet()` | Create a child span for user input events. Immediately `.end()`ed since it's a point-in-time event. |
| `span.start_generation(name, model, input, output, metadata)` | `outlet()` | Create an LLM generation observation. Contains the model, redacted I/O, and metadata. |
| `generation.update(usage={...})` | `outlet()` | Attach token usage data to the generation after creation. |
| `span.end()` / `generation.end()` | Various | Close an observation. Required in Langfuse v3. |
| `langfuse.flush()` | `outlet()`, `on_shutdown()`, `_cleanup_stale_chats()` | Send all pending observations to the Langfuse API. Called after every outlet and on shutdown. |

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
| `chat_traces` | Root Langfuse span per chat | TTL cleanup + shutdown |
| `model_names` | Model ID/name per chat | TTL cleanup + shutdown |
| `inlet_timestamps` | Inlet entry time per chat | Popped in outlet + TTL cleanup |
| `chat_enrichments` | Title/tags per chat | TTL cleanup + shutdown |
| `chat_last_seen` | Last activity timestamp per chat | TTL cleanup + shutdown |

### TTL-Based Cleanup

To prevent unbounded memory growth in long-running servers:

- `_cleanup_stale_chats()` runs every **5 minutes** (`_CLEANUP_INTERVAL_SECONDS = 300`)
- Removes all state for chats inactive for **24 hours** (`_CHAT_TTL_SECONDS = 86400`)
- Ends stale Langfuse traces before removing them
- Flushes pending data after cleanup
- Triggered at the start of every `inlet()` call

### Shutdown

`on_shutdown()` ends all active traces, clears all state dicts, and flushes all pending data to Langfuse.

---

## Error Handling

| Scenario | Behaviour |
|----------|-----------|
| Langfuse credentials wrong (401/unauthorized) | Logged, `self.langfuse` set to `None`. All inlet/outlet calls skip tracing silently. |
| Langfuse host unreachable | Logged, `self.langfuse` set to `None`. |
| Trace creation fails | Logged, `body` returned unchanged. Chat continues without tracing. |
| Generation creation fails | Logged. Trace still exists, just missing this generation. |
| Flush fails | Logged. Data will be retried by Langfuse SDK on next flush. |
| Outlet called without matching trace | Inlet is re-run to create a trace, then outlet proceeds. |
| `user` is `None` | `user_id` becomes `None`. Trace is still created without a user association. |
