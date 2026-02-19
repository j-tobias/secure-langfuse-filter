# OpenWebUI Filter Pipeline: Metadata Reference

This document describes the data structures that OpenWebUI passes to filter pipelines. Understanding these is essential for knowing what data the filter has access to and what needs to be sanitised.

---

## How Filters Work

OpenWebUI pipelines support **filter** functions that sit between the user and the LLM. A filter has two hooks:

| Hook | Signature | When it runs |
|------|-----------|-------------|
| `inlet` | `async inlet(body: dict, user: dict) -> dict` | Before the request reaches the LLM |
| `outlet` | `async outlet(body: dict, user: dict) -> dict` | After the LLM responds |

Additionally, the pipeline class supports lifecycle hooks:

| Hook | When it runs |
|------|-------------|
| `on_startup()` | When the pipeline server starts |
| `on_shutdown()` | When the pipeline server stops |
| `on_valves_updated()` | When valve settings are changed in the UI |

### Critical Rule

**The filter must return `body` unchanged to OpenWebUI.** Any in-place mutation to `body` (e.g. overwriting `chat_id`, injecting metadata keys, modifying `messages`) will propagate back to OpenWebUI and can break its internal state matching. Always work on copies when preparing data for external systems.

---

## The `body` Dict

### In `inlet` (request body headed for the LLM)

```python
{
    "model": "llama3.1:latest",           # str — Model ID
    "messages": [                          # list[dict] — Conversation history
        {"role": "system", "content": "..."},
        {"role": "user", "content": "Hello!"},
        {"role": "assistant", "content": "Hi there!"},
        {"role": "user", "content": "What's 2+2?"}
    ],
    "stream": True,                        # bool — Stream the response?
    "metadata": { ... }                    # dict — See metadata section below
}
```

### In `outlet` (response body after LLM response)

The outlet body has a **different structure** — key fields are promoted to the top level:

```python
{
    "chat_id": "abc-123-def",             # str — Promoted to top level
    "session_id": "sess-456",             # str — Promoted to top level
    "id": "msg-789",                      # str — Message ID
    "model": "llama3.1:latest",           # str — Model ID
    "messages": [                          # list[dict] — Includes assistant response
        {"role": "user", "content": "What's 2+2?"},
        {
            "role": "assistant",
            "content": "4",
            "usage": {                     # Optional — Token usage (model-dependent)
                "prompt_tokens": 12,
                "completion_tokens": 5
            }
        }
    ],
    "metadata": { ... }                   # dict — Same structure as inlet
}
```

**Key difference:** In the outlet, `chat_id` and `session_id` are at the **top level** of `body`, not nested inside `metadata`. The filter reads them via `body.get("chat_id")` in the outlet, vs `metadata.get("chat_id")` in the inlet.

---

## The `metadata` Dict

Present in both inlet and outlet `body`:

| Field | Type | Description | PII Risk |
|-------|------|-------------|----------|
| `chat_id` | `str` | Chat/conversation ID. Value `"local"` indicates a temporary/unsaved chat. | No |
| `session_id` | `str` | Browser session ID | No |
| `message_id` | `str` | ID of the current message being processed | No |
| `task` | `str` | The task type for this LLM call (see Task Types below) | No |
| `model` | `dict` | Model information object (see below) | No |
| `filter_ids` | `list[str]` | IDs of active filter functions | No |
| `variables` | `dict` | Template variables — **contains PII** | **Yes** |

### The `metadata.model` Dict

```python
{
    "id": "llama3.1:latest",
    "name": "Llama 3.1 (8B)",
    "object": "model",
    "owned_by": "ollama",
    ...
}
```

### The `metadata.variables` Dict  ⚠️ Contains PII

OpenWebUI injects template variables that may include user-identifying information:

```python
{
    "{{USER_NAME}}": "John Doe",          # PII
    "{{USER_EMAIL}}": "john@example.com", # PII
    "{{USER_LOCATION}}": "Berlin, DE",    # PII
    "{{CURRENT_DATE}}": "2026-02-19",     # Safe
    "{{CURRENT_TIME}}": "14:30",          # Safe
    "{{LANGUAGE}}": "English",            # Safe
}
```

The filter strips any variable key containing PII-related substrings (`user`, `name`, `email`, `location`, `phone`, `address`, `ip`, `avatar`, `profile`, `display`).

---

## The `user` Dict

Passed as the second argument to `inlet()` and `outlet()`. This is a dump of OpenWebUI's `UserModel`:

| Field | Type | Example | PII? | How we handle it |
|-------|------|---------|------|-----------------|
| `id` | `str` | `"550e8400-e29b-..."` | Yes | Never sent |
| `email` | `str` | `"john@example.com"` | Yes | SHA-256 hashed → anonymous `user_id` |
| `name` | `str` | `"John Doe"` | Yes | Never sent |
| `role` | `str` | `"user"` or `"admin"` | No | Never sent (not needed for analytics) |
| `profile_image_url` | `str` | `"https://..."` | Yes | Never sent |

The `user` dict can also be `None` (e.g. for API-key-based access without a user session).

---

## Task Types

OpenWebUI sends **multiple LLM calls per user interaction**. Each call has a different `metadata.task` value. Understanding these is important because the filter processes all of them:

| Task Value | Triggered By | What the LLM Does | Filter Behaviour |
|------------|-------------|-------------------|-----------------|
| `user_response` | User sends a message (default for inlet) | Generates the main chat response | Full trace + generation. This is the primary analytics event. |
| `llm_response` | LLM finishes responding (default for outlet) | N/A (used as outlet default) | Full trace + generation |
| `title_generation` | First message in a new chat | Generates a short title for the conversation | **Captured** → stored as `chat_title` in trace metadata for categorisation |
| `tags_generation` | First message in a new chat | Generates category tags for the conversation | **Captured** → stored as `chat_tags` in trace metadata for categorisation |
| `emoji_generation` | After a response is generated | Selects an emoji for the chat | Traced as a normal task, task name added as Langfuse tag |
| Other / custom | Plugins or future OpenWebUI features | Varies | Traced normally, task name added as Langfuse tag |

### Task Call Flow (typical new chat)

```
User sends first message
  ├── inlet (task: user_response)    ──▶ LLM ──▶ outlet (task: llm_response)
  ├── inlet (task: title_generation) ──▶ LLM ──▶ outlet (task: title_generation)  → captured
  ├── inlet (task: tags_generation)  ──▶ LLM ──▶ outlet (task: tags_generation)   → captured
  └── inlet (task: emoji_generation) ──▶ LLM ──▶ outlet (task: emoji_generation)
```

All of these go through the same `inlet()`/`outlet()` pipeline. The filter identifies them via `metadata.task` and handles title/tags specially by extracting the LLM's response and storing it for trace enrichment.

---

## Message Format

Messages in `body["messages"]` follow the OpenAI chat format:

### Text message
```python
{"role": "user", "content": "What's the weather like?"}
```

### Multi-modal message (text + image)
```python
{
    "role": "user",
    "content": [
        {"type": "text", "text": "What's in this image?"},
        {"type": "image_url", "image_url": {"url": "data:image/png;base64,..."}}
    ]
}
```

### Assistant message with usage
```python
{
    "role": "assistant",
    "content": "The weather is sunny.",
    "usage": {
        "prompt_tokens": 45,        # or "prompt_eval_count" (Ollama)
        "completion_tokens": 12      # or "eval_count" (Ollama)
    }
}
```

### Tool call message
```python
{
    "role": "assistant",
    "content": null,
    "tool_calls": [
        {
            "id": "call_abc123",
            "type": "function",
            "function": {"name": "get_weather", "arguments": "{\"city\": \"Berlin\"}"}
        }
    ]
}
```

The filter's `_redact_messages()` replaces all `content` values with size summaries while preserving `role`, `tool_calls`, and other structural fields.

---

## Temporary Chats

When a user starts a chat without saving it, OpenWebUI sets `chat_id` to `"local"`. The filter converts this to `"temporary-session-{session_id}"` using the browser session ID — this provides a stable identifier within the session without exposing any user data. This conversion is done **internally only** and never written back to `body`.

---

## Valves (Configuration)

The `Valves` inner class defines configurable settings exposed in the OpenWebUI admin UI:

```python
class Valves(BaseModel):
    pipelines: List[str] = ["*"]           # Which pipelines this filter applies to
    priority: int = 0                       # Execution order (lower = earlier)
    secret_key: str                         # Langfuse secret key
    public_key: str                         # Langfuse public key
    host: str                               # Langfuse host URL
    insert_tags: bool = True                # Add task names as Langfuse tags
    use_model_name_instead_of_id: bool = False  # Use human name in generations
    redact_content: bool = True             # Replace content with size summaries
    debug: bool = False                     # Enable debug logging
```

Valves are initialised from environment variables at startup and can be changed at runtime via the OpenWebUI admin panel. When changed, `on_valves_updated()` is called, which reinitialises the Langfuse client.
