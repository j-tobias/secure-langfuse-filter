# Configuration Reference

All runtime behaviour of the filter is controlled through **Valves** (OpenWebUI's UI-configurable settings) and a small number of **compile-time constants** for memory management.

---

## Valves

Valves are defined in `Pipeline.Valves` (Pydantic `BaseModel`) and can be edited in the OpenWebUI admin panel under **Workspace → Functions → Langfuse Filter → Valves**.

| Valve | Type | Default | Env Variable | Description |
|-------|------|---------|-------------|-------------|
| `pipelines` | `List[str]` | `["*"]` | — | Which pipelines this filter applies to. `["*"]` means all pipelines. Set to specific pipeline IDs to limit scope. |
| `priority` | `int` | `0` | — | Execution order when multiple filters are active. Lower numbers run first. |
| `secret_key` | `str` | `"your-secret-key-here"` | `LANGFUSE_SECRET_KEY` | Langfuse project secret key. Found in Langfuse → Settings → API Keys. |
| `public_key` | `str` | `"your-public-key-here"` | `LANGFUSE_PUBLIC_KEY` | Langfuse project public key. Found in Langfuse → Settings → API Keys. |
| `host` | `str` | `"https://cloud.langfuse.com"` | `LANGFUSE_HOST` | Langfuse API host URL. Change for self-hosted instances. |
| `insert_tags` | `bool` | `True` | — | When `True`, adds `"open-webui"` tag to every trace and appends the task name (e.g., `"title_generation"`) for non-default tasks. |
| `use_model_name_instead_of_id_for_generation` | `bool` | `False` | `USE_MODEL_NAME` | When `True`, uses the human-readable model name (e.g., `"Llama 3.1 (8B)"`) instead of the model ID (e.g., `"llama3.1:latest"`) in generation observations. |
| `redact_content` | `bool` | `True` | — | When `True`, replaces all message content with metadata summaries (`[REDACTED | N chars | M words | ~T tokens]`). When `False`, full message text is sent to Langfuse. **Strongly recommended to keep enabled for privacy.** |
| `debug` | `bool` | `False` | `DEBUG_MODE` | Enables debug logging to the server console. Logs are sanitised — no PII or message content is printed. |

### Environment Variables

Environment variables are read **only at initialisation** (when the pipeline is first loaded). Changing an env var requires restarting OpenWebUI. Valves set through the UI override environment variable defaults.

```bash
# Required
LANGFUSE_SECRET_KEY=sk-lf-...
LANGFUSE_PUBLIC_KEY=pk-lf-...

# Optional
LANGFUSE_HOST=https://langfuse.example.com   # default: https://cloud.langfuse.com
USE_MODEL_NAME=true                           # default: false
DEBUG_MODE=true                               # default: false
```

---

## Memory Management Constants

These are **class-level constants** defined directly in `Pipeline`. They are not configurable through the UI — change them in the source code if needed.

| Constant | Value | Description |
|----------|-------|-------------|
| `_CLEANUP_INTERVAL_SECONDS` | `300` (5 min) | How often the stale chat cleanup runs. Checked at the start of every `inlet()` call. |
| `_CHAT_TTL_SECONDS` | `86400` (24 h) | How long a chat's state is kept after the last activity. After this, all state for that chat is evicted. |

### How Cleanup Works

1. Every `inlet()` call checks if `_CLEANUP_INTERVAL_SECONDS` has elapsed since the last cleanup
2. If yes, scans `chat_last_seen` for entries older than `_CHAT_TTL_SECONDS`
3. For each stale chat:
   - Ends the Langfuse root span/trace
   - Removes entries from `chat_traces`, `model_names`, `inlet_timestamps`, `chat_enrichments`, `chat_last_seen`
4. Flushes pending Langfuse data after cleanup

### Tuning

- **High-traffic servers**: Consider reducing `_CHAT_TTL_SECONDS` to `3600` (1 hour) to free memory faster
- **Low-traffic / long conversations**: Increase to `172800` (48 hours) if users leave chats open overnight
- **Cleanup frequency**: `_CLEANUP_INTERVAL_SECONDS` at `300` is conservative. Only adjust if you see memory growth in monitoring

---

## Internal State

The filter maintains per-chat state in instance dictionaries. Understanding these helps with debugging:

| Dict | Key | Value | Lifecycle |
|------|-----|-------|-----------|
| `chat_traces` | `chat_id` | Root Langfuse span object | Created in `inlet()`, ended in `on_shutdown()` or cleanup |
| `model_names` | `chat_id` | `{"model_id": "...", "model_name": "..."}` | Set in `inlet()`, read in `outlet()` |
| `inlet_timestamps` | `chat_id` | `float` (epoch seconds) | Set in `inlet()`, popped in `outlet()` for response time |
| `chat_enrichments` | `chat_id` | `{"chat_title": "...", "chat_tags": "..."}` | Built up from `title_generation` / `tags_generation` task outlets |
| `chat_last_seen` | `chat_id` | `float` (epoch seconds) | Updated in `inlet()`, used by cleanup to determine staleness |
| `suppressed_logs` | — | `set` of message strings | Prevents repeated debug log messages |

---

## Lifecycle Hooks

| Hook | When it fires | What the filter does |
|------|--------------|---------------------|
| `on_startup()` | OpenWebUI starts, pipeline loads | Calls `set_langfuse()` to initialise the Langfuse client |
| `on_shutdown()` | OpenWebUI stops, pipeline unloads | Ends all active traces, clears all state, flushes to Langfuse |
| `on_valves_updated()` | User saves valve changes in the UI | Calls `set_langfuse()` to reinitialise with new credentials/host |
| `inlet(body, user)` | Before each LLM request | Records timing, creates/reuses trace, logs user input |
| `outlet(body, user)` | After each LLM response | Captures enrichments, logs generation, calculates response time |

---

## Typical Setup

1. **Install the filter** in OpenWebUI (Workspace → Functions → Import)
2. **Set Langfuse keys** in the Valves UI:
   - `secret_key`: Your Langfuse secret key
   - `public_key`: Your Langfuse public key
   - `host`: Your Langfuse instance URL (or keep the default for cloud)
3. **Leave defaults** for everything else — `redact_content=True` and `insert_tags=True` are the recommended privacy settings
4. **Enable debug** temporarily if traces aren't appearing, then disable once verified
