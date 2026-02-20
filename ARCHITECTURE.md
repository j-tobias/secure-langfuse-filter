# Architecture: Secure Langfuse Filter for OpenWebUI

This document provides a high-level overview and links to the detailed documentation.

---

## Overview

The filter is an [OpenWebUI Pipeline Filter](https://docs.openwebui.com/pipelines/) that intercepts every LLM request/response cycle and sends structured usage telemetry to [Langfuse](https://langfuse.com/) — **without storing any conversation content or user-identifiable information**.

```
User ──▶ OpenWebUI ──▶ Filter (inlet) ──▶ LLM Provider
                                              │
User ◀── OpenWebUI ◀── Filter (outlet) ◀─────┘
                           │
                    Langfuse (sanitised traces)
```

### Design Principles

1. **Privacy by default** — No message content is ever sent; users are anonymised, PII is stripped
2. **Non-invasive** — The `body` dict is never mutated; OpenWebUI is unaware of the filter
3. **Operational focus** — Collects token usage, response times, model info, and message structure (counts/roles only)
4. **Self-managing** — TTL-based memory cleanup prevents unbounded growth in long-running servers

---

## Documentation

| Document | Description |
|----------|-------------|
| [OpenWebUI Metadata](docs/OPENWEBUI-METADATA.md) | Complete reference for the `body`, `metadata`, `user`, and `messages` data structures that OpenWebUI passes to the filter. Covers inlet vs outlet differences, task types, temporary chats, and multimodal content. |
| [Langfuse Integration](docs/LANGFUSE-INTEGRATION.md) | How the filter maps OpenWebUI's request/response cycle to Langfuse traces and generations. Covers the SDK methods used, trace lifecycle, token usage extraction, memory management, and error handling. |
| [Privacy Model](docs/PRIVACY-MODEL.md) | Detailed breakdown of what is and isn't sent to Langfuse. Documents all three sanitisation layers, PII detection mechanisms, the threat model, and known limitations. |
| [Configuration](docs/CONFIGURATION.md) | Reference for all valves (UI-configurable settings), environment variables, memory management constants, internal state, and lifecycle hooks. |

---

## Quick Reference

### Trace Structure

```
Langfuse Trace (one per chat)
├── user_id  = SHA-256(email)
├── session  = chat_id
├── tags     = ["open-webui", ...chat tags]
├── metadata = { interface, chat_title, chat_tags }
│
├── Generation: user_response  → model, flat stats metadata, token usage
├── Generation: title_generation
├── Generation: user_response  (message 2)
└── ...
```

### Key Valves

| Valve | Default | Effect |
|-------|---------|--------|
| `insert_tags` | `True` | Add `open-webui` + task name as trace tags |

See [Configuration](docs/CONFIGURATION.md) for the full list.
