# Secure Langfuse Filter

This filter version is adapted from the [example filter](https://github.com/open-webui/pipelines/blob/main/examples/filters/langfuse_v3_filter_pipeline.py).

## Privacy Measures

The tracking of sensitive data has been removed. This allows collecting usage information without identifying individual users:

- **Hashed user ID** — User emails are SHA-256 hashed before being sent to Langfuse. This provides a stable, anonymous handle per user (for aggregate analytics) without exposing the actual email.
- **Metadata sanitisation** — All user-identifiable fields (`user`, `name`, `email`, `profile_image_url`, `avatar`, etc.) are stripped from metadata before it is sent to Langfuse.
- **Body sanitisation** — Top-level PII fields are removed from the request body before it is logged as trace input.
- **Content redaction** (`redact_content` valve, **enabled by default**) — All message text (user prompts and assistant responses) is replaced with metadata summaries before being sent to Langfuse. Instead of actual conversation content, Langfuse receives entries like `[REDACTED | 523 chars | 98 words | ~131 tokens]`. Multi-modal content (images) is also redacted. This keeps message structure, roles, and sizing information intact for analytics while ensuring no conversation content leaves the system.
- **Response time tracking** — The elapsed time between inlet (user request) and outlet (LLM response) is recorded in milliseconds in the trace metadata (`response_time_ms`), providing performance insights without exposing content.

No raw user email, name, or conversation content is ever transmitted to Langfuse.

