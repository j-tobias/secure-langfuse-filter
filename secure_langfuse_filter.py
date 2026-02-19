"""
title: Langfuse Filter Pipeline for v3
author: justus
date: 2026-19-02
version: 0.0.1
license: MIT
description: A filter pipeline that uses Langfuse v3.
requirements: langfuse>=3.0.0
"""

from typing import List, Optional
import os
import uuid
import hashlib
import time


from utils.pipelines.main import get_last_assistant_message
from pydantic import BaseModel
from langfuse import Langfuse


def get_last_assistant_message_obj(messages: list) -> Optional[dict]:
    """
    Returns the full message dict of the last assistant message,
    so we can access usage/token metadata attached to it.
    """
    for msg in reversed(messages):
        if msg.get("role") == "assistant":
            return msg
    return None


class Pipeline:
    class Valves(BaseModel):
        pipelines: List[str] = []
        priority: int = 0
        secret_key: str
        public_key: str
        host: str
        # New valve that controls whether task names are added as tags:
        insert_tags: bool = True
        # New valve that controls whether to use model name instead of model ID for generation
        use_model_name_instead_of_id_for_generation: bool = False
        # When True, replaces actual message content with metadata summaries
        # (char count, word count, estimated tokens). No conversation text is sent to Langfuse.
        redact_content: bool = True

    def __init__(self):
        self.type = "filter"
        self.name = "Langfuse Filter"

        self.valves = self.Valves(
            **{
                "pipelines": ["*"],
                "secret_key": os.getenv("LANGFUSE_SECRET_KEY", "your-secret-key-here"),
                "public_key": os.getenv("LANGFUSE_PUBLIC_KEY", "your-public-key-here"),
                "host": os.getenv("LANGFUSE_HOST", "https://cloud.langfuse.com"),
                "use_model_name_instead_of_id_for_generation": os.getenv("USE_MODEL_NAME", "false").lower() == "true",
            }
        )

        self.langfuse = None
        self.chat_traces = {}
        # Dictionary to store model names for each chat
        self.model_names = {}
        # Track inlet timestamps per chat for response-time calculation
        self.inlet_timestamps = {}
        # Store chat enrichments (title, tags) from OpenWebUI task calls
        self.chat_enrichments = {}
        # Track last activity per chat_id for stale entry cleanup
        self.chat_last_seen = {}
        self._last_cleanup = 0.0

    async def on_startup(self):
        self.set_langfuse()

    async def on_shutdown(self):
        if self.langfuse:
            try:
                for chat_id, trace in self.chat_traces.items():
                    try:
                        trace.end()
                    except Exception:
                        pass

                self.chat_traces.clear()
                self.model_names.clear()
                self.inlet_timestamps.clear()
                self.chat_enrichments.clear()
                self.chat_last_seen.clear()
                self.langfuse.flush()
            except Exception:
                pass

    async def on_valves_updated(self):
        self.set_langfuse()

    def set_langfuse(self):
        try:
            self.langfuse = Langfuse(
                secret_key=self.valves.secret_key,
                public_key=self.valves.public_key,
                host=self.valves.host,
            )
            self.langfuse.auth_check()
        except Exception:
            self.langfuse = None

    @staticmethod
    def _hash_user_id(user_email: Optional[str]) -> Optional[str]:
        """
        Returns a SHA-256 hash of the user email to provide a stable,
        anonymous user identifier that cannot be reversed to the original email.
        Returns None if no email is provided.
        """
        if not user_email:
            return None
        return hashlib.sha256(user_email.lower().strip().encode("utf-8")).hexdigest()

    # Stale chat cleanup settings
    _CLEANUP_INTERVAL_SECONDS = 300   # Run cleanup every 5 minutes
    _CHAT_TTL_SECONDS = 86400         # Remove chats inactive for 24 hours

    # Substrings that indicate a variable/key contains PII.
    # Matched case-insensitively against both top-level metadata keys
    # and keys inside the nested "variables" dict.
    _PII_PATTERNS = {
        "user", "name", "email", "avatar", "location",
        "profile", "display", "phone", "address", "ip",
    }

    # Exact top-level metadata keys to strip (fast set lookup)
    _PII_KEYS = {
        "user", "name", "email", "user_email", "user_name",
        "profile_image_url", "avatar", "display_name",
        "user_id",  # raw user_id before hashing
    }

    @classmethod
    def _is_pii_variable(cls, key: str) -> bool:
        """
        Returns True if a variable key looks like it contains PII,
        based on substring matching against known PII patterns.
        E.g. '{{USER_NAME}}', 'user_email', 'user_location' all match.
        """
        lower = key.lower()
        return any(pattern in lower for pattern in cls._PII_PATTERNS)

    @classmethod
    def _sanitize_metadata(cls, metadata: dict) -> dict:
        """
        Removes any user-identifiable fields from metadata before
        sending it to Langfuse. Retains only operational fields.
        Also strips PII keys from the nested 'variables' dict if present.
        """
        sanitized = {k: v for k, v in metadata.items() if k.lower() not in cls._PII_KEYS}

        # Sanitize the variables sub-dict (OpenWebUI template variables)
        if "variables" in sanitized and isinstance(sanitized["variables"], dict):
            sanitized["variables"] = {
                k: v for k, v in sanitized["variables"].items()
                if not cls._is_pii_variable(k)
            }

        return sanitized

    @classmethod
    def _sanitize_body(cls, body: dict) -> dict:
        """
        Returns a copy of the request body safe for logging to Langfuse.
        Strips top-level user-identifiable fields while keeping messages,
        model info, and other operational data.
        Also sanitizes the nested metadata dict to remove PII.
        """
        pii_keys = {
            "user", "user_id", "user_email", "user_name",
            "name", "email", "profile_image_url", "avatar",
        }
        safe = {k: v for k, v in body.items() if k.lower() not in pii_keys}
        # Sanitize the nested metadata dict (contains user object with PII)
        if "metadata" in safe and isinstance(safe["metadata"], dict):
            safe["metadata"] = cls._sanitize_metadata(safe["metadata"])
        return safe

    @staticmethod
    def _estimate_tokens(text: str) -> int:
        """
        Rough token estimate: ~4 characters per token for English text.
        This is a simple heuristic; actual tokenization depends on the model.
        """
        if not text:
            return 0
        return max(1, len(text) // 4)

    def _redact_text(self, text: str) -> str:
        """
        Replaces a text string with a metadata summary.
        Returns a string like: "[REDACTED | 523 chars | 98 words | ~131 tokens]"
        """
        if not text:
            return "[REDACTED | empty]"
        char_count = len(text)
        word_count = len(text.split())
        token_estimate = self._estimate_tokens(text)
        return f"[REDACTED | {char_count} chars | {word_count} words | ~{token_estimate} tokens]"

    def _redact_messages(self, messages: list) -> list:
        """
        Returns a redacted copy of the messages list.
        Keeps all metadata (role, images flag, tool_calls structure, etc.)
        but replaces actual text content with metadata summaries.
        """
        if not self.valves.redact_content:
            return messages

        redacted = []
        for msg in messages:
            redacted_msg = {}
            for key, value in msg.items():
                if key == "content":
                    if isinstance(value, str):
                        redacted_msg[key] = self._redact_text(value)
                    elif isinstance(value, list):
                        # Multi-modal content (text + images, etc.)
                        redacted_parts = []
                        for part in value:
                            if isinstance(part, dict):
                                redacted_part = dict(part)
                                if part.get("type") == "text" and "text" in part:
                                    redacted_part["text"] = self._redact_text(part["text"])
                                elif part.get("type") == "image_url":
                                    redacted_part["image_url"] = "[REDACTED image]"
                                redacted_parts.append(redacted_part)
                            else:
                                redacted_parts.append(self._redact_text(str(part)))
                        redacted_msg[key] = redacted_parts
                    else:
                        redacted_msg[key] = self._redact_text(str(value))
                else:
                    # Keep all non-content fields (role, tool_calls, name, etc.)
                    redacted_msg[key] = value
            redacted.append(redacted_msg)
        return redacted

    def _build_tags(self, task_name: str) -> list:
        """
        Builds a list of tags based on valve settings, ensuring we always add
        'open-webui' and skip user_response / llm_response from becoming tags themselves.
        """
        tags_list = []
        if self.valves.insert_tags:
            tags_list.append("open-webui")
            if task_name not in ("user_response", "llm_response"):
                tags_list.append(task_name)
        return tags_list

    @staticmethod
    def _resolve_chat_id(body: dict, from_outlet: bool = False) -> str:
        """
        Extract and normalise chat_id from the request body.
        Inlet reads from metadata, outlet reads from top-level.
        Temporary chats ("local") are mapped to "temporary-session-<session_id>".
        """
        if from_outlet:
            chat_id = body.get("chat_id")
            session_id = body.get("session_id")
        else:
            metadata = body.get("metadata", {})
            chat_id = metadata.get("chat_id", str(uuid.uuid4()))
            session_id = metadata.get("session_id")
        if chat_id == "local":
            chat_id = f"temporary-session-{session_id}"
        return chat_id

    @staticmethod
    def _get_hashed_user_id(user: Optional[dict]) -> Optional[str]:
        """Extract user email and return its SHA-256 hash."""
        email = user.get("email") if user else None
        return Pipeline._hash_user_id(email)

    def _build_safe_metadata(self, metadata: dict, task_name: str) -> dict:
        """Sanitise metadata and add standard operational fields."""
        safe = self._sanitize_metadata(metadata)
        safe["type"] = task_name
        safe["interface"] = "open-webui"
        return safe

    @staticmethod
    def _extract_usage(assistant_message_obj: Optional[dict]) -> Optional[dict]:
        """Extract token usage from the assistant message object, if available."""
        if not assistant_message_obj:
            return None
        info = assistant_message_obj.get("usage", {})
        if not isinstance(info, dict):
            return None
        input_tokens = info.get("prompt_eval_count") or info.get("prompt_tokens")
        output_tokens = info.get("eval_count") or info.get("completion_tokens")
        if input_tokens is not None and output_tokens is not None:
            return {"input": input_tokens, "output": output_tokens, "unit": "TOKENS"}
        return None

    def _cleanup_stale_chats(self):
        """
        Removes chat state older than _CHAT_TTL_SECONDS.
        Called periodically from inlet() to prevent unbounded memory growth.
        """
        now = time.time()
        if now - self._last_cleanup < self._CLEANUP_INTERVAL_SECONDS:
            return

        self._last_cleanup = now
        cutoff = now - self._CHAT_TTL_SECONDS
        stale_ids = [
            cid for cid, last_seen in self.chat_last_seen.items()
            if last_seen < cutoff
        ]

        for cid in stale_ids:
            # End and remove stale trace
            trace = self.chat_traces.pop(cid, None)
            if trace:
                try:
                    trace.end()
                except Exception:
                    pass
            self.model_names.pop(cid, None)
            self.inlet_timestamps.pop(cid, None)
            self.chat_enrichments.pop(cid, None)
            self.chat_last_seen.pop(cid, None)

        if stale_ids and self.langfuse:
                try:
                    self.langfuse.flush()
                except Exception:
                    pass

    async def inlet(self, body: dict, user: Optional[dict] = None) -> dict:
        if not self.langfuse:
            return body

        metadata = body.get("metadata", {})
        chat_id = self._resolve_chat_id(body)

        # Periodic cleanup of stale chat state to prevent memory leaks
        self._cleanup_stale_chats()
        self.chat_last_seen[chat_id] = time.time()

        # Store model information for this chat
        model_info = metadata.get("model", {})
        model_id = body.get("model")
        self.model_names.setdefault(chat_id, {})["id"] = model_id
        if isinstance(model_info, dict) and "name" in model_info:
            self.model_names[chat_id]["name"] = model_info["name"]

        required_keys = ["model", "messages"]
        missing_keys = [key for key in required_keys if key not in body]
        if missing_keys:
            raise ValueError(f"Error: Missing keys in the request body: {', '.join(missing_keys)}")

        hashed_user_id = self._get_hashed_user_id(user)
        task_name = metadata.get("task", "user_response")
        tags_list = self._build_tags(task_name)

        # Sanitize metadata and body — copies so we never mutate original body
        safe_metadata = self._build_safe_metadata(metadata, task_name)
        safe_body = self._sanitize_body(body)
        if self.valves.redact_content and "messages" in safe_body:
            safe_body["messages"] = self._redact_messages(safe_body["messages"])

        # Record inlet timestamp for response-time calculation in outlet
        self.inlet_timestamps[chat_id] = time.time()

        # Build trace metadata once (used for both new and existing traces)
        trace_metadata = {**safe_metadata, "session_id": chat_id}

        if chat_id not in self.chat_traces:
            try:
                trace = self.langfuse.start_span(
                    name=f"chat:{chat_id}",
                    input=safe_body,
                    metadata=trace_metadata,
                )
                trace.update_trace(
                    user_id=hashed_user_id,
                    session_id=chat_id,
                    tags=tags_list or None,
                    input=safe_body,
                    metadata=trace_metadata,
                )
                self.chat_traces[chat_id] = trace
            except Exception:
                return body
        else:
            self.chat_traces[chat_id].update_trace(
                user_id=hashed_user_id,
                tags=tags_list or None,
                metadata=trace_metadata,
            )

        # Log user input as a child span
        try:
            trace = self.chat_traces[chat_id]
            event_span = trace.start_span(
                name=f"user_input:{uuid.uuid4()}",
                metadata={**safe_metadata, "type": "user_input", "session_id": chat_id},
                input=safe_body.get("messages", []),
            )
            event_span.end()
        except Exception:
            pass

        return body

    async def outlet(self, body: dict, user: Optional[dict] = None) -> dict:
        if not self.langfuse:
            return body

        chat_id = self._resolve_chat_id(body, from_outlet=True)
        self.chat_last_seen[chat_id] = time.time()

        metadata = body.get("metadata", {})
        task_name = metadata.get("task", "llm_response")
        tags_list = self._build_tags(task_name)

        if chat_id not in self.chat_traces:
            return await self.inlet(body, user)

        messages = body["messages"]
        assistant_message_raw = get_last_assistant_message(messages)
        assistant_message_obj = get_last_assistant_message_obj(messages)

        # Capture title/tags from OpenWebUI task calls for trace enrichment
        if task_name in ("title_generation", "tags_generation") and assistant_message_raw:
            enrichment_key = "chat_title" if task_name == "title_generation" else "chat_tags"
            self.chat_enrichments.setdefault(chat_id, {})[enrichment_key] = assistant_message_raw.strip()

        # Redact assistant message if content redaction is enabled
        assistant_message = (
            self._redact_text(assistant_message_raw) if self.valves.redact_content and assistant_message_raw
            else assistant_message_raw
        )

        # Calculate response time from inlet to outlet
        inlet_ts = self.inlet_timestamps.pop(chat_id, None)
        response_time_ms = round((time.time() - inlet_ts) * 1000, 1) if inlet_ts else None

        # Extract token usage
        usage = self._extract_usage(assistant_message_obj)

        hashed_user_id = self._get_hashed_user_id(user)
        safe_metadata = self._build_safe_metadata(metadata, task_name)

        # Merge enrichments (title, tags) into trace metadata and Langfuse tags
        enrichments = self.chat_enrichments.get(chat_id, {})
        if enrichments.get("chat_tags"):
            for tag in enrichments["chat_tags"].split(","):
                tag = tag.strip()
                if tag and tag not in tags_list:
                    tags_list.append(tag)

        trace_name = enrichments.get("chat_title") or f"chat:{chat_id}"
        complete_metadata = {**safe_metadata, **enrichments, "session_id": chat_id, "task": task_name}
        if response_time_ms is not None:
            complete_metadata["response_time_ms"] = response_time_ms

        # Update trace with output and sanitized metadata
        trace = self.chat_traces[chat_id]
        trace.update_trace(
            name=trace_name,
            user_id=hashed_user_id,
            output=assistant_message,
            metadata=complete_metadata,
            tags=tags_list or None,
        )

        # Create LLM generation
        model_id = self.model_names.get(chat_id, {}).get("id", body.get("model"))
        model_name = self.model_names.get(chat_id, {}).get("name", "unknown")
        model_value = model_name if self.valves.use_model_name_instead_of_id_for_generation else model_id

        try:
            generation = trace.start_generation(
                name=f"llm_response:{uuid.uuid4()}",
                model=model_value,
                input=self._redact_messages(messages),
                output=assistant_message,
                metadata={**complete_metadata, "model_id": model_id, "model_name": model_name},
            )
            if usage:
                generation.update(usage=usage)
            generation.end()
        except Exception:
            pass

        try:
            self.langfuse.flush()
        except Exception:
            pass

        return body
