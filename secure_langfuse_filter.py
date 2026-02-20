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
    """Return the full dict of the last assistant message for usage metadata."""
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
        insert_tags: bool = True
        use_model_name_instead_of_id_for_generation: bool = False

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
        self.model_names = {}
        self.inlet_timestamps = {}
        self.chat_enrichments = {}
        self.chat_last_seen = {}
        self._last_cleanup = 0.0

    # ── Lifecycle ──────────────────────────────────────────────

    async def on_startup(self):
        self.set_langfuse()

    async def on_shutdown(self):
        if self.langfuse:
            try:
                self.langfuse.flush()
            except Exception:
                pass
            self.chat_traces.clear()
            self.model_names.clear()
            self.inlet_timestamps.clear()
            self.chat_enrichments.clear()
            self.chat_last_seen.clear()

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

    # ── Helpers ────────────────────────────────────────────────

    _CLEANUP_INTERVAL_SECONDS = 300
    _CHAT_TTL_SECONDS = 86400

    _PII_PATTERNS = {
        "user", "name", "email", "avatar", "location",
        "profile", "display", "phone", "address", "ip",
    }

    _PII_KEYS = {
        "user", "name", "email", "user_email", "user_name",
        "profile_image_url", "avatar", "display_name", "user_id",
    }

    @staticmethod
    def _hash_user_id(user_email: Optional[str]) -> Optional[str]:
        if not user_email:
            return None
        return hashlib.sha256(user_email.lower().strip().encode("utf-8")).hexdigest()

    @staticmethod
    def _get_hashed_user_id(user: Optional[dict]) -> Optional[str]:
        email = user.get("email") if user else None
        return Pipeline._hash_user_id(email)

    @classmethod
    def _is_pii_variable(cls, key: str) -> bool:
        lower = key.lower()
        return any(p in lower for p in cls._PII_PATTERNS)

    @classmethod
    def _sanitize_metadata(cls, metadata: dict) -> dict:
        """Strip PII keys from metadata. Never passes through content."""
        sanitized = {k: v for k, v in metadata.items() if k.lower() not in cls._PII_KEYS}
        if "variables" in sanitized and isinstance(sanitized["variables"], dict):
            sanitized["variables"] = {
                k: v for k, v in sanitized["variables"].items()
                if not cls._is_pii_variable(k)
            }
        return sanitized

    def _build_tags(self, task_name: str, enrichments: Optional[dict] = None) -> list:
        tags = []
        if self.valves.insert_tags:
            tags.append("open-webui")
            if task_name not in ("user_response", "llm_response"):
                tags.append(task_name)
        if enrichments and enrichments.get("chat_tags"):
            for tag in enrichments["chat_tags"].split(","):
                tag = tag.strip()
                if tag and tag not in tags:
                    tags.append(tag)
        return tags

    @staticmethod
    def _resolve_chat_id(body: dict, from_outlet: bool = False) -> str:
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
    def _extract_usage(assistant_message_obj: Optional[dict]) -> Optional[dict]:
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

    @staticmethod
    def _message_stats(messages: list) -> dict:
        """Content-free message statistics. No text is stored."""
        roles = [m.get("role", "unknown") for m in messages]
        total_chars = 0
        for msg in messages:
            content = msg.get("content", "")
            if isinstance(content, str):
                total_chars += len(content)
            elif isinstance(content, list):
                for part in content:
                    if isinstance(part, dict) and part.get("type") == "text":
                        total_chars += len(part.get("text", ""))
        return {
            "message_count": len(messages),
            "roles": roles,
            "input_chars": total_chars,
            "estimated_input_tokens": max(1, total_chars // 4),
        }

    def _cleanup_stale_chats(self):
        now = time.time()
        if now - self._last_cleanup < self._CLEANUP_INTERVAL_SECONDS:
            return
        self._last_cleanup = now
        cutoff = now - self._CHAT_TTL_SECONDS
        stale = [cid for cid, ts in self.chat_last_seen.items() if ts < cutoff]
        for cid in stale:
            self.chat_traces.pop(cid, None)
            self.model_names.pop(cid, None)
            self.inlet_timestamps.pop(cid, None)
            self.chat_enrichments.pop(cid, None)
            self.chat_last_seen.pop(cid, None)
        if stale and self.langfuse:
            try:
                self.langfuse.flush()
            except Exception:
                pass

    # ── Filter hooks ──────────────────────────────────────────

    async def inlet(self, body: dict, user: Optional[dict] = None) -> dict:
        if not self.langfuse:
            return body

        metadata = body.get("metadata", {})
        chat_id = self._resolve_chat_id(body)

        self._cleanup_stale_chats()
        self.chat_last_seen[chat_id] = time.time()

        # Store model info for outlet
        model_id = body.get("model")
        model_info = metadata.get("model", {})
        self.model_names.setdefault(chat_id, {})["id"] = model_id
        if isinstance(model_info, dict) and "name" in model_info:
            self.model_names[chat_id]["name"] = model_info["name"]

        required_keys = ["model", "messages"]
        missing = [k for k in required_keys if k not in body]
        if missing:
            raise ValueError(f"Missing keys in request body: {', '.join(missing)}")

        # Create trace on first message — no content, just a container
        if chat_id not in self.chat_traces:
            task_name = metadata.get("task", "user_response")
            try:
                self.chat_traces[chat_id] = self.langfuse.trace(
                    name=f"chat:{chat_id}",
                    user_id=self._get_hashed_user_id(user),
                    session_id=chat_id,
                    tags=self._build_tags(task_name) or None,
                    metadata={"interface": "open-webui"},
                )
            except Exception:
                return body

        self.inlet_timestamps[chat_id] = time.time()
        return body

    async def outlet(self, body: dict, user: Optional[dict] = None) -> dict:
        if not self.langfuse:
            return body

        chat_id = self._resolve_chat_id(body, from_outlet=True)
        self.chat_last_seen[chat_id] = time.time()

        metadata = body.get("metadata", {})
        task_name = metadata.get("task", "llm_response")

        # Ensure trace exists
        if chat_id not in self.chat_traces:
            await self.inlet(body, user)
            if chat_id not in self.chat_traces:
                return body

        messages = body["messages"]
        assistant_raw = get_last_assistant_message(messages)
        assistant_obj = get_last_assistant_message_obj(messages)

        # Capture title/tags from task calls
        if task_name in ("title_generation", "tags_generation") and assistant_raw:
            key = "chat_title" if task_name == "title_generation" else "chat_tags"
            self.chat_enrichments.setdefault(chat_id, {})[key] = assistant_raw.strip()

        enrichments = self.chat_enrichments.get(chat_id, {})
        tags = self._build_tags(task_name, enrichments)

        # Response time
        inlet_ts = self.inlet_timestamps.pop(chat_id, None)
        response_time_ms = round((time.time() - inlet_ts) * 1000, 1) if inlet_ts else None

        # Model info
        model_id = self.model_names.get(chat_id, {}).get("id", body.get("model"))
        model_name = self.model_names.get(chat_id, {}).get("name")
        model_value = (model_name or model_id) if self.valves.use_model_name_instead_of_id_for_generation else model_id

        # Generation metadata — single flat dict with all stats
        gen_meta = {
            "task": task_name,
            "model_id": model_id,
            "model_name": model_name,
            **self._message_stats(messages),
        }
        if assistant_raw:
            gen_meta["output_chars"] = len(assistant_raw)
            gen_meta["estimated_output_tokens"] = max(1, len(assistant_raw) // 4)
        if response_time_ms is not None:
            gen_meta["response_time_ms"] = response_time_ms

        # Update trace with latest enrichments
        trace = self.chat_traces[chat_id]
        trace.update(
            name=enrichments.get("chat_title") or f"chat:{chat_id}",
            user_id=self._get_hashed_user_id(user),
            tags=tags or None,
            metadata={"interface": "open-webui", **enrichments},
        )

        # Single generation per LLM call
        usage = self._extract_usage(assistant_obj)
        try:
            gen_kwargs = {"name": task_name, "model": model_value, "metadata": gen_meta}
            if usage:
                gen_kwargs["usage"] = usage
            trace.generation(**gen_kwargs).end()
        except Exception:
            pass

        try:
            self.langfuse.flush()
        except Exception:
            pass

        return body
