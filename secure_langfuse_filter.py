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
import json
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
        debug: bool = False

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
                "debug": os.getenv("DEBUG_MODE", "false").lower() == "true",
            }
        )

        self.langfuse = None
        self.chat_traces = {}
        self.suppressed_logs = set()
        # Dictionary to store model names for each chat
        self.model_names = {}
        # Track inlet timestamps per chat for response-time calculation
        self.inlet_timestamps = {}

    def log(self, message: str, suppress_repeats: bool = False):
        if self.valves.debug:
            if suppress_repeats:
                if message in self.suppressed_logs:
                    return
                self.suppressed_logs.add(message)
            print(f"[DEBUG] {message}")

    async def on_startup(self):
        self.log(f"on_startup triggered for {__name__}")
        self.set_langfuse()

    async def on_shutdown(self):
        self.log(f"on_shutdown triggered for {__name__}")
        if self.langfuse:
            try:
                # End all active traces
                for chat_id, trace in self.chat_traces.items():
                    try:
                        trace.end()
                        self.log(f"Ended trace for chat_id: {chat_id}")
                    except Exception as e:
                        self.log(f"Failed to end trace for {chat_id}: {e}")

                self.chat_traces.clear()
                self.langfuse.flush()
                self.log("Langfuse data flushed on shutdown")
            except Exception as e:
                self.log(f"Failed to flush Langfuse data: {e}")

    async def on_valves_updated(self):
        self.log("Valves updated, resetting Langfuse client.")
        self.set_langfuse()

    def set_langfuse(self):
        try:
            self.log(f"Initializing Langfuse with host: {self.valves.host}")
            self.log(
                f"Secret key set: {'Yes' if self.valves.secret_key and self.valves.secret_key != 'your-secret-key-here' else 'No'}"
            )
            self.log(
                f"Public key set: {'Yes' if self.valves.public_key and self.valves.public_key != 'your-public-key-here' else 'No'}"
            )

            # Initialize Langfuse client for v3.2.1
            self.langfuse = Langfuse(
                secret_key=self.valves.secret_key,
                public_key=self.valves.public_key,
                host=self.valves.host,
                debug=self.valves.debug,
            )

            # Test authentication
            try:
                self.langfuse.auth_check()
                self.log(
                    f"Langfuse client initialized and authenticated successfully. Connected to host: {self.valves.host}")

            except Exception as e:
                self.log(f"Auth check failed: {e}")
                self.log(f"Failed host: {self.valves.host}")
                self.langfuse = None
                return

        except Exception as auth_error:
            if (
                "401" in str(auth_error)
                or "unauthorized" in str(auth_error).lower()
                or "credentials" in str(auth_error).lower()
            ):
                self.log(f"Langfuse credentials incorrect: {auth_error}")
                self.langfuse = None
                return
        except Exception as e:
            self.log(f"Langfuse initialization error: {e}")
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

    @staticmethod
    def _sanitize_metadata(metadata: dict) -> dict:
        """
        Removes any user-identifiable fields from metadata before
        sending it to Langfuse. Retains only operational fields.
        """
        # Fields that could contain PII or allow tracing back to a user
        pii_keys = {
            "user", "name", "email", "user_email", "user_name",
            "profile_image_url", "avatar", "display_name",
            "user_id",  # raw user_id before hashing
        }
        return {k: v for k, v in metadata.items() if k.lower() not in pii_keys}

    @staticmethod
    def _sanitize_body(body: dict) -> dict:
        """
        Returns a copy of the request body safe for logging to Langfuse.
        Strips top-level user-identifiable fields while keeping messages,
        model info, and other operational data.
        """
        pii_keys = {
            "user", "user_id", "user_email", "user_name",
            "name", "email", "profile_image_url", "avatar",
        }
        return {k: v for k, v in body.items() if k.lower() not in pii_keys}

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
            # Always add 'open-webui'
            tags_list.append("open-webui")
            # Add the task_name if it's not one of the excluded defaults
            if task_name not in ["user_response", "llm_response"]:
                tags_list.append(task_name)
        return tags_list

    async def inlet(self, body: dict, user: Optional[dict] = None) -> dict:
        self.log("Langfuse Filter INLET called")

        # Check Langfuse client status
        if not self.langfuse:
            self.log("[WARNING] Langfuse client not initialized - Skipped")
            return body

        # self.log(f"Inlet function called with body: {body} and user: {user}")

        metadata = body.get("metadata", {})
        chat_id = metadata.get("chat_id", str(uuid.uuid4()))

        # Handle temporary chats (use modified chat_id only for Langfuse, never write back)
        if chat_id == "local":
            session_id = metadata.get("session_id")
            chat_id = f"temporary-session-{session_id}"

        # Extract and store both model name and ID if available
        model_info = metadata.get("model", {})
        model_id = body.get("model")
        
        # Store model information for this chat
        if chat_id not in self.model_names:
            self.model_names[chat_id] = {"id": model_id}
        else:
            self.model_names[chat_id]["id"] = model_id
            
        if isinstance(model_info, dict) and "name" in model_info:
            self.model_names[chat_id]["name"] = model_info["name"]
            # self.log(f"Stored model info - name: '{model_info['name']}', id: '{model_id}' for chat_id: {chat_id}")

        required_keys = ["model", "messages"]
        missing_keys = [key for key in required_keys if key not in body]
        if missing_keys:
            error_message = f"Error: Missing keys in the request body: {', '.join(missing_keys)}"
            self.log(error_message)
            raise ValueError(error_message)

        # Hash the user email for a stable but anonymous user handle
        user_email_raw = user.get("email") if user else None
        hashed_user_id = self._hash_user_id(user_email_raw)
        # Defaulting to 'user_response' if no task is provided
        task_name = metadata.get("task", "user_response")

        # Build tags
        tags_list = self._build_tags(task_name)

        # Sanitize metadata and body to remove any PII before sending to Langfuse
        # Work on copies so we never mutate the original body returned to OpenWebUI
        safe_metadata = self._sanitize_metadata(metadata)
        safe_metadata["type"] = task_name
        safe_metadata["interface"] = "open-webui"
        safe_body = self._sanitize_body(body)

        # Redact message content if redact_content is enabled
        if self.valves.redact_content and "messages" in safe_body:
            safe_body["messages"] = self._redact_messages(safe_body["messages"])

        # Record inlet timestamp for response-time calculation in outlet
        self.inlet_timestamps[chat_id] = time.time()

        if chat_id not in self.chat_traces:
            self.log(f"Creating new trace for chat_id: {chat_id}")

            try:
                # Create trace using Langfuse v3 API with sanitized data
                trace_metadata = {
                    **safe_metadata,
                    "session_id": chat_id,
                    "interface": "open-webui",
                }
                
                # Create trace with all necessary information
                trace = self.langfuse.start_span(
                    name=f"chat:{chat_id}",
                    input=safe_body,
                    metadata=trace_metadata
                )

                # Set additional trace attributes
                trace.update_trace(
                    user_id=hashed_user_id,
                    session_id=chat_id,
                    tags=tags_list if tags_list else None,
                    input=safe_body,
                    metadata=trace_metadata,
                )

                self.chat_traces[chat_id] = trace
                self.log(f"Successfully created trace for chat_id: {chat_id}")
            except Exception as e:
                self.log(f"Failed to create trace: {e}")
                return body
        else:
            trace = self.chat_traces[chat_id]
            self.log(f"Reusing existing trace for chat_id: {chat_id}")
            # Update trace with current sanitized metadata and tags
            trace_metadata = {
                **safe_metadata,
                "session_id": chat_id,
                "interface": "open-webui",
            }
            trace.update_trace(
                user_id=hashed_user_id,
                tags=tags_list if tags_list else None,
                metadata=trace_metadata,
            )

        # Log user input as event
        try:
            trace = self.chat_traces[chat_id]
            
            # Create sanitized event metadata (no PII)
            event_metadata = {
                **safe_metadata,
                "type": "user_input",
                "interface": "open-webui",
                "session_id": chat_id,
                "event_id": str(uuid.uuid4()),
            }
            
            # Redact user input messages if enabled
            event_input = self._redact_messages(body["messages"])

            event_span = trace.start_span(
                name=f"user_input:{str(uuid.uuid4())}",
                metadata=event_metadata,
                input=event_input,
            )
            event_span.end()
            self.log(f"User input event logged for chat_id: {chat_id}")
        except Exception as e:
            self.log(f"Failed to log user input event: {e}")

        return body

    async def outlet(self, body: dict, user: Optional[dict] = None) -> dict:
        self.log("Langfuse Filter OUTLET called")

        # Check Langfuse client status
        if not self.langfuse:
            self.log("[WARNING] Langfuse client not initialized - Skipped")
            return body

        self.log(f"Outlet function called with body: {body}")

        chat_id = body.get("chat_id")

        # Handle temporary chats
        if chat_id == "local":
            session_id = body.get("session_id")
            chat_id = f"temporary-session-{session_id}"

        metadata = body.get("metadata", {})
        # Defaulting to 'llm_response' if no task is provided
        task_name = metadata.get("task", "llm_response")

        # Build tags
        tags_list = self._build_tags(task_name)

        if chat_id not in self.chat_traces:
            self.log(f"[WARNING] No matching trace found for chat_id: {chat_id}, attempting to re-register.")
            # Re-run inlet to register if somehow missing
            return await self.inlet(body, user)

        self.chat_traces[chat_id]

        assistant_message_raw = get_last_assistant_message(body["messages"])
        assistant_message_obj = get_last_assistant_message_obj(body["messages"])

        # Redact assistant message if content redaction is enabled
        if self.valves.redact_content:
            assistant_message = self._redact_text(assistant_message_raw) if assistant_message_raw else None
        else:
            assistant_message = assistant_message_raw

        # Calculate response time from inlet to outlet
        inlet_ts = self.inlet_timestamps.pop(chat_id, None)
        response_time_ms = round((time.time() - inlet_ts) * 1000, 1) if inlet_ts else None

        usage = None
        if assistant_message_obj:
            info = assistant_message_obj.get("usage", {})
            if isinstance(info, dict):
                input_tokens = info.get("prompt_eval_count") or info.get("prompt_tokens")
                output_tokens = info.get("eval_count") or info.get("completion_tokens")
                if input_tokens is not None and output_tokens is not None:
                    usage = {
                        "input": input_tokens,
                        "output": output_tokens,
                        "unit": "TOKENS",
                    }
                    self.log(f"Usage data extracted: {usage}")

        # Hash user email for anonymous but stable user handle
        user_email_raw = user.get("email") if user else None
        hashed_user_id = self._hash_user_id(user_email_raw)

        # Update the trace with complete output information
        trace = self.chat_traces[chat_id]
        
        # Work on a copy of metadata so we never mutate the original body
        safe_metadata = self._sanitize_metadata(metadata)
        safe_metadata["type"] = task_name
        safe_metadata["interface"] = "open-webui"
        
        # Create sanitized trace metadata (no PII), include response time
        complete_trace_metadata = {
            **safe_metadata,
            "session_id": chat_id,
            "interface": "open-webui",
            "task": task_name,
        }
        if response_time_ms is not None:
            complete_trace_metadata["response_time_ms"] = response_time_ms
        
        # Update trace with output and sanitized metadata
        trace.update_trace(
            user_id=hashed_user_id,
            output=assistant_message,
            metadata=complete_trace_metadata,
            tags=tags_list if tags_list else None,
        )

        # Outlet: Always create LLM generation (this is the LLM response)
        # Determine which model value to use based on the use_model_name valve
        model_id = self.model_names.get(chat_id, {}).get("id", body.get("model"))
        model_name = self.model_names.get(chat_id, {}).get("name", "unknown")

        # Pick primary model identifier based on valve setting
        model_value = (
            model_name
            if self.valves.use_model_name_instead_of_id_for_generation
            else model_id
        )

        # Add model values to sanitized metadata (these are not PII)
        safe_metadata["model_id"] = model_id
        safe_metadata["model_name"] = model_name

        # Create LLM generation for the response
        try:
            trace = self.chat_traces[chat_id]
            
            # Create sanitized generation metadata (no PII)
            generation_metadata = {
                **complete_trace_metadata,
                "type": "llm_response",
                "model_id": model_id,
                "model_name": model_name,
                "generation_id": str(uuid.uuid4()),
            }
            
            # Redact generation input messages if enabled
            generation_input = self._redact_messages(body["messages"])

            generation = trace.start_generation(
                name=f"llm_response:{str(uuid.uuid4())}",
                model=model_value,
                input=generation_input,
                output=assistant_message,
                metadata=generation_metadata,
            )

            # Update with usage if available
            if usage:
                generation.update(usage=usage)

            generation.end()
            self.log(f"LLM generation completed for chat_id: {chat_id}")
        except Exception as e:
            self.log(f"Failed to create LLM generation: {e}")

        # Flush data to Langfuse
        try:
            if self.langfuse:
                self.langfuse.flush()
                self.log("Langfuse data flushed")
        except Exception as e:
            self.log(f"Failed to flush Langfuse data: {e}")

        return body
