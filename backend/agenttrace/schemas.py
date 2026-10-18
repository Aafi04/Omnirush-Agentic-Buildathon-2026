"""Version 1.0 event contract and recognized tool argument validation."""
import re
from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue, TypeAdapter, field_validator

Identifier = Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$")]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class EventBase(StrictModel):
    schema_version: Literal["1.0"]
    trace_id: Identifier
    event_id: Identifier
    timestamp: str
    call_id: Identifier

    @field_validator("timestamp")
    @classmethod
    def timestamp_is_rfc3339(cls, value: str) -> str:
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})", value):
            raise ValueError("RFC3339 timestamp required")
        datetime.fromisoformat(value.replace("Z", "+00:00"))
        return value


class ToolCall(EventBase):
    type: Literal["tool_call"]
    tool: Annotated[str, Field(min_length=1, max_length=128)]
    arguments: dict[str, JsonValue]


class ToolResult(EventBase):
    type: Literal["tool_result"]
    status: Literal["ok", "error"]
    output: JsonValue


Event = Annotated[ToolCall | ToolResult, Field(discriminator="type")]
EVENT_ADAPTER = TypeAdapter(Event)


class ProcessArguments(StrictModel):
    argv: Annotated[list[Annotated[str, Field(min_length=1, max_length=8192)]], Field(min_length=1, max_length=256)]
    cwd: Annotated[str, Field(min_length=1, max_length=4096)]
    shell: bool
    path_flavor: Literal["posix", "windows"] = "posix"


class WriteArguments(StrictModel):
    path: Annotated[str, Field(min_length=1, max_length=4096)]
    cwd: Annotated[str, Field(min_length=1, max_length=4096)]
    content: str
    path_flavor: Literal["posix", "windows"] = "posix"


class HttpArguments(StrictModel):
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
    url: Annotated[str, Field(min_length=1, max_length=8192)]
    headers: dict[str, str] = Field(default_factory=dict)
    body: str = ""

    @field_validator("url")
    @classmethod
    def valid_http_url(cls, value: str) -> str:
        from urllib.parse import urlsplit
        parts = urlsplit(value)
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            raise ValueError("absolute HTTP URL required")
        return value


ARGUMENT_SCHEMAS = {
    "process.exec": ProcessArguments,
    "filesystem.write": WriteArguments,
    "http.request": HttpArguments,
}
