"""Dependency-free validation for the checked-in benchmark JSON schemas."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


SUPPORTED_KEYWORDS = {
    "$schema",
    "title",
    "type",
    "required",
    "properties",
    "additionalProperties",
    "const",
    "minLength",
    "minimum",
    "pattern",
    "items",
    "uniqueItems",
}


class SchemaValidationError(ValueError):
    """Raised when a schema or instance violates the supported contract."""


def load_schema(path: Path) -> dict[str, Any]:
    try:
        schema = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SchemaValidationError(f"unreadable JSON schema {path}: {exc}") from exc
    validate_schema_definition(schema)
    return schema


def validate_schema_definition(schema: Any, location: str = "$") -> None:
    if not isinstance(schema, dict):
        raise SchemaValidationError(f"{location}: schema must be an object")
    unknown = set(schema) - SUPPORTED_KEYWORDS
    if unknown:
        raise SchemaValidationError(f"{location}: unsupported schema keywords {sorted(unknown)}")
    schema_type = schema.get("type")
    if schema_type is not None and schema_type not in {"object", "array", "string", "integer", "boolean"}:
        raise SchemaValidationError(f"{location}: unsupported type {schema_type!r}")
    required = schema.get("required")
    if required is not None and (
        not isinstance(required, list)
        or not all(isinstance(value, str) and value for value in required)
        or len(set(required)) != len(required)
    ):
        raise SchemaValidationError(f"{location}: required must contain unique non-empty strings")
    properties = schema.get("properties")
    if properties is not None:
        if not isinstance(properties, dict) or not all(isinstance(key, str) and key for key in properties):
            raise SchemaValidationError(f"{location}: properties must be an object")
        for key, child in properties.items():
            validate_schema_definition(child, f"{location}.properties.{key}")
    if schema.get("additionalProperties") not in {None, True, False}:
        raise SchemaValidationError(f"{location}: additionalProperties must be boolean")
    if "minLength" in schema and (
        not isinstance(schema["minLength"], int)
        or isinstance(schema["minLength"], bool)
        or schema["minLength"] < 0
    ):
        raise SchemaValidationError(f"{location}: minLength must be a non-negative integer")
    if "minimum" in schema and (
        not isinstance(schema["minimum"], int) or isinstance(schema["minimum"], bool)
    ):
        raise SchemaValidationError(f"{location}: minimum must be an integer")
    if "pattern" in schema:
        if not isinstance(schema["pattern"], str):
            raise SchemaValidationError(f"{location}: pattern must be a string")
        try:
            re.compile(schema["pattern"])
        except re.error as exc:
            raise SchemaValidationError(f"{location}: invalid pattern: {exc}") from exc
    if "items" in schema:
        validate_schema_definition(schema["items"], f"{location}.items")
    if "uniqueItems" in schema and not isinstance(schema["uniqueItems"], bool):
        raise SchemaValidationError(f"{location}: uniqueItems must be boolean")


def validate_instance(instance: Any, schema: dict[str, Any], location: str = "$") -> None:
    expected_type = schema.get("type")
    type_matches = {
        "object": lambda value: isinstance(value, dict),
        "array": lambda value: isinstance(value, list),
        "string": lambda value: isinstance(value, str),
        "integer": lambda value: isinstance(value, int) and not isinstance(value, bool),
        "boolean": lambda value: isinstance(value, bool),
    }
    if expected_type is not None and not type_matches[expected_type](instance):
        raise SchemaValidationError(f"{location}: expected {expected_type}")
    if "const" in schema and instance != schema["const"]:
        raise SchemaValidationError(f"{location}: value differs from const")
    if isinstance(instance, dict):
        required = schema.get("required", [])
        missing = [key for key in required if key not in instance]
        if missing:
            raise SchemaValidationError(f"{location}: missing required properties {missing}")
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            extras = set(instance) - set(properties)
            if extras:
                raise SchemaValidationError(f"{location}: additional properties {sorted(extras)}")
        for key, child in properties.items():
            if key in instance:
                validate_instance(instance[key], child, f"{location}.{key}")
    if isinstance(instance, list):
        if schema.get("uniqueItems") is True:
            canonical = [json.dumps(value, sort_keys=True, separators=(",", ":")) for value in instance]
            if len(set(canonical)) != len(canonical):
                raise SchemaValidationError(f"{location}: array items are not unique")
        if "items" in schema:
            for index, value in enumerate(instance):
                validate_instance(value, schema["items"], f"{location}[{index}]")
    if isinstance(instance, str):
        if len(instance) < schema.get("minLength", 0):
            raise SchemaValidationError(f"{location}: string is too short")
        if "pattern" in schema and re.fullmatch(schema["pattern"], instance) is None:
            raise SchemaValidationError(f"{location}: string does not match pattern")
    if (
        isinstance(instance, int)
        and not isinstance(instance, bool)
        and "minimum" in schema
        and instance < schema["minimum"]
    ):
        raise SchemaValidationError(f"{location}: integer is below minimum")
