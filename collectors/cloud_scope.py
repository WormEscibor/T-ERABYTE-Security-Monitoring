# -*- coding: utf-8 -*-
"""Google Cloud resource helpers (khusus ekstraksi project ID dari entry log)."""

from __future__ import annotations


def _nested_value(obj, *paths):
    for path in paths:
        current = obj
        for name in path:
            if isinstance(current, dict):
                current = current.get(name)
            else:
                current = getattr(current, name, None)
            if current in (None, ""):
                break
        else:
            if current not in (None, ""):
                return current
    return ""


def _project_from_resource_name(resource_name: str) -> str:
    value = str(resource_name or "").strip()
    if not value:
        return ""
    parts = [part for part in value.split("/") if part]
    try:
        idx = next(i for i, part in enumerate(parts) if part.casefold() == "projects")
        return parts[idx + 1].strip() if idx + 1 < len(parts) else ""
    except StopIteration:
        return ""


def extract_project_id(entry) -> str:
    """Extract a concrete GCP project ID from a log/resource object.

    The helper intentionally returns an empty string when an organization-level
    audit entry cannot be attributed to a project. Callers must not guess a
    project in that case; this preserves strict project isolation.
    """
    payload = _nested_value(
        entry,
        ("protoPayload",), ("proto_payload",), ("jsonPayload",),
        ("json_payload",), ("payload",),
    )
    resource = _nested_value(entry, ("resource",))
    project = _nested_value(
        entry,
        ("project_id",), ("projectId",),
        ("resource", "labels", "project_id"),
        ("resource", "labels", "projectId"),
        ("resource", "project_id"),
        ("resource", "projectId"),
    )
    if not project:
        project = _nested_value(
            payload,
            ("project_id",), ("projectId",),
            ("resource", "project_id"), ("resource", "projectId"),
        )
    if not project and resource:
        labels = _nested_value(resource, ("labels",)) or {}
        project = _nested_value(labels, ("project_id",), ("projectId",))
    if not project:
        for candidate in (
            _nested_value(payload, ("resourceName",)),
            _nested_value(payload, ("resource_name",)),
            _nested_value(payload, ("parent",)),
            _nested_value(entry, ("resourceName",)),
            _nested_value(entry, ("resource_name",)),
        ):
            project = _project_from_resource_name(str(candidate or ""))
            if project:
                break
    if not project:
        for candidate in (
            _nested_value(entry, ("logName",)),
            _nested_value(entry, ("log_name",)),
        ):
            project = _project_from_resource_name(str(candidate or ""))
            if project:
                break
    return str(project or "").strip()
