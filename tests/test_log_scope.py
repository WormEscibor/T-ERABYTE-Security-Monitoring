# -*- coding: utf-8 -*-
import pandas as pd

from core.event_schema import ensure_canonical_event_frame
from core.log_scope import ALL_LOGS, HUMAN_ONLY, filter_log_scope, human_mask, scope_counts
from engines import focused_detections as fd


def _events(rows):
    return ensure_canonical_event_frame(pd.DataFrame(rows))


def test_human_only_keeps_real_human_identity_and_all_logs_keeps_everything():
    events = _events([
        {"event_id": "h", "principal_id": "alice@example.org", "principal_type": "HUMAN", "timestamp": "2026-10-05T09:00:00Z"},
        {"event_id": "sa", "principal_id": "svc-app@project.iam.gserviceaccount.com", "principal_type": "SERVICE ACCOUNT", "timestamp": "2026-10-05T09:01:00Z"},
        {"event_id": "sys", "principal_id": "system@google.com", "principal_type": "HUMAN", "timestamp": "2026-10-05T09:02:00Z"},
        {"event_id": "empty", "principal_id": "", "principal_type": "UNKNOWN", "timestamp": "2026-10-05T09:03:00Z"},
    ])
    mask = human_mask(events)
    assert mask.tolist() == [True, False, False, False]
    assert len(filter_log_scope(events, HUMAN_ONLY)) == 1
    assert len(filter_log_scope(events, ALL_LOGS)) == 4
    assert scope_counts(events) == {"total": 4, "human": 1, "non_human": 3}


def test_scope_applies_to_detection_rules():
    events = _events([
        {"event_id": "h", "principal_id": "alice@example.org", "principal_type": "HUMAN", "timestamp": "2026-10-05T00:30:00Z", "event_action": "LOGIN", "event_outcome": "SUCCESS"},
        {"event_id": "sa", "principal_id": "svc-app@project.iam.gserviceaccount.com", "principal_type": "SERVICE ACCOUNT", "timestamp": "2026-10-05T00:30:00Z", "event_action": "LOGIN", "event_outcome": "SUCCESS"},
        {"event_id": "sys", "principal_id": "system@google.com", "principal_type": "HUMAN", "timestamp": "2026-10-05T00:30:00Z", "event_action": "LOGIN", "event_outcome": "SUCCESS"},
    ])
    human = fd.outside_office_hours(events, scope=HUMAN_ONLY)
    all_logs = fd.outside_office_hours(events, scope=ALL_LOGS)
    assert len(human) == 1
    assert len(all_logs) == 3
    assert set(all_logs["principal_id"]) == {"alice@example.org", "svc-app@project.iam.gserviceaccount.com", "system@google.com"}


def test_legacy_include_service_accounts_maps_to_all_logs():
    events = _events([
        {"event_id": "h", "principal_id": "alice@example.org", "principal_type": "HUMAN", "timestamp": "2026-10-05T00:30:00Z"},
        {"event_id": "sa", "principal_id": "svc-app@project.iam.gserviceaccount.com", "principal_type": "SERVICE ACCOUNT", "timestamp": "2026-10-05T00:30:00Z"},
    ])
    result = fd.outside_office_hours(events, include_service_accounts=True)
    assert len(result) == 2
