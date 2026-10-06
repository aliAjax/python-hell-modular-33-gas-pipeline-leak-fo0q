from datetime import datetime


class DomainError(Exception):
    def __init__(self, code, message, status=400):
        super().__init__(message)
        self.code = code
        self.status = status


class ConflictError(DomainError):
    def __init__(self, code, message):
        super().__init__(code, message, 409)


class NotFoundError(DomainError):
    def __init__(self, code, message):
        super().__init__(code, message, 404)


def require_text(payload, name):
    value = payload.get(name)
    if not isinstance(value, str) or not value.strip():
        raise DomainError("field_required", "%s 不能为空" % name)
    return value.strip()


def number(payload, name, minimum=None):
    value = payload.get(name)
    if isinstance(value, bool):
        raise DomainError("invalid_number", "%s 必须是数字" % name)
    try:
        value = float(value)
    except (TypeError, ValueError):
        raise DomainError("invalid_number", "%s 必须是数字" % name)
    if minimum is not None and value < minimum:
        raise DomainError("invalid_number", "%s 不能小于 %s" % (name, minimum))
    return value


def parse_timestamp(payload, name):
    value = require_text(payload, name)
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise DomainError("invalid_timestamp", "%s 必须是 ISO 时间" % name)
    return value


def normalize_create(payload):
    pipeline_id = require_text(payload, "pipeline_id")
    segment_id = require_text(payload, "segment_id")
    reported_at = parse_timestamp(payload, "reported_at")
    pressure_drop = number(payload, "pressure_drop_kpa", 0)
    sensor_ppm = number(payload, "sensor_value_ppm", 0)
    odor_reports = int(payload.get("odor_reports", 0) or 0)
    if odor_reports < 0:
        raise DomainError("invalid_odor_reports", "异味报告数不能为负数")
    reporter = require_text(payload, "reporter")
    stable_key = "%s|%s|%s" % (pipeline_id, segment_id, reported_at)
    return {
        "pipeline_id": pipeline_id,
        "segment_id": segment_id,
        "reported_at": reported_at,
        "pressure_drop_kpa": pressure_drop,
        "sensor_value_ppm": sensor_ppm,
        "odor_reports": odor_reports,
        "reporter": reporter,
        "source_comparison": [],
        "valve_sequence": [],
        "hazards_clear": False,
        "_stable_key": stable_key,
    }


def normalize_source(payload):
    source_type = require_text(payload, "source_type")
    external_id = require_text(payload, "external_id")
    observed_at = parse_timestamp(payload, "observed_at")
    result = {
        "source_type": source_type,
        "external_id": external_id,
        "observed_at": observed_at,
        "sensor_value_ppm": number(payload, "sensor_value_ppm", 0) if "sensor_value_ppm" in payload else None,
        "pressure_drop_kpa": number(payload, "pressure_drop_kpa", 0) if "pressure_drop_kpa" in payload else None,
        "odor_reports": int(payload.get("odor_reports", 0) or 0),
        "note": payload.get("note", ""),
    }
    return result
