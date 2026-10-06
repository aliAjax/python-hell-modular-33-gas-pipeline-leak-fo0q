# -*- coding: utf-8 -*-
"""为审计事件与处置动作生成可读摘要。

监管抽查时需要回答"谁、什么时候、做了什么"。摘要在动作落下时生成，
挂在审计事件与处置记录上；它不参与哈希，因此回填旧摘要不会破坏链的完整性。
"""

from datetime import datetime


def _fmt_time(value):
    if not value:
        return "时间不详"
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return str(value)


def _who(actor, role):
    actor = actor or "系统"
    return "%s（%s）" % (actor, role) if role else actor


def summarize_event(event):
    """根据审计事件（或同构的动作记录）生成一句话摘要。"""
    event_type = event.get("event_type") or event.get("action") or ""
    actor = event.get("actor")
    role = event.get("role")
    when = _fmt_time(event.get("created_at"))
    payload = event.get("payload") or {}
    who = _who(actor, role)

    if event_type == "created":
        return "%s 于 %s 创建泄漏事件并完成登记" % (who, when)
    if event_type == "verify":
        level = (payload.get("assessment") or {}).get("level", "")
        suffix = "，风险等级 %s" % level if level else ""
        return "%s 于 %s 完成现场核验%s" % (who, when, suffix)
    if event_type == "isolate":
        seq = payload.get("valve_sequence") or []
        return "%s 于 %s 完成阀门隔离，阀门顺序：%s" % (who, when, "、".join(seq) if seq else "未记录")
    if event_type == "repair":
        return "%s 于 %s 完成抢修，工单 %s" % (who, when, payload.get("work_order", "未记录"))
    if event_type == "pressure_test":
        pt = payload.get("pressure_test") or {}
        pressure = pt.get("pressure_kpa")
        return "%s 于 %s 完成压力测试，试验压力 %skPa" % (who, when, pressure if pressure is not None else "未记录")
    if event_type == "restore":
        return "%s 于 %s 恢复供气" % (who, when)
    if event_type == "cancel":
        return "%s 于 %s 取消事件，原因：%s" % (who, when, payload.get("reason", "未记录"))
    if event_type == "source_recorded":
        return "%s 于 %s 登记来源记录（%s / %s）" % (
            who, when, payload.get("source_type", "?"), payload.get("external_id", "?"))
    if event_type == "receipt_recorded":
        return "%s 于 %s 登记回执 %s（%s）" % (
            who, when, payload.get("receipt_number", "?"), payload.get("receipt_type", "?"))
    if event_type == "receipt_duplicate":
        return "%s 于 %s 提交的回执 %s 与已有回执重复，未重复入账" % (
            who, when, payload.get("receipt_number", "?"))
    return "%s 于 %s 执行了 %s" % (who, when, event_type)


def summarize_action(action_row):
    """根据 actions 表记录生成摘要。"""
    event = {
        "event_type": action_row.get("action"),
        "actor": action_row.get("actor"),
        "role": action_row.get("role"),
        "created_at": action_row.get("created_at"),
        "payload": action_row.get("payload") or {},
    }
    return summarize_event(event)
