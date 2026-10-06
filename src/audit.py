import hashlib
import json

GENESIS = "GENESIS"


def canonical_json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def content_digest(value):
    """对任意可 JSON 化内容做摘要（落内容指纹用）。"""
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def chain_digest(previous_hash, value):
    """链式摘要：把上一条摘要与本条内容指纹串起来。"""
    return hashlib.sha256((previous_hash + content_digest(value)).encode("utf-8")).hexdigest()


def audit_hash(previous_hash, event):
    """审计事件哈希：保持与历史记录完全一致的算法。"""
    payload = canonical_json(event)
    return hashlib.sha256((previous_hash + payload).encode("utf-8")).hexdigest()
