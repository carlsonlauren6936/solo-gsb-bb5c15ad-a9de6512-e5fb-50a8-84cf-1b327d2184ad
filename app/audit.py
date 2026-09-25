"""交集审计：同一批观测记录两次公开发布后，按 id 对齐两次分组的交集并标记风险。

即使两批各自的每个等价组都达到 k，交集组仍可能不足 k，需要单独报险。
"""

from __future__ import annotations

from typing import Any

from .anonymizer import unprocessable


def validate_batch(
    records: list[dict[str, Any]],
    fields: list[str],
    id_field: str,
    label: str,
) -> list[tuple[str, ...]]:
    """校验单批已发布记录，返回与 records 等长、逐条对应的分组签名。

    校验内容：批内至少 1 条记录；分组字段名是非空字符串；每条记录的
    id 字段是非空字符串且批内唯一；每条记录都包含全部分组字段且值为字符串。
    """
    if len(records) < 1:
        raise unprocessable(f"{label} 至少需要包含 1 条记录")

    for field in fields:
        if not field.strip():
            raise unprocessable(f"{label} 的分组字段名不能为空字符串")

    seen_ids: set[str] = set()
    signatures: list[tuple[str, ...]] = []
    for record in records:
        record_id = record.get(id_field)
        if not isinstance(record_id, str) or not record_id.strip():
            raise unprocessable(
                f"{label} 每条记录的 id 字段 {id_field!r} 都必须是非空字符串"
            )
        if record_id in seen_ids:
            raise unprocessable(f"{label} 中 id {record_id!r} 重复出现")
        seen_ids.add(record_id)

        signature: list[str] = []
        for field in fields:
            value = record.get(field)
            if not isinstance(value, str):
                raise unprocessable(
                    f"{label} 每条记录的分组字段 {field!r} 都必须存在且为字符串"
                )
            signature.append(value)
        signatures.append(tuple(signature))

    return signatures


def compute_intersections(
    records_a: list[dict[str, Any]],
    fields_a: list[str],
    records_b: list[dict[str, Any]],
    fields_b: list[str],
    id_field: str,
    k: int,
) -> list[dict[str, Any]]:
    """按两批各自的公开字段值分组，再按 id 求两次分组的交集。

    返回按交集在第一批记录中首次出现顺序排列的列表；每项包含 id 列表、
    成员数、两侧字段组合以及 count < k 的风险标记。
    """
    signatures_a = validate_batch(records_a, fields_a, id_field, "records_a")
    signatures_b = validate_batch(records_b, fields_b, id_field, "records_b")

    ids_a = {record[id_field] for record in records_a}
    ids_b = {record[id_field] for record in records_b}
    if ids_a != ids_b:
        raise unprocessable("两批记录的 id 集合必须完全相同")

    # 第二批：id -> 分组签名（id 批内唯一，可安全建索引）。
    signature_by_id = {
        record[id_field]: signature
        for record, signature in zip(records_b, signatures_b)
    }

    # 按第一批记录的首次出现顺序收集交集；ids 同样按该顺序追加。
    intersections: dict[tuple[tuple[str, ...], tuple[str, ...]], dict[str, Any]] = {}
    for record, signature_a in zip(records_a, signatures_a):
        record_id = record[id_field]
        signature_b = signature_by_id[record_id]
        key = (signature_a, signature_b)
        entry = intersections.get(key)
        if entry is None:
            entry = {
                "ids": [],
                "values_a": dict(zip(fields_a, signature_a)),
                "values_b": dict(zip(fields_b, signature_b)),
            }
            intersections[key] = entry
        entry["ids"].append(record_id)

    result: list[dict[str, Any]] = []
    for entry in intersections.values():
        count = len(entry["ids"])
        result.append(
            {
                "ids": entry["ids"],
                "count": count,
                "values_a": entry["values_a"],
                "values_b": entry["values_b"],
                "at_risk": count < k,
            }
        )
    return result
