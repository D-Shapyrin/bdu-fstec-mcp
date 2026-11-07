"""Pretty-printers that turn domain objects into text blocks for the LLM."""

from __future__ import annotations

from .models import SnapshotInfo, Threat, Vulnerability


_DESC_PREVIEW_LIMIT = 400


def _truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[:limit].rstrip() + "…"


def format_short(v: Vulnerability) -> str:
    """One-screen summary of a vulnerability — the search-result format."""
    lines = [f"{v.id} — {v.name}"]
    if v.severity:
        lines.append(f"  Опасность: {v.severity}")
    elif v.cvss_score is not None:
        lines.append(f"  CVSS: {v.cvss_score} ({v.cvss_vector})")
    if v.cves:
        lines.append(f"  CVE: {', '.join(v.cves)}")
    if v.software:
        preview = ", ".join(
            " ".join(part for part in (s.vendor, s.name, s.version) if part)
            for s in v.software[:5]
        )
        if len(v.software) > 5:
            preview += f" (+{len(v.software) - 5})"
        lines.append(f"  ПО: {preview}")
    if v.publication_date:
        lines.append(f"  Опубликована: {v.publication_date}")
    if v.status:
        lines.append(f"  Статус: {v.status}")
    lines.append(f"  {v.url}")
    body = v.match_snippet or v.description
    if body:
        lines.append(f"  {_truncate(body, _DESC_PREVIEW_LIMIT)}")
    return "\n".join(lines)


def format_full(v: Vulnerability) -> str:
    """Full record including solution, CWEs, and source references."""
    parts = [format_short(v)]
    extras: list[str] = []
    if v.solution:
        extras.append(f"Решение: {v.solution}")
    if v.exploit_status:
        extras.append(f"Эксплойт: {v.exploit_status}")
    if v.fix_status:
        extras.append(f"Исправление: {v.fix_status}")
    if v.cwes:
        extras.append(f"CWE: {', '.join(v.cwes)}")
    if v.sources:
        extras.append(f"Источники: {v.sources}")
    if extras:
        parts.append("")
        parts.extend(extras)
    return "\n".join(parts)


def format_snapshot(info: SnapshotInfo) -> str:
    lines = [
        "БДУ ФСТЭК — снимок данных",
        f"  Записей: {info.total}",
        f"  Идентификаторы: {info.first_id} → {info.last_id}",
        f"  Дата снимка в зеркале: {info.snapshot_date}",
    ]
    if info.threats_total:
        lines.append(f"  Угроз из БнД УБИ: {info.threats_total}")
    if info.latest_update:
        lines.append(f"  Последнее обновление источника: {info.latest_update}")
    if info.is_stale:
        lines.append(f"  ⚠ Снимок устарел: {info.stale_reason}")
    else:
        lines.append("  ✓ Снимок свежий.")
    return "\n".join(lines)


def _threat_cia_line(t: Threat) -> str:
    flags = {
        "конфиденциальность": t.confidentiality,
        "целостность": t.integrity,
        "доступность": t.availability,
    }
    affected = [k for k, v in flags.items() if v]
    if not affected:
        return "  Нарушаемые свойства: нет"
    return "  Нарушаемые свойства: " + ", ".join(affected)


def format_threat_short(t: Threat) -> str:
    """One-screen summary of a threat — the search-result format."""
    lines = [f"{t.id} — {t.name}"]
    if t.status:
        lines.append(f"  Статус: {t.status}")
    if t.object:
        lines.append(f"  Объект воздействия: {t.object}")
    lines.append(_threat_cia_line(t))
    if t.source:
        lines.append(f"  Источник угрозы: {_truncate(t.source, 200)}")
    lines.append(f"  {t.url}")
    body = t.match_snippet or t.description
    if body:
        lines.append(f"  {_truncate(body, _DESC_PREVIEW_LIMIT)}")
    return "\n".join(lines)


def format_threat_full(t: Threat) -> str:
    """Full threat record including dates and remarks."""
    parts = [format_threat_short(t)]
    extras: list[str] = []
    if t.description:
        extras.append(f"Описание: {t.description}")
    if t.source:
        extras.append(f"Источник угрозы: {t.source}")
    if t.added_date:
        extras.append(f"Включена в БнД УБИ: {t.added_date}")
    if t.last_upd_date:
        extras.append(f"Последнее изменение: {t.last_upd_date}")
    if t.remarks:
        extras.append(f"Замечания: {t.remarks}")
    if extras:
        parts.append("")
        parts.extend(extras)
    return "\n".join(parts)


def format_threat_results(
    results: list[Threat], query: str, total_filters: str = ""
) -> str:
    if not results:
        tail = f" ({total_filters})" if total_filters else ""
        return f"Ничего не найдено по запросу «{query}»{tail}."
    header = f"Найдено {len(results)} угроз по запросу «{query}»"
    if total_filters:
        header += f" ({total_filters})"
    body = "\n\n".join(format_threat_short(t) for t in results)
    return f"{header}:\n\n{body}"


def format_search_results(
    results: list[Vulnerability], query: str, total_filters: str = ""
) -> str:
    if not results:
        tail = f" ({total_filters})" if total_filters else ""
        return f"Ничего не найдено по запросу «{query}»{tail}."
    header = f"Найдено {len(results)} результатов по запросу «{query}»"
    if total_filters:
        header += f" ({total_filters})"
    body = "\n\n".join(format_short(v) for v in results)
    return f"{header}:\n\n{body}"
