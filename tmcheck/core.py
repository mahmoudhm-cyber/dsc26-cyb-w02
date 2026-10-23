"""tmcheck: a checker for threat models kept as YAML in the repository."""
from __future__ import annotations

import re
from dataclasses import dataclass
import yaml


class ModelError(Exception):
    """The file cannot be read as a threat model."""


@dataclass(frozen=True, order=True)
class Issue:
    ref: str          # id of the zone/element/flow/threat the issue is about
    code: str
    message: str = ""


@dataclass(frozen=True, order=True)
class Gap:
    ref: str          # element or flow id
    category: str     # one STRIDE letter


@dataclass(frozen=True)
class RankedThreat:
    id: str
    score: int
    level: str        # "high" | "medium" | "low"


def natural_key(text: str):
    """Sort helper so that T2 comes before T10."""
    return [int(c) if c.isdigit() else c.lower() for c in re.split(r"(\d+)", str(text))]


def load_model(path) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except (OSError, yaml.YAMLError) as e:
        raise ModelError(f"Cannot load model: {e}") from e
    except Exception as e:
        raise ModelError(f"Unexpected error loading model: {e}") from e

    if not isinstance(data, dict):
        raise ModelError("Top level must be a mapping")

    for s in ["zones", "elements", "flows", "threats"]:
        val = data.get(s)
        if val is None:
            data[s] = []
        elif not isinstance(val, list):
            raise ModelError(f"Section {s} must be a list")

    return data


def applicable(kind: str, *, is_log: bool = False) -> set[str]:
    """STRIDE per element: the categories that apply to `kind`. Unknown kind: ValueError."""
    if kind == "external_entity":
        return {"S", "R"}
    if kind == "process":
        return set("STRIDE")
    if kind == "data_store":
        return {"T", "I", "D", "R"} if is_log else {"T", "I", "D"}
    if kind == "data_flow":
        return {"T", "I", "D"}
    raise ValueError(f"Unknown kind: {kind}")


def rank(model: dict) -> list[RankedThreat]:
    """Open threats with valid scores, by score desc, then impact desc, then natural id order."""
    threats_data = []
    for t in model.get("threats", []):
        if t.get("status") != "open":
            continue
        lk, imp = t.get("likelihood"), t.get("impact")
        if type(lk) is not int or isinstance(lk, bool) or not (1 <= lk <= 5):
            continue
        if type(imp) is not int or isinstance(imp, bool) or not (1 <= imp <= 5):
            continue
        tid = str(t.get("id", ""))
        score = lk * imp
        level = "high" if score >= 15 else ("medium" if score >= 8 else "low")
        threats_data.append((score, imp, tid, level))

    threats_data.sort(key=lambda item: (-item[0], -item[1], natural_key(item[2])))
    return [RankedThreat(id=tid, score=sc, level=lvl) for sc, imp, tid, lvl in threats_data]


def validate(model: dict) -> list[Issue]:
    """Structural problems, sorted by (ref, code, message), no duplicates."""
    issues: list[Issue] = []
    zones = model.get("zones", [])
    elements = model.get("elements", [])
    flows = model.get("flows", [])
    threats = model.get("threats", [])

    all_ids = [str(item["id"]) for item in zones + elements + flows + threats if isinstance(item, dict) and "id" in item]
    seen, duplicates = set(), set()
    for item_id in all_ids:
        if item_id in seen:
            duplicates.add(item_id)
        else:
            seen.add(item_id)
    for dup_id in duplicates:
        issues.append(Issue(ref=dup_id, code="DUPLICATE_ID"))

    zone_ids = {str(z["id"]) for z in zones if isinstance(z, dict) and "id" in z}
    element_map = {str(e["id"]): e for e in elements if isinstance(e, dict) and "id" in e}
    flow_map = {str(f["id"]): f for f in flows if isinstance(f, dict) and "id" in f}

    valid_kinds = {"external_entity", "process", "data_store"}
    for e in elements:
        if not isinstance(e, dict):
            continue
        eid = str(e.get("id", ""))
        if e.get("kind") not in valid_kinds:
            issues.append(Issue(ref=eid, code="BAD_KIND"))
        if "zone" in e and str(e.get("zone")) not in zone_ids:
            issues.append(Issue(ref=eid, code="UNKNOWN_ZONE"))

    for f in flows:
        if not isinstance(f, dict):
            continue
        fid = str(f.get("id", ""))
        src, tgt = str(f.get("source", "")), str(f.get("target", ""))
        src_exists, tgt_exists = src in element_map, tgt in element_map

        if not src_exists or not tgt_exists:
            issues.append(Issue(ref=fid, code="UNKNOWN_REF"))

        if src == tgt:
            issues.append(Issue(ref=fid, code="INVALID_FLOW"))
        elif src_exists and tgt_exists:
            if element_map[src].get("kind") != "process" and element_map[tgt].get("kind") != "process":
                issues.append(Issue(ref=fid, code="INVALID_FLOW"))

    valid_cats = set("STRIDE")
    valid_statuses = {"open", "mitigated", "accepted"}
    for t in threats:
        if not isinstance(t, dict):
            continue
        tid = str(t.get("id", ""))
        tgt = str(t.get("target", ""))
        cat = t.get("category")
        tgt_elem, tgt_flow = element_map.get(tgt), flow_map.get(tgt)

        if not tgt_elem and not tgt_flow:
            issues.append(Issue(ref=tid, code="UNKNOWN_REF"))

        if cat not in valid_cats:
            issues.append(Issue(ref=tid, code="BAD_CATEGORY"))
        elif tgt_elem:
            if cat not in applicable(tgt_elem.get("kind"), is_log=tgt_elem.get("is_log", False)):
                issues.append(Issue(ref=tid, code="INAPPLICABLE_CATEGORY"))
        elif tgt_flow:
            if cat not in applicable("data_flow"):
                issues.append(Issue(ref=tid, code="INAPPLICABLE_CATEGORY"))

        lk, imp = t.get("likelihood"), t.get("impact")
        lk_ok = type(lk) is int and not isinstance(lk, bool) and 1 <= lk <= 5
        imp_ok = type(imp) is int and not isinstance(imp, bool) and 1 <= imp <= 5
        if not lk_ok or not imp_ok:
            issues.append(Issue(ref=tid, code="BAD_SCORE"))

        status = t.get("status")
        if status not in valid_statuses:
            issues.append(Issue(ref=tid, code="BAD_STATUS"))
        elif status == "mitigated":
            if not t.get("mitigation") or not str(t.get("mitigation")).strip():
                issues.append(Issue(ref=tid, code="MISSING_MITIGATION"))
        elif status == "accepted":
            if not t.get("justification") or not str(t.get("justification")).strip():
                issues.append(Issue(ref=tid, code="MISSING_JUSTIFICATION"))

    unique_issues = list(dict.fromkeys(issues))
    unique_issues.sort(key=lambda x: (x.ref, x.code, x.message))
    return unique_issues


def crossing_flows(model: dict) -> list[str]:
    """Ids of flows whose source and target are in different zones, in file order."""
    elem_zone = {e["id"]: e.get("zone") for e in model.get("elements", []) if "id" in e}
    result = []
    for f in model.get("flows", []):
        src, tgt = f.get("source"), f.get("target")
        if src in elem_zone and tgt in elem_zone and elem_zone[src] != elem_zone[tgt]:
            result.append(f["id"])
    return result


def coverage_gaps(model: dict) -> list[Gap]:
    """(ref, category) pairs in scope with no threat recorded, sorted by ref then S, T, R, I, D, E."""
    x_flows = crossing_flows(model)
    flows_map = {f["id"]: f for f in model.get("flows", []) if "id" in f}
    elem_map = {e["id"]: e for e in model.get("elements", []) if "id" in e}

    in_scope_refs = set()
    for fid in x_flows:
        in_scope_refs.add(fid)
        flow = flows_map[fid]
        if flow.get("source") in elem_map:
            in_scope_refs.add(flow["source"])
        if flow.get("target") in elem_map:
            in_scope_refs.add(flow["target"])

    covered = {(t.get("target"), t.get("category")) for t in model.get("threats", [])}
    gaps = []
    stride_order = {c: i for i, c in enumerate("STRIDE")}

    for ref in in_scope_refs:
        if ref in flows_map:
            cats = applicable("data_flow")
        elif ref in elem_map:
            elem = elem_map[ref]
            cats = applicable(elem.get("kind"), is_log=elem.get("is_log", False))
        else:
            continue
        for cat in cats:
            if (ref, cat) not in covered:
                gaps.append(Gap(ref=ref, category=cat))

    gaps.sort(key=lambda g: (g.ref, stride_order.get(g.category, 99)))
    return gaps


def policy_findings(model: dict) -> list[Issue]:
    """UNENCRYPTED_CROSSING, UNAUTHENTICATED_INBOUND, PII_STORE_WITHOUT_I_THREAT, sorted by (ref, code)."""
    findings = []
    x_flows = crossing_flows(model)
    elem_map = {str(e["id"]): e for e in model.get("elements", []) if isinstance(e, dict) and "id" in e}
    flow_map = {str(f["id"]): f for f in model.get("flows", []) if isinstance(f, dict) and "id" in f}
    zone_trust = {str(z["id"]): z.get("trust", 0) for z in model.get("zones", []) if isinstance(z, dict) and "id" in z}
    safe_protocols = {"https", "tls", "mtls", "sftp", "ssh"}

    for fid in x_flows:
        flow = flow_map.get(fid)
        if not flow:
            continue
        if str(flow.get("protocol", "")).strip().lower() not in safe_protocols:
            findings.append(Issue(ref=fid, code="UNENCRYPTED_CROSSING"))
        src_elem, tgt_elem = elem_map.get(str(flow.get("source", ""))), elem_map.get(str(flow.get("target", "")))
        if src_elem and tgt_elem:
            sz, tz = str(src_elem.get("zone", "")), str(tgt_elem.get("zone", ""))
            if sz in zone_trust and tz in zone_trust and zone_trust[tz] > zone_trust[sz]:
                if flow.get("authenticated") is not True:
                    findings.append(Issue(ref=fid, code="UNAUTHENTICATED_INBOUND"))

    for e in model.get("elements", []):
        if isinstance(e, dict) and e.get("kind") == "data_store" and e.get("holds_pii") is True:
            eid = str(e.get("id", ""))
            if not any(isinstance(t, dict) and str(t.get("target", "")) == eid and t.get("category") == "I" for t in model.get("threats", [])):
                findings.append(Issue(ref=eid, code="PII_STORE_WITHOUT_I_THREAT"))

    unique = list(dict.fromkeys(findings))
    unique.sort(key=lambda x: (x.ref, x.code))
    return unique
