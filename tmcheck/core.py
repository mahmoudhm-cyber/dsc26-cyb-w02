"""tmcheck: a checker for threat models kept as YAML in the repository.

Fill in every function. Keep the names and signatures exactly as they are: the grader imports them.
The full rules are in README.md ("What to build").
"""
from __future__ import annotations

from dataclasses import dataclass
import yaml
import re
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

    sections = ["zones", "elements", "flows", "threats"]
    for s in sections:
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
    elif kind == "process":
        return set("STRIDE")
    elif kind == "data_store":
        return {"T", "I", "D", "R"} if is_log else {"T", "I", "D"}
    elif kind == "data_flow":
        return {"T", "I", "D"}
    else:
        raise ValueError(f"Unknown kind: {kind}")



def validate(model: dict) -> list[Issue]:
    """Structural problems, sorted by (ref, code, message), no duplicates."""
    issues = []

    zones = model.get("zones", [])
    elements = model.get("elements", [])
    flows = model.get("flows", [])
    threats = model.get("threats", [])

    # 1. فحص تكرار الـ IDs في الموديل بالكامل
    all_ids = []
    for item in zones + elements + flows + threats:
        if isinstance(item, dict) and "id" in item:
            all_ids.append(str(item["id"]))

    seen = set()
    duplicates = set()
    for item_id in all_ids:
        if item_id in seen:
            duplicates.add(item_id)
        else:
            seen.add(item_id)

    for dup_id in duplicates:
        issues.append(Issue(ref=dup_id, code="DUPLICATE_ID"))

    # خرائط للبحث السريع
    zone_ids = {str(z["id"]) for z in zones if isinstance(z, dict) and "id" in z}
    element_map = {str(e["id"]): e for e in elements if isinstance(e, dict) and "id" in e}
    flow_map = {str(f["id"]): f for f in flows if isinstance(f, dict) and "id" in f}

    valid_kinds = {"external_entity", "process", "data_store"}

    # 2. فحص الـ Elements
    for e in elements:
        if not isinstance(e, dict):
            continue
        eid = str(e.get("id", ""))
        kind = e.get("kind")
        if kind not in valid_kinds:
            issues.append(Issue(ref=eid, code="BAD_KIND"))
        if "zone" in e and str(e.get("zone")) not in zone_ids:
            issues.append(Issue(ref=eid, code="UNKNOWN_ZONE"))

    # 3. فحص الـ Flows
    for f in flows:
        if not isinstance(f, dict):
            continue
        fid = str(f.get("id", ""))
        src = str(f.get("source", ""))
        tgt = str(f.get("target", ""))

        src_exists = src in element_map
        tgt_exists = tgt in element_map

        if not src_exists or not tgt_exists:
            issues.append(Issue(ref=fid, code="UNKNOWN_REF"))

        # فحص قواعد الـ DFD
        if src_exists and tgt_exists:
            if src == tgt:
                issues.append(Issue(ref=fid, code="INVALID_FLOW"))
            else:
                src_kind = element_map[src].get("kind")
                tgt_kind = element_map[tgt].get("kind")
                # لازم طرف من الاتنين على الأقل يكون process
                if src_kind != "process" and tgt_kind != "process":
                    issues.append(Issue(ref=fid, code="INVALID_FLOW"))

    # 4. فحص الـ Threats
    valid_categories = set("STRIDE")
    valid_statuses = {"open", "mitigated", "accepted"}

    for t in threats:
        if not isinstance(t, dict):
            continue
        tid = str(t.get("id", ""))
        tgt = str(t.get("target", ""))
        cat = t.get("category")

        # فحص هل الهدف موجود كـ element أو flow
        tgt_elem = element_map.get(tgt)
        tgt_flow = flow_map.get(tgt)
        if not tgt_elem and not tgt_flow:
            issues.append(Issue(ref=tid, code="UNKNOWN_REF"))

        # فحص الـ Category
        if cat not in valid_categories:
            issues.append(Issue(ref=tid, code="BAD_CATEGORY"))
        else:
            # لو الحرف صحيح نتأكد إنه ينطبق على الهدف
            if tgt_elem:
                app_cats = applicable(tgt_elem.get("kind"), is_log=tgt_elem.get("is_log", False))
                if cat not in app_cats:
                    issues.append(Issue(ref=tid, code="INAPPLICABLE_CATEGORY"))
            elif tgt_flow:
                app_cats = applicable("data_flow")
                if cat not in app_cats:
                    issues.append(Issue(ref=tid, code="INAPPLICABLE_CATEGORY"))

        # فحص الـ Likelihood والـ Impact (من 1 لـ 5 وأرقام صحيحة فقط بدون boolean)
        lk = t.get("likelihood")
        imp = t.get("impact")
        lk_valid = type(lk) is int and not isinstance(lk, bool) and (1 <= lk <= 5)
        imp_valid = type(imp) is int and not isinstance(imp, bool) and (1 <= imp <= 5)
        if not lk_valid or not imp_valid:
            issues.append(Issue(ref=tid, code="BAD_SCORE"))

        # فحص الـ Status
        status = t.get("status")
        if status not in valid_statuses:
            issues.append(Issue(ref=tid, code="BAD_STATUS"))
        elif status == "mitigated":
            mit = t.get("mitigation")
            if mit is None or not str(mit).strip():
                issues.append(Issue(ref=tid, code="MISSING_MITIGATION"))
        elif status == "accepted":
            just = t.get("justification")
            if just is None or not str(just).strip():
                issues.append(Issue(ref=tid, code="MISSING_JUSTIFICATION"))

    # إزالة التكرار والترتيب حسب (ref, code, message)
    unique_issues = list(dict.fromkeys(issues))
    unique_issues.sort(key=lambda x: (x.ref, x.code, x.message))
    return unique_issues



def crossing_flows(model: dict) -> list[str]:
    """Ids of flows whose source and target are in different zones, in file order."""
    elem_zone = {
        e["id"]: e.get("zone")
        for e in model.get("elements", [])
        if "id" in e
    }

    result = []
    for f in model.get("flows", []):
        src = f.get("source")
        tgt = f.get("target")
        if src in elem_zone and tgt in elem_zone:
            if elem_zone[src] != elem_zone[tgt]:
                result.append(f["id"])
    return result


def coverage_gaps(model: dict) -> list[Gap]:
    """(ref, category) pairs in scope with no threat recorded, sorted by ref then S, T, R, I, D, E."""
    x_flows = crossing_flows(model)
    flows_map = {f["id"]: f for f in model.get("flows", []) if "id" in f}
    elem_map = {e["id"]: e for e in model.get("elements", []) if "id" in e}

    # تحديد العناصر اللي في النطاق (الفلو اللي بيعبر الحدود + طرفيه)
    in_scope_refs = set()
    for fid in x_flows:
        in_scope_refs.add(fid)
        flow = flows_map[fid]
        if flow.get("source") in elem_map:
            in_scope_refs.add(flow["source"])
        if flow.get("target") in elem_map:
            in_scope_refs.add(flow["target"])

    # التهديدات الموجودة بالفعل
    covered = {
        (t.get("target"), t.get("category"))
        for t in model.get("threats", [])
    }

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

    # الترتيب: حسب ref ثم ترتيب STRIDE
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

    # 1 & 2: فحص الـ Crossing Flows
    for fid in x_flows:
        flow = flow_map.get(fid)
        if not flow:
            continue

        # فحص التشفير
        proto = str(flow.get("protocol", "")).strip().lower()
        if proto not in safe_protocols:
            findings.append(Issue(ref=fid, code="UNENCRYPTED_CROSSING"))

        # فحص المصادقة عند الدخول لـ Trust أعلى
        src_id = str(flow.get("source", ""))
        tgt_id = str(flow.get("target", ""))
        src_elem = elem_map.get(src_id)
        tgt_elem = elem_map.get(tgt_id)

        if src_elem and tgt_elem:
            src_zone = str(src_elem.get("zone", ""))
            tgt_zone = str(tgt_elem.get("zone", ""))
            if src_zone in zone_trust and tgt_zone in zone_trust:
                if zone_trust[tgt_zone] > zone_trust[src_zone]:
                    if flow.get("authenticated") is not True:
                        findings.append(Issue(ref=fid, code="UNAUTHENTICATED_INBOUND"))

    # 3: فحص الـ Data Stores اللي فيها PII
    for e in model.get("elements", []):
        if not isinstance(e, dict):
            continue
        if e.get("kind") == "data_store" and e.get("holds_pii") is True:
            eid = str(e.get("id", ""))
            has_i = any(
                isinstance(t, dict) and str(t.get("target", "")) == eid and t.get("category") == "I"
                for t in model.get("threats", [])
            )
            if not has_i:
                findings.append(Issue(ref=eid, code="PII_STORE_WITHOUT_I_THREAT"))

    # إزالة التكرار والترتيب حسب (ref, code)
    unique_findings = list(dict.fromkeys(findings))
    unique_findings.sort(key=lambda x: (x.ref, x.code))
    return unique_findings



def rank(model: dict) -> list[RankedThreat]:
    """Open threats with valid scores, by score desc, then impact desc, then natural id order."""
    threats_data = []

    for t in model.get("threats", []):
        if t.get("status") != "open":
            continue

        lk = t.get("likelihood")
        imp = t.get("impact")

        # التأكد إنه رقم صحيح وليس Boolean ومن 1 إلى 5
        if type(lk) is not int or isinstance(lk, bool) or not (1 <= lk <= 5):
            continue
        if type(imp) is not int or isinstance(imp, bool) or not (1 <= imp <= 5):
            continue

        t_id = str(t.get("id", ""))
        score = lk * imp

        if score >= 15:
            level = "high"
        elif score >= 8:
            level = "medium"
        else:
            level = "low"

        threats_data.append((score, imp, t_id, level))

    # الترتيب: score تنازلي، impact تنازلي، id ترتيب طبيعي تصاعدي
    threats_data.sort(key=lambda item: (-item[0], -item[1], natural_key(item[2])))

    return [
        RankedThreat(id=item[2], score=item[0], level=item[3])
        for item in threats_data
    ]
